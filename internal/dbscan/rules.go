package dbscan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ininia/scanx/internal/report"
)

// Categories.
const (
	CatNaming      = "naming"
	CatConsistency = "consistency"
	CatStructure   = "structure"
	CatSecurity    = "security"
)

// Categories in display order with their weight in the overall score.
var Categories = []struct {
	ID     string
	Weight int
}{{CatStructure, 35}, {CatNaming, 25}, {CatConsistency, 25}, {CatSecurity, 15}}

// RuleInfo describes a rule. Titles, messages and fixes are translated
// (i18n keys dbrule.<ID>.title/.msg/.fix).
type RuleInfo struct {
	ID        string
	Category  string
	Severity  string
	DefaultOn bool
	// Param names a profile option the rule uses (shown next to it).
	Param string
}

// Rules is the catalog, in display order.
var Rules = []RuleInfo{
	{ID: "DBN001", Category: CatNaming, Severity: "medium", DefaultOn: true, Param: "language"},
	{ID: "DBN002", Category: CatNaming, Severity: "low", DefaultOn: true, Param: "table_case"},
	{ID: "DBN003", Category: CatNaming, Severity: "low", DefaultOn: true, Param: "column_case"},
	{ID: "DBN004", Category: CatNaming, Severity: "low", DefaultOn: true, Param: "table_number"},
	{ID: "DBN005", Category: CatNaming, Severity: "medium", DefaultOn: true},
	{ID: "DBN006", Category: CatNaming, Severity: "medium", DefaultOn: true},
	{ID: "DBN007", Category: CatNaming, Severity: "low", DefaultOn: true, Param: "max_name_length"},
	{ID: "DBN008", Category: CatNaming, Severity: "low", DefaultOn: true},
	{ID: "DBN009", Category: CatNaming, Severity: "info", DefaultOn: false},

	{ID: "DBC001", Category: CatConsistency, Severity: "medium", DefaultOn: true, Param: "audit_names"},
	{ID: "DBC002", Category: CatConsistency, Severity: "medium", DefaultOn: true},
	{ID: "DBC003", Category: CatConsistency, Severity: "high", DefaultOn: true},
	{ID: "DBC004", Category: CatConsistency, Severity: "low", DefaultOn: true},

	{ID: "DBS001", Category: CatStructure, Severity: "high", DefaultOn: true},
	{ID: "DBS002", Category: CatStructure, Severity: "medium", DefaultOn: true},
	{ID: "DBS003", Category: CatStructure, Severity: "low", DefaultOn: true},
	{ID: "DBS004", Category: CatStructure, Severity: "low", DefaultOn: true},
	{ID: "DBS005", Category: CatStructure, Severity: "low", DefaultOn: true, Param: "max_columns"},
	{ID: "DBS006", Category: CatStructure, Severity: "medium", DefaultOn: true},
	{ID: "DBS007", Category: CatStructure, Severity: "medium", DefaultOn: true},
	{ID: "DBS008", Category: CatStructure, Severity: "medium", DefaultOn: true},
	{ID: "DBS009", Category: CatStructure, Severity: "low", DefaultOn: true},
	{ID: "DBS010", Category: CatStructure, Severity: "low", DefaultOn: true, Param: "require_audit"},
	{ID: "DBS011", Category: CatStructure, Severity: "high", DefaultOn: true},
	{ID: "DBS012", Category: CatStructure, Severity: "low", DefaultOn: true},
	{ID: "DBS013", Category: CatStructure, Severity: "info", DefaultOn: true},
	{ID: "DBS014", Category: CatStructure, Severity: "low", DefaultOn: true},

	{ID: "DBX001", Category: CatSecurity, Severity: "high", DefaultOn: true},
	{ID: "DBX002", Category: CatSecurity, Severity: "info", DefaultOn: true},
	{ID: "DBX003", Category: CatSecurity, Severity: "high", DefaultOn: true},
}

// RuleByID finds a rule.
func RuleByID(id string) *RuleInfo {
	for i := range Rules {
		if Rules[i].ID == id {
			return &Rules[i]
		}
	}
	return nil
}

// Finding is one rule violation. The message is rendered from the rule's
// translated template and Params.
type Finding struct {
	RuleID      string   `json:"rule"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	ObjectType  string   `json:"object_type"` // database | table | column | index | foreign_key | concept
	Object      string   `json:"object"`
	Params      []string `json:"params,omitempty"`
	Details     []string `json:"details,omitempty"`
	Fingerprint string   `json:"fingerprint"`
}

// Stats summarise the inspected structure.
type Stats struct {
	Tables      int    `json:"tables"`
	Columns     int    `json:"columns"`
	Views       int    `json:"views"`
	Routines    int    `json:"routines"`
	Indexes     int    `json:"indexes"`
	ForeignKeys int    `json:"foreign_keys"`
	Schemas     int    `json:"schemas"`
	Excluded    int    `json:"excluded"`
	TableStyle  string `json:"table_style,omitempty"`
	ColumnStyle string `json:"column_style,omitempty"`
	TableNumber string `json:"table_number,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

// CategoryScore is the score of one category.
type CategoryScore struct {
	Category string `json:"category"`
	Score    int    `json:"score"`
	Findings int    `json:"findings"`
}

// Report is the outcome of evaluating a snapshot.
type Report struct {
	Findings   []Finding       `json:"findings"`
	Score      int             `json:"score"`
	Grade      string          `json:"grade"`
	Categories []CategoryScore `json:"categories"`
	Counts     map[string]int  `json:"counts"`
	Stats      Stats           `json:"stats"`
	Gate       string          `json:"gate"` // pass | fail
	FailOn     string          `json:"fail_on"`
	// Checked counts how many objects each rule looked at (score ratios).
	Checked map[string]int `json:"checked"`
}

type evaluator struct {
	s       *Snapshot
	p       Profile
	tables  []*Table
	byName  map[string]*Table // folded qualified and bare names
	out     []Finding
	checked map[string]int
	sev     map[string]string
}

func (e *evaluator) on(id string) bool {
	_, ok := e.sev[id]
	return ok
}

func (e *evaluator) check(id string, n int) { e.checked[id] += n }

func (e *evaluator) add(id, objType, object string, params []string, details ...string) {
	sev, ok := e.sev[id]
	if !ok {
		return
	}
	r := RuleByID(id)
	h := sha256.Sum256([]byte(id + "|" + objType + "|" + strings.ToLower(object)))
	e.out = append(e.out, Finding{
		RuleID: id, Category: r.Category, Severity: sev, ObjectType: objType, Object: object,
		Params: params, Details: details, Fingerprint: hex.EncodeToString(h[:12]),
	})
}

func (e *evaluator) addSev(id, sev, objType, object string, params []string, details ...string) {
	if !e.on(id) {
		return
	}
	saved := e.sev[id]
	if rs, ok := e.p.Rules[id]; !ok || rs.Severity == "" {
		e.sev[id] = sev // rule-specific severity unless the user fixed one
	}
	e.add(id, objType, object, params, details...)
	e.sev[id] = saved
}

// Evaluate runs the enabled rules of the profile on a snapshot.
func Evaluate(s *Snapshot, prof Profile) *Report {
	p := prof.Effective()
	e := &evaluator{s: s, p: p, byName: map[string]*Table{}, checked: map[string]int{}, sev: map[string]string{}}
	for i := range Rules {
		if on, sev := p.RuleOn(&Rules[i]); on {
			e.sev[Rules[i].ID] = sev
		}
	}
	st := Stats{Views: len(s.Views), Routines: len(s.Routines), Truncated: s.Truncated}
	schemas := map[string]bool{}
	for i := range s.Tables {
		t := &s.Tables[i]
		if p.Excluded(t.Schema, t.Name) {
			st.Excluded++
			continue
		}
		e.tables = append(e.tables, t)
		e.byName[Fold(t.QualifiedName())] = t
		if _, dup := e.byName[Fold(t.Name)]; !dup {
			e.byName[Fold(t.Name)] = t
		}
		schemas[t.Schema] = true
		st.Columns += len(t.Columns)
		st.Indexes += len(t.Indexes)
		st.ForeignKeys += len(t.ForeignKey)
	}
	st.Tables, st.Schemas = len(e.tables), len(schemas)

	st.TableStyle = e.naming()
	st.ColumnStyle = e.columnNaming()
	st.TableNumber = e.plurality()
	e.consistency()
	e.structure()
	e.security()

	rep := &Report{Findings: e.out, Stats: st, Checked: e.checked, Counts: map[string]int{}}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if SevRank(a.Severity) != SevRank(b.Severity) {
			return SevRank(a.Severity) > SevRank(b.Severity)
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Object < b.Object
	})
	for _, f := range rep.Findings {
		rep.Counts[f.Severity]++
	}
	rep.score()
	rep.Gate, rep.FailOn = "pass", p.FailOn
	if p.FailOn != "none" {
		for _, f := range rep.Findings {
			if SevRank(f.Severity) >= SevRank(p.FailOn) {
				rep.Gate = "fail"
				break
			}
		}
	}
	return rep
}

// SevRank orders severities (critical highest).
func SevRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

// ---------- naming ----------

func colRef(t *Table, c *Column) string { return t.QualifiedName() + "." + c.Name }

// dominant returns the most common style ("" if none). Single lowercase
// words ("orders") fit both snake_case and camelCase, so they give each
// half a vote; single uppercase words count for UPPER_SNAKE.
func dominant(names []string) (string, int) {
	count := map[string]float64{}
	total := 0.0
	for _, n := range names {
		switch st := Style(n); st {
		case CaseSnake, CasePascal, CaseCamel, CaseUpperSnake:
			count[st]++
			total++
		case "lower":
			count[CaseSnake] += 0.5
			count[CaseCamel] += 0.5
			total++
		case "upper":
			count[CaseUpperSnake]++
			total++
		}
	}
	best, n := "", 0.0
	for _, st := range []string{CaseSnake, CasePascal, CaseCamel, CaseUpperSnake} {
		if count[st] > n {
			best, n = st, count[st]
		}
	}
	if total == 0 || best == "" {
		return "", 0
	}
	return best, int(n * 100 / total)
}

func (e *evaluator) naming() string {
	names := make([]string, 0, len(e.tables))
	for _, t := range e.tables {
		names = append(names, t.Name)
	}
	want := e.p.TableCase
	dom, pct := dominant(names)
	if want == CaseAuto {
		want = dom
	}
	for _, t := range e.tables {
		e.check("DBN001", 1)
		if words := ForeignWords(t.Name, e.p.Language); len(words) > 0 {
			e.add("DBN001", "table", t.QualifiedName(), []string{strings.Join(words, ", ")})
		}
		if want != "" {
			e.check("DBN002", 1)
			if st := Style(t.Name); !StyleCompatible(st, want) {
				e.add("DBN002", "table", t.QualifiedName(), []string{styleLabel(st), styleLabel(want)})
			}
		}
		e.nameChecks(t.QualifiedName(), "table", t.Name)
		e.check("DBN008", 1)
		l := strings.ToLower(t.Name)
		for _, pre := range []string{"tbl_", "tbl", "tb_", "t_"} {
			if strings.HasPrefix(l, pre) && len(l) > len(pre)+2 && (pre != "tbl" || Style(t.Name) == CasePascal || Style(t.Name) == CaseCamel) {
				e.add("DBN008", "table", t.QualifiedName(), []string{t.Name[:len(pre)]})
				break
			}
		}
	}
	if e.s.Engine == EngineMSSQL {
		for _, r := range e.s.Routines {
			if r.Kind == "procedure" {
				e.check("DBN008", 1)
				if strings.HasPrefix(strings.ToLower(r.Name), "sp_") {
					e.addSev("DBN008", "medium", "routine", qualified(r.Schema, r.Name), []string{"sp_"})
				}
			}
		}
	}
	if dom == "" {
		return ""
	}
	return styleLabel(dom) + " " + strconv.Itoa(pct) + "%"
}

func qualified(schema, name string) string {
	if schema == "" {
		return name
	}
	return schema + "." + name
}

func styleLabel(st string) string {
	switch st {
	case CaseSnake:
		return "snake_case"
	case CasePascal:
		return "PascalCase"
	case CaseCamel:
		return "camelCase"
	case CaseUpperSnake:
		return "UPPER_SNAKE"
	case "lower":
		return "lowercase"
	case "upper":
		return "UPPERCASE"
	}
	return "mixed"
}

// nameChecks are the per-identifier rules shared by tables and columns.
func (e *evaluator) nameChecks(object, objType, name string) {
	e.check("DBN005", 1)
	if Reserved(name, e.s.Engine) {
		e.add("DBN005", objType, object, []string{name})
	}
	e.check("DBN006", 1)
	if NeedsQuoting(name) {
		e.add("DBN006", objType, object, []string{name})
	}
	e.check("DBN007", 1)
	if n := len([]rune(name)); n > e.p.MaxNameLength {
		e.add("DBN007", objType, object, []string{strconv.Itoa(n), strconv.Itoa(e.p.MaxNameLength)})
	}
}

func (e *evaluator) columnNaming() string {
	var names []string
	for _, t := range e.tables {
		for i := range t.Columns {
			names = append(names, t.Columns[i].Name)
		}
	}
	want := e.p.ColumnCase
	dom, pct := dominant(names)
	if want == CaseAuto {
		want = dom
	}
	for _, t := range e.tables {
		tableTokens := Tokens(foldTR(t.Name))
		for i := range t.Columns {
			c := &t.Columns[i]
			ref := colRef(t, c)
			e.check("DBN001", 1)
			if words := ForeignWords(c.Name, e.p.Language); len(words) > 0 {
				e.add("DBN001", "column", ref, []string{strings.Join(words, ", ")})
			}
			if want != "" {
				e.check("DBN003", 1)
				if st := Style(c.Name); !StyleCompatible(st, want) {
					e.add("DBN003", "column", ref, []string{styleLabel(st), styleLabel(want)})
				}
			}
			e.nameChecks(ref, "column", c.Name)
			// users.user_name: the table name repeated in a column (not FK-ish "user_id").
			e.check("DBN009", 1)
			ct := Tokens(foldTR(c.Name))
			if len(ct) > 1 && len(tableTokens) > 0 && singular(ct[0]) == singular(tableTokens[len(tableTokens)-1]) && ct[len(ct)-1] != "id" {
				e.add("DBN009", "column", ref, []string{c.Name})
			}
		}
	}
	if dom == "" {
		return ""
	}
	return styleLabel(dom) + " " + strconv.Itoa(pct) + "%"
}

func singular(w string) string {
	switch {
	case strings.HasSuffix(w, "ies") && len(w) > 4:
		return w[:len(w)-3] + "y"
	case strings.HasSuffix(w, "ses") || strings.HasSuffix(w, "xes"):
		return w[:len(w)-2]
	case strings.HasSuffix(w, "ler") || strings.HasSuffix(w, "lar"):
		return w[:len(w)-3]
	case strings.HasSuffix(w, "s") && !strings.HasSuffix(w, "ss"):
		return w[:len(w)-1]
	}
	return w
}

func (e *evaluator) plurality() string {
	count := map[string]int{}
	for _, t := range e.tables {
		if pl := Plurality(t.Name); pl != "" {
			count[pl]++
		}
	}
	want := e.p.TableNumber
	if want == "any" {
		return ""
	}
	dom := "plural"
	if count["singular"] > count["plural"] {
		dom = "singular"
	}
	if want == CaseAuto {
		want = dom
	}
	for _, t := range e.tables {
		pl := Plurality(t.Name)
		if pl == "" {
			continue
		}
		e.check("DBN004", 1)
		if pl != want {
			e.add("DBN004", "table", t.QualifiedName(), []string{pl, want})
		}
	}
	total := count["plural"] + count["singular"]
	if total == 0 {
		return ""
	}
	return dom + " " + strconv.Itoa(count[dom]*100/total) + "%"
}

// ---------- consistency ----------

// auditConcepts maps a concept to the folded names that express it.
var auditConcepts = map[string][]string{
	"created": {
		"createdat", "createdon", "createddate", "createdtime", "createddatetime", "creationdate", "creationtime",
		"createdate", "createtime", "createdatetime", "insertdate", "inserteddate", "insertedat", "insertedon", "insertdatetime",
		"datecreated", "createdts", "createdtimestamp", "olusturmatarihi", "olusturulmatarihi", "kayittarihi", "eklenmetarihi",
		"eklemetarihi",
	},
	"updated": {
		"updatedat", "updatedon", "updateddate", "updatedtime", "updatetime", "updatedate", "updatedatetime",
		"modifiedat", "modifiedon", "modifieddate", "modifydate", "modifytime", "modificationdate", "lastmodified",
		"lastmodifieddate", "lastmodifiedat", "lastupdated", "lastupdate", "lastupdatedate", "lastupdatedat",
		"datemodified", "dateupdated", "editdate", "editedat", "changedat", "changedate", "updatedts", "updatedtimestamp",
		"guncellemetarihi", "guncellenmetarihi", "degistirmetarihi", "degisiklitarihi",
	},
	"deleted": {"deletedat", "deletedon", "deleteddate", "deletedate", "deletiondate", "removedat", "silinmetarihi", "silmetarihi"},
	"deleted_flag": {
		"isdeleted", "deleted", "deletedflag", "isremoved", "removed", "silindi", "silinmis", "issilindi",
		"silindimi",
	},
	"created_by": {
		"createdby", "createdbyid", "createdbyuser", "createdbyuserid", "createuser", "createuserid",
		"createduser", "createduserid", "creatorid", "creator", "insertuser", "insertedby", "insertuserid", "olusturan",
		"olusturankullanici", "olusturankullaniciid", "ekleyen", "ekleyenkullanici", "kaydeden",
	},
	"updated_by": {
		"updatedby", "updatedbyid", "updatedbyuser", "updateuser", "updateuserid", "modifiedby", "modifiedbyid",
		"modifyuser", "modifyuserid", "lastmodifiedby", "lastupdatedby", "editedby", "changedby", "guncelleyen",
		"guncelleyenkullanici", "degistiren", "degistirenkullanici",
	},
}

// AuditConcepts lists the concept keys in display order.
var AuditConcepts = []string{"created", "updated", "deleted", "deleted_flag", "created_by", "updated_by"}

var auditIndex = func() map[string]string {
	m := map[string]string{}
	for concept, names := range auditConcepts {
		for _, n := range names {
			m[n] = concept
		}
	}
	return m
}()

func (e *evaluator) consistency() {
	// DBC001: one name per audit concept.
	type variant struct {
		name   string
		tables []string
	}
	concepts := map[string]map[string]*variant{}
	hasCreated, hasUpdated := map[*Table]bool{}, map[*Table]bool{}
	for _, t := range e.tables {
		for i := range t.Columns {
			c := &t.Columns[i]
			concept, ok := auditIndex[Fold(c.Name)]
			if !ok {
				continue
			}
			switch concept {
			case "created":
				hasCreated[t] = true
			case "updated":
				hasUpdated[t] = true
			}
			if concepts[concept] == nil {
				concepts[concept] = map[string]*variant{}
			}
			key := Fold(c.Name)
			v := concepts[concept][key]
			if v == nil {
				v = &variant{name: c.Name}
				concepts[concept][key] = v
			}
			v.tables = append(v.tables, t.QualifiedName())
		}
	}
	for _, concept := range AuditConcepts {
		vs := concepts[concept]
		if len(vs) == 0 {
			continue
		}
		e.check("DBC001", 1)
		list := make([]*variant, 0, len(vs))
		for _, v := range vs {
			list = append(list, v)
		}
		sort.Slice(list, func(i, j int) bool {
			if len(list[i].tables) != len(list[j].tables) {
				return len(list[i].tables) > len(list[j].tables)
			}
			return list[i].name < list[j].name
		})
		want := list[0].name
		if fixed := e.p.AuditNames[concept]; fixed != "" {
			want = fixed
		}
		var details []string
		bad := 0
		for _, v := range list {
			if Fold(v.name) == Fold(want) {
				continue
			}
			bad += len(v.tables)
			details = append(details, fmt.Sprintf("%s (%d): %s", v.name, len(v.tables), sample(v.tables, 8)))
		}
		if bad > 0 {
			e.add("DBC001", "concept", concept, []string{want, strconv.Itoa(len(list)), strconv.Itoa(bad)}, details...)
		}
	}

	// DBC002: the same column name with different types.
	type use struct {
		typ    string
		base   string
		tables []string
	}
	byCol := map[string]map[string]*use{}
	display := map[string]string{}
	for _, t := range e.tables {
		for i := range t.Columns {
			c := &t.Columns[i]
			k := Fold(c.Name)
			if k == "id" {
				continue // primary keys are checked by DBC003/DBC004
			}
			if byCol[k] == nil {
				byCol[k] = map[string]*use{}
				display[k] = c.Name
			}
			u := byCol[k][c.FullType]
			if u == nil {
				u = &use{typ: c.FullType, base: baseType(c.DataType)}
				byCol[k][c.FullType] = u
			}
			u.tables = append(u.tables, t.QualifiedName())
		}
	}
	keys := make([]string, 0, len(byCol))
	for k := range byCol {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		uses := byCol[k]
		n := 0
		bases := map[string]bool{}
		for _, u := range uses {
			n += len(u.tables)
			bases[u.base] = true
		}
		if n < 2 {
			continue
		}
		e.check("DBC002", 1)
		if len(uses) < 2 {
			continue
		}
		list := make([]*use, 0, len(uses))
		for _, u := range uses {
			list = append(list, u)
		}
		sort.Slice(list, func(i, j int) bool { return len(list[i].tables) > len(list[j].tables) })
		var details, types []string
		for _, u := range list {
			types = append(types, u.typ)
			details = append(details, fmt.Sprintf("%s (%d): %s", u.typ, len(u.tables), sample(u.tables, 8)))
		}
		sev := "medium"
		if len(bases) == 1 {
			sev = "low" // only lengths/precision differ
		}
		e.addSev("DBC002", sev, "column", display[k], []string{display[k], strings.Join(types, ", ")}, details...)
	}

	// DBC003: FK column type differs from the referenced column.
	for _, t := range e.tables {
		for _, fk := range t.ForeignKey {
			ref := e.lookup(fk.RefSchema, fk.RefTable)
			if ref == nil {
				continue
			}
			for i, col := range fk.Columns {
				if i >= len(fk.RefColumns) {
					break
				}
				a, b := t.column(col), ref.column(fk.RefColumns[i])
				if a == nil || b == nil {
					continue
				}
				e.check("DBC003", 1)
				if !sameType(a, b) {
					e.add("DBC003", "foreign_key", t.QualifiedName()+"."+col,
						[]string{a.FullType, ref.QualifiedName() + "." + b.Name, b.FullType})
				}
			}
		}
	}

	// DBC004: primary key naming pattern.
	styles := map[string][]string{}
	for _, t := range e.tables {
		if len(t.PrimaryKey) != 1 {
			continue
		}
		pk := Fold(t.PrimaryKey[0])
		tn := Fold(Tokens(foldTR(t.Name))[len(Tokens(foldTR(t.Name)))-1])
		switch {
		case pk == "id":
			styles["id"] = append(styles["id"], t.QualifiedName())
		case pk == tn+"id" || pk == singular(tn)+"id" || pk == Fold(t.Name)+"id" || pk == singular(Fold(t.Name))+"id":
			styles["<table>Id"] = append(styles["<table>Id"], t.QualifiedName())
		}
	}
	if len(styles["id"]) > 0 || len(styles["<table>Id"]) > 0 {
		e.check("DBC004", 1)
	}
	if len(styles["id"]) > 0 && len(styles["<table>Id"]) > 0 {
		major, minor := "id", "<table>Id"
		if len(styles["<table>Id"]) > len(styles["id"]) {
			major, minor = minor, major
		}
		e.add("DBC004", "concept", "primary_key", []string{major, minor, strconv.Itoa(len(styles[minor]))},
			fmt.Sprintf("%s (%d): %s", major, len(styles[major]), sample(styles[major], 6)),
			fmt.Sprintf("%s (%d): %s", minor, len(styles[minor]), sample(styles[minor], 10)))
	}

	// DBS010 (structure) uses the audit scan above.
	if *e.p.RequireAudit {
		for _, t := range e.tables {
			e.check("DBS010", 1)
			var miss []string
			if !hasCreated[t] {
				miss = append(miss, "created")
			}
			if !hasUpdated[t] {
				miss = append(miss, "updated")
			}
			if len(miss) > 0 {
				e.add("DBS010", "table", t.QualifiedName(), []string{strings.Join(miss, ", ")})
			}
		}
	}
}

func sample(list []string, n int) string {
	if len(list) <= n {
		return strings.Join(list, ", ")
	}
	return strings.Join(list[:n], ", ") + fmt.Sprintf(" … +%d", len(list)-n)
}

func (e *evaluator) lookup(schema, name string) *Table {
	if t := e.byName[Fold(qualified(schema, name))]; t != nil {
		return t
	}
	return e.byName[Fold(name)]
}

func (t *Table) column(name string) *Column {
	for i := range t.Columns {
		if strings.EqualFold(t.Columns[i].Name, name) {
			return &t.Columns[i]
		}
	}
	return nil
}

func baseType(t string) string {
	switch t {
	case "int", "int4", "integer", "mediumint":
		return "integer"
	case "int8", "bigint":
		return "bigint"
	case "int2", "smallint", "tinyint":
		return "smallint"
	case "varchar", "nvarchar", "character varying", "text", "ntext", "longtext", "mediumtext", "tinytext", "char", "nchar", "bpchar":
		return "string"
	case "datetime", "datetime2", "timestamp", "timestamptz", "smalldatetime", "datetimeoffset", "timestamp without time zone", "timestamp with time zone":
		return "timestamp"
	case "decimal", "numeric", "money", "smallmoney":
		return "decimal"
	case "float", "real", "double", "double precision", "float4", "float8":
		return "float"
	case "bit", "boolean", "bool":
		return "boolean"
	case "uuid", "uniqueidentifier":
		return "uuid"
	}
	return t
}

func sameType(a, b *Column) bool {
	if strings.EqualFold(a.FullType, b.FullType) {
		return true
	}
	// "integer" vs "int(11)" on MySQL: compare base types and lengths only.
	return baseType(a.DataType) == baseType(b.DataType) && a.DataType == b.DataType && a.Length == b.Length
}

// ---------- structure ----------

var moneyWords = setOf(`price amount total cost balance fee salary charge payment tax discount subtotal tutar fiyat ucret bakiye maas toplam odeme borc alacak indirim vergi bedel`)

var dateWords = setOf(`date time datetime timestamp at tarih tarihi zaman`)

func isStringType(t string) bool {
	switch t {
	case "varchar", "nvarchar", "char", "nchar", "text", "ntext", "character varying", "bpchar", "tinytext", "mediumtext", "longtext":
		return true
	}
	return false
}

func isFloatType(t string) bool {
	switch t {
	case "float", "real", "double", "double precision", "float4", "float8":
		return true
	}
	return false
}

// typeMax is the largest value of an integer identity type (0 = unknown).
func typeMax(c *Column) float64 {
	unsigned := strings.Contains(c.FullType, "unsigned")
	switch c.DataType {
	case "tinyint":
		if unsigned {
			return 255
		}
		return 127
	case "smallint", "int2":
		if unsigned {
			return 65535
		}
		return 32767
	case "mediumint":
		if unsigned {
			return 16777215
		}
		return 8388607
	case "int", "integer", "int4", "serial":
		if unsigned {
			return 4294967295
		}
		return 2147483647
	case "bigint", "int8", "bigserial":
		return 9.2e18
	}
	return 0
}

func (e *evaluator) structure() {
	for _, t := range e.tables {
		name := t.QualifiedName()
		e.check("DBS001", 1)
		if len(t.PrimaryKey) == 0 {
			e.add("DBS001", "table", name, nil)
		}
		e.check("DBS005", 1)
		if len(t.Columns) > e.p.MaxColumns {
			e.add("DBS005", "table", name, []string{strconv.Itoa(len(t.Columns)), strconv.Itoa(e.p.MaxColumns)})
		}

		// DBS002: FK columns without a supporting index (MySQL creates one).
		if e.s.Engine != EngineMySQL {
			for _, fk := range t.ForeignKey {
				e.check("DBS002", 1)
				if !t.indexed(fk.Columns) {
					e.add("DBS002", "foreign_key", name+"."+strings.Join(fk.Columns, ","), []string{fk.Name})
				}
			}
		}

		// DBS003: "<table>_id" columns without a foreign key to that table.
		inFK := map[string]bool{}
		for _, fk := range t.ForeignKey {
			for _, c := range fk.Columns {
				inFK[strings.ToLower(c)] = true
			}
		}
		pk := map[string]bool{}
		for _, c := range t.PrimaryKey {
			pk[strings.ToLower(c)] = true
		}
		for i := range t.Columns {
			c := &t.Columns[i]
			toks := Tokens(foldTR(c.Name))
			if len(toks) < 2 || toks[len(toks)-1] != "id" || inFK[strings.ToLower(c.Name)] || pk[strings.ToLower(c.Name)] {
				continue
			}
			target := strings.Join(toks[:len(toks)-1], "")
			ref := e.byName[target]
			if ref == nil {
				ref = e.byName[target+"s"]
			}
			if ref == nil {
				ref = e.byName[strings.TrimSuffix(target, "y")+"ies"]
			}
			if ref == nil || ref == t {
				continue
			}
			e.check("DBS003", 1)
			e.add("DBS003", "column", colRef(t, c), []string{ref.QualifiedName()})
		}

		// DBS004: duplicate or redundant (left-prefix) indexes.
		for i, a := range t.Indexes {
			if len(a.Columns) == 0 || a.Primary {
				continue
			}
			e.check("DBS004", 1)
			for j, b := range t.Indexes {
				if i == j || len(b.Columns) < len(a.Columns) {
					continue
				}
				if prefix(a.Columns, b.Columns) && (len(b.Columns) > len(a.Columns) && !a.Unique || len(b.Columns) == len(a.Columns) && (j < i || b.Primary)) {
					e.add("DBS004", "index", name+"."+a.Name, []string{a.Name, b.Name})
					break
				}
			}
		}

		// DBS006: discouraged types and storage settings.
		if e.s.Engine == EngineMySQL {
			e.check("DBS006", 1)
			if strings.EqualFold(t.StorageEngine, "MyISAM") {
				e.add("DBS006", "table", name, []string{"ENGINE=MyISAM", "InnoDB"})
			}
			if utf8mb3(t.Collation) {
				e.addSev("DBS006", "low", "table", name, []string{t.Collation, "utf8mb4"})
			}
		}
		nonPKNullable, nonPK := 0, 0
		for i := range t.Columns {
			c := &t.Columns[i]
			ref := colRef(t, c)
			toks := Tokens(foldTR(c.Name))
			last := ""
			if len(toks) > 0 {
				last = toks[len(toks)-1]
			}
			e.check("DBS006", 1)
			switch {
			case e.s.Engine == EngineMSSQL && (c.DataType == "text" || c.DataType == "ntext" || c.DataType == "image"):
				repl := map[string]string{"text": "varchar(max)", "ntext": "nvarchar(max)", "image": "varbinary(max)"}[c.DataType]
				e.add("DBS006", "column", ref, []string{c.DataType, repl})
			case e.s.Engine == EnginePostgres && c.DataType == "money":
				e.add("DBS006", "column", ref, []string{"money", "numeric(19,4)"})
			case e.s.Engine == EngineMySQL && utf8mb3(c.Collation):
				e.addSev("DBS006", "low", "column", ref, []string{c.Collation, "utf8mb4"})
			}
			// DBS007: money in floating point.
			e.check("DBS007", 1)
			if isFloatType(c.DataType) && anyWord(toks, moneyWords) {
				e.add("DBS007", "column", ref, []string{c.FullType})
			}
			// DBS008: dates stored as text.
			e.check("DBS008", 1)
			if isStringType(c.DataType) && dateWords[last] {
				e.add("DBS008", "column", ref, []string{c.FullType})
			}
			// DBS009: audit timestamps without time zone / legacy datetime.
			if concept := auditIndex[Fold(c.Name)]; concept == "created" || concept == "updated" || concept == "deleted" {
				e.check("DBS009", 1)
				switch {
				case e.s.Engine == EnginePostgres && c.DataType == "timestamp":
					e.add("DBS009", "column", ref, []string{"timestamp", "timestamptz"})
				case e.s.Engine == EngineMSSQL && (c.DataType == "datetime" || c.DataType == "smalldatetime"):
					e.add("DBS009", "column", ref, []string{c.DataType, "datetime2 / datetimeoffset"})
				}
			}
			// DBS011: identity close to the maximum of its type.
			if c.Identity && c.IdentityValue > 0 {
				if maxV := typeMax(c); maxV > 0 {
					e.check("DBS011", 1)
					ratio := float64(c.IdentityValue) / maxV
					switch {
					case ratio >= 0.8:
						e.add("DBS011", "column", ref, []string{strconv.FormatInt(c.IdentityValue, 10), c.FullType, strconv.Itoa(int(ratio * 100))})
					case ratio >= 0.5:
						e.addSev("DBS011", "medium", "column", ref, []string{strconv.FormatInt(c.IdentityValue, 10), c.FullType, strconv.Itoa(int(ratio * 100))})
					}
				}
			}
			// DBS014: column collation differs from the database default.
			if e.s.Collation != "" && c.Collation != "" && e.s.Engine != EnginePostgres {
				e.check("DBS014", 1)
				if !strings.EqualFold(c.Collation, e.s.Collation) {
					e.add("DBS014", "column", ref, []string{c.Collation, e.s.Collation})
				}
			}
			if !pk[strings.ToLower(c.Name)] {
				nonPK++
				if c.Nullable {
					nonPKNullable++
				}
			}
		}
		// DBS012: every non-key column nullable.
		e.check("DBS012", 1)
		if nonPK >= 3 && nonPKNullable == nonPK {
			e.add("DBS012", "table", name, []string{strconv.Itoa(nonPK)})
		}
		// DBS013: empty table (row estimate 0; -1 = unknown).
		e.check("DBS013", 1)
		if t.RowEst == 0 {
			e.add("DBS013", "table", name, nil)
		}
	}
}

func utf8mb3(coll string) bool {
	l := strings.ToLower(coll)
	return strings.HasPrefix(l, "utf8_") || strings.HasPrefix(l, "utf8mb3_")
}

func anyWord(toks []string, set map[string]bool) bool {
	for _, t := range toks {
		if set[t] {
			return true
		}
	}
	return false
}

func prefix(a, b []string) bool {
	if len(a) > len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
}

// indexed reports whether cols are the leading columns of some index.
func (t *Table) indexed(cols []string) bool {
	for _, ix := range t.Indexes {
		if len(ix.Columns) >= len(cols) && sameSet(ix.Columns[:len(cols)], cols) {
			return true
		}
	}
	return false
}

func sameSet(a, b []string) bool {
	m := map[string]bool{}
	for _, x := range a {
		m[strings.ToLower(x)] = true
	}
	for _, x := range b {
		if !m[strings.ToLower(x)] {
			return false
		}
	}
	return true
}

// ---------- security ----------

var (
	passwordWords  = setOf(`password passwd pwd pass passcode sifre parola`)
	sensitiveNames = setOf(`tckimlik tckimlikno tckn tcno tckimliknumarasi kimlikno kimliknumarasi ssn socialsecuritynumber
creditcard creditcardnumber cardnumber cardno kartno kartnumarasi kredikarti kredikartino cvv cvc cvv2 iban ibanno
passport passportno passportnumber pasaport pasaportno vergikimlikno vkn taxnumber taxid`)
)

func (e *evaluator) security() {
	for _, t := range e.tables {
		for i := range t.Columns {
			c := &t.Columns[i]
			toks := Tokens(foldTR(c.Name))
			ref := colRef(t, c)
			// DBX001: password column too short to hold a modern hash.
			if anyWord(toks, passwordWords) && !anyWord(toks, setOf("hash hashed salt reset policy expire expires expiry expiration changed date at")) {
				e.check("DBX001", 1)
				if isStringType(c.DataType) && c.Length > 0 && c.Length < 60 {
					e.add("DBX001", "column", ref, []string{c.FullType})
				}
			}
			e.check("DBX002", 1)
			if sensitiveNames[Fold(c.Name)] {
				e.add("DBX002", "column", ref, []string{c.Name})
			}
		}
	}
	// DBX003: privileges granted to everyone.
	byTable := map[string][]string{}
	var order []string
	for _, g := range e.s.PublicGrants {
		if e.p.Excluded(g.Schema, g.Table) {
			continue
		}
		k := qualified(g.Schema, g.Table)
		if _, ok := byTable[k]; !ok {
			order = append(order, k)
		}
		byTable[k] = append(byTable[k], strings.ToUpper(g.Privilege))
	}
	e.check("DBX003", len(e.tables))
	for _, k := range order {
		privs := byTable[k]
		sev := "medium"
		for _, p := range privs {
			if p != "SELECT" && p != "REFERENCES" {
				sev = "high"
			}
		}
		e.addSev("DBX003", sev, "table", k, []string{strings.Join(privs, ", ")})
	}
}

// ---------- score ----------

// Points per severity when every checked object violates a rule.
var sevWeight = map[string]float64{"critical": 40, "high": 30, "medium": 15, "low": 6, "info": 0}

func (r *Report) score() {
	byRule := map[string][]Finding{}
	for _, f := range r.Findings {
		byRule[f.RuleID] = append(byRule[f.RuleID], f)
	}
	catPenalty := map[string]float64{}
	catFindings := map[string]int{}
	for id, fs := range byRule {
		rule := RuleByID(id)
		checked := r.Checked[id]
		if checked < len(fs) {
			checked = len(fs)
		}
		// The worst severity of the rule's findings, weighted by how much
		// of the database violates it: 3 of 300 tables without a PK cost
		// less than 3 of 4.
		worst := 0.0
		for _, f := range fs {
			worst = max(worst, sevWeight[f.Severity])
		}
		ratio := float64(len(fs)) / float64(checked)
		// Any finding costs at least a fifth of the rule's weight.
		catPenalty[rule.Category] += worst * max(ratio, 0.2)
		catFindings[rule.Category] += len(fs)
	}
	total, weights := 0.0, 0.0
	for _, c := range Categories {
		s := int(max(0, 100-catPenalty[c.ID]) + 0.5)
		r.Categories = append(r.Categories, CategoryScore{Category: c.ID, Score: s, Findings: catFindings[c.ID]})
		total += float64(s * c.Weight)
		weights += float64(c.Weight)
	}
	r.Score = int(total/weights + 0.5)
	r.Grade = report.Grade(r.Score)
}
