package dbscan

import (
	"reflect"
	"strings"
	"testing"
)

func TestTokensAndStyle(t *testing.T) {
	cases := map[string][]string{
		"created_at":       {"created", "at"},
		"CreatedDate":      {"created", "date"},
		"createdAt":        {"created", "at"},
		"HTTPServerLog":    {"http", "server", "log"},
		"order_items2":     {"order", "items", "2"},
		"MüşteriAdı":       {"müşteri", "adı"},
		"__EFMigrations":   {"ef", "migrations"},
		"UPPER_SNAKE_CASE": {"upper", "snake", "case"},
	}
	for in, want := range cases {
		if got := Tokens(in); !reflect.DeepEqual(got, want) {
			t.Errorf("Tokens(%q) = %v, want %v", in, got, want)
		}
	}
	styles := map[string]string{
		"created_at": CaseSnake, "CreatedAt": CasePascal, "createdAt": CaseCamel, "CREATED_AT": CaseUpperSnake,
		"users": "lower", "USERS": "upper", "Created_At": "mixed",
	}
	for in, want := range styles {
		if got := Style(in); got != want {
			t.Errorf("Style(%q) = %q, want %q", in, got, want)
		}
	}
	if Fold("Oluşturma_Tarihi") != "olusturmatarihi" {
		t.Fatal(Fold("Oluşturma_Tarihi"))
	}
	for in, want := range map[string]string{"Users": "plural", "user": "singular", "Status": "", "Addresses": "plural", "Kullanicilar": "plural", "Address": "singular", "MusteriAdresleri": "plural"} {
		if got := Plurality(in); got != want {
			t.Errorf("Plurality(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestForeignWords(t *testing.T) {
	if w := ForeignWords("MusteriAdi", "en"); len(w) != 2 {
		t.Fatalf("en: %v", w)
	}
	if w := ForeignWords("customer_name", "en"); len(w) != 0 {
		t.Fatalf("en: %v", w)
	}
	if w := ForeignWords("Sipariş", "en"); len(w) != 1 {
		t.Fatalf("turkish letters: %v", w)
	}
	if w := ForeignWords("customer_name", "tr"); len(w) != 2 {
		t.Fatalf("tr: %v", w)
	}
	if w := ForeignWords("musteri_id", "tr"); len(w) != 0 {
		t.Fatalf("tr: %v", w)
	}
}

func col(name, typ string, opts ...func(*Column)) Column {
	c := Column{Name: name, DataType: typ, FullType: typ}
	for _, o := range opts {
		o(&c)
	}
	return c
}

func sample1() *Snapshot {
	return &Snapshot{Engine: EngineMSSQL, Collation: "Turkish_CI_AS", Tables: []Table{
		{
			Schema: "dbo", Name: "Customers", PrimaryKey: []string{"Id"}, RowEst: 10,
			Columns: []Column{
				col("Id", "int"), col("Name", "nvarchar"), col("CreatedAt", "datetime2"), col("UpdatedAt", "datetime2"),
				col("Password", "varchar", func(c *Column) { c.FullType, c.Length = "varchar(32)", 32 }),
			},
			Indexes: []Index{{Name: "PK_Customers", Columns: []string{"Id"}, Primary: true, Unique: true}},
		},
		{
			Schema: "dbo", Name: "Orders", PrimaryKey: []string{"OrderId"}, RowEst: 5,
			Columns: []Column{
				col("OrderId", "bigint"), col("CustomerId", "bigint"), col("Price", "float"), col("CreatedDate", "datetime"),
				col("ModifiedDate", "datetime"), col("ShipDate", "varchar", func(c *Column) { c.FullType = "varchar(20)" }),
			},
			ForeignKey: []ForeignKey{{Name: "FK_Orders_Customers", Columns: []string{"CustomerId"}, RefSchema: "dbo", RefTable: "Customers", RefColumns: []string{"Id"}}},
		},
		{
			Schema: "dbo", Name: "MusteriAdresleri", RowEst: 0,
			Columns: []Column{col("Ilce", "nvarchar"), col("Sehir", "nvarchar"), col("CustomerId", "int"), col("Tckn", "char")},
		},
		{Schema: "dbo", Name: "__EFMigrationsHistory", Columns: []Column{col("MigrationId", "nvarchar")}},
		{
			Schema: "dbo", Name: "Counters", PrimaryKey: []string{"Id"}, RowEst: 1,
			Columns: []Column{col("Id", "int", func(c *Column) { c.Identity, c.IdentityValue = true, 2_000_000_000 }), col("Name", "nvarchar")},
			Indexes: []Index{{Name: "PK", Columns: []string{"Id"}, Primary: true}},
		},
	}}
}

func rules(r *Report) map[string][]Finding {
	m := map[string][]Finding{}
	for _, f := range r.Findings {
		m[f.RuleID] = append(m[f.RuleID], f)
	}
	return m
}

func TestEvaluateDefaults(t *testing.T) {
	r := Evaluate(sample1(), Profile{})
	got := rules(r)
	if r.Stats.Tables != 4 || r.Stats.Excluded != 1 {
		t.Fatalf("stats %+v", r.Stats)
	}
	expect := map[string]string{
		"DBN001": "dbo.MusteriAdresleri",            // Turkish table name
		"DBC001": "created",                         // CreatedAt vs CreatedDate
		"DBC003": "dbo.Orders.CustomerId",           // bigint → int
		"DBS001": "dbo.MusteriAdresleri",            // no primary key
		"DBS002": "dbo.Orders.CustomerId",           // FK without index
		"DBS003": "dbo.MusteriAdresleri.CustomerId", // looks like an FK
		"DBS007": "dbo.Orders.Price",                // money as float
		"DBS008": "dbo.Orders.ShipDate",             // date as text
		"DBS009": "dbo.Orders.CreatedDate",          // legacy datetime
		"DBS011": "dbo.Counters.Id",                 // identity near max
		"DBX001": "dbo.Customers.Password",          // short password column
		"DBX002": "dbo.MusteriAdresleri.Tckn",       // national id
		"DBS013": "dbo.MusteriAdresleri",            // empty
		"DBC004": "primary_key",                     // Id vs OrderId
		"DBS010": "dbo.MusteriAdresleri",            // no audit columns
		"DBC002": "CustomerId",                      // bigint vs int
		"DBN002": "",                                // (style is consistent: no finding expected)
	}
	for id, obj := range expect {
		if obj == "" {
			if len(got[id]) != 0 {
				t.Errorf("%s: unexpected %v", id, got[id])
			}
			continue
		}
		found := false
		for _, f := range got[id] {
			if f.Object == obj {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no finding for %s (got %v)", id, obj, got[id])
		}
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Object, "EFMigrations") {
			t.Errorf("excluded table reported: %+v", f)
		}
	}
	created := got["DBC001"][0]
	if created.Params[0] != "CreatedAt" || len(created.Details) != 1 || !strings.HasPrefix(created.Details[0], "CreatedDate (1)") {
		t.Fatalf("audit concept %+v", created)
	}
	if r.Grade == "" || r.Score <= 0 || r.Score >= 100 || r.Gate != "fail" || len(r.Categories) != 4 {
		t.Fatalf("score %d %s gate %s", r.Score, r.Grade, r.Gate)
	}
}

func TestProfileOverrides(t *testing.T) {
	off := false
	p := Profile{
		Language: "tr", AuditNames: map[string]string{"created": "CreatedDate"},
		Rules:   map[string]RuleSetting{"DBS001": {Enabled: &off}, "DBX001": {Severity: "low"}},
		Exclude: []string{"dbo.Counters"}, FailOn: "none",
	}
	got := rules(Evaluate(sample1(), p))
	for _, f := range got["DBN001"] {
		if f.Object == "dbo.MusteriAdresleri" {
			t.Fatal("Turkish names must be accepted with language=tr")
		}
	}
	if len(got["DBS001"]) != 0 || len(got["DBS011"]) != 0 {
		t.Fatalf("disabled/excluded: %v %v", got["DBS001"], got["DBS011"])
	}
	if got["DBX001"][0].Severity != "low" {
		t.Fatal("severity override")
	}
	if got["DBC001"][0].Params[0] != "CreatedDate" {
		t.Fatalf("fixed audit name: %+v", got["DBC001"][0])
	}
	if err := (Profile{Language: "xx"}).Validate(); err == nil {
		t.Fatal("bad language accepted")
	}
	if err := (Profile{Rules: map[string]RuleSetting{"NOPE": {}}}).Validate(); err == nil {
		t.Fatal("unknown rule accepted")
	}
}

func TestCaseStyleRule(t *testing.T) {
	s := &Snapshot{Engine: EnginePostgres, Tables: []Table{
		{Schema: "public", Name: "order_items", PrimaryKey: []string{"id"}, Columns: []Column{col("id", "integer"), col("created_at", "timestamptz"), col("unit_price", "numeric")}},
		{Schema: "public", Name: "customers", PrimaryKey: []string{"id"}, Columns: []Column{col("id", "integer"), col("full_name", "text"), col("createdAt", "timestamp")}},
		{Schema: "public", Name: "UserRoles", PrimaryKey: []string{"id"}, Columns: []Column{col("id", "integer"), col("role_name", "text")}},
	}}
	got := rules(Evaluate(s, Profile{}))
	if len(got["DBN002"]) != 1 || got["DBN002"][0].Object != "public.UserRoles" {
		t.Fatalf("table case: %v", got["DBN002"])
	}
	if len(got["DBN003"]) != 1 || got["DBN003"][0].Object != "public.customers.createdAt" {
		t.Fatalf("column case: %v", got["DBN003"])
	}
	if len(got["DBS009"]) != 1 {
		t.Fatalf("timestamp without tz: %v", got["DBS009"])
	}
	if len(got["DBN005"]) != 0 {
		t.Fatalf("reserved: %v", got["DBN005"])
	}
}

// One PascalCase table must not make the lowercase majority "wrong".
func TestDominantCountsSingleWords(t *testing.T) {
	if st, _ := dominant([]string{"customers", "orders", "user", "MusteriAdresleri"}); st != CaseSnake {
		t.Fatalf("tables: %s", st)
	}
	if st, _ := dominant([]string{"id", "name", "email", "createdAt", "updatedAt", "customerId"}); st != CaseCamel {
		t.Fatalf("camel columns: %s", st)
	}
}
