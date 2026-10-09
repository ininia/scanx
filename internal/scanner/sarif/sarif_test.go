package sarif

import (
	"testing"

	"github.com/ininia/scanx/internal/finding"
)

const doc = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x","rules":[
 {"id":"R1","shortDescription":{"text":"Weak hash"},"fullDescription":{"text":"The digest is broken"},
  "help":{"text":"Use SHA-256"},"helpUri":"https://example.com/r1",
  "properties":{"tags":["security","external/cwe/cwe-327"],"security-severity":"7.5"}},
 {"id":"R2","defaultConfiguration":{"level":"note"}}]}},
 "results":[
  {"ruleId":"R1","ruleIndex":0,"level":"error","message":{"text":"weak digest used"},
   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///work/src/a.cs"},"region":{"startLine":3,"endLine":4}}}]},
  {"ruleId":"R2","message":{"text":"style thing\nmore"},
   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.sh"},"region":{"startLine":9}}}]}]}]}`

func TestParse(t *testing.T) {
	fs, err := Parse([]byte(doc), Options{Tool: "x", Category: finding.CategorySAST})
	if err != nil || len(fs) != 2 {
		t.Fatal(fs, err)
	}
	a := fs[0]
	if a.Severity != finding.High || a.Title != "Weak hash" || a.CWE[0] != "CWE-327" || a.File != "/work/src/a.cs" ||
		a.StartLine != 3 || a.Remediation != "Use SHA-256" || a.References[0] != "https://example.com/r1" {
		t.Fatalf("%+v", a)
	}
	b := fs[1]
	if b.Severity != finding.Info || b.Title != "style thing" || b.File != "b.sh" {
		t.Fatalf("%+v", b)
	}
	if _, err := Parse([]byte("{"), Options{Tool: "x"}); err == nil {
		t.Fatal("bad json accepted")
	}
}
