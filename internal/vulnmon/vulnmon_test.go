package vulnmon

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParsePURL(t *testing.T) {
	cases := map[string]Component{
		"pkg:npm/%40angular/core@16.2.0":                       {Ecosystem: "npm", Name: "@angular/core", Version: "16.2.0"},
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1": {Ecosystem: "Maven", Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1"},
		"pkg:pypi/Django_Rest@3.0?arch=x":                      {Ecosystem: "PyPI", Name: "django-rest", Version: "3.0"},
		"pkg:nuget/Newtonsoft.Json@13.0.1":                     {Ecosystem: "NuGet", Name: "Newtonsoft.Json", Version: "13.0.1"},
		"pkg:golang/github.com/gin-gonic/gin@v1.9.0":           {Ecosystem: "Go", Name: "github.com/gin-gonic/gin", Version: "v1.9.0"},
		"pkg:composer/laravel/framework@10.0.0":                {Ecosystem: "Packagist", Name: "laravel/framework", Version: "10.0.0"},
	}
	for in, want := range cases {
		got, ok := ParsePURL(in)
		if !ok || got.Ecosystem != want.Ecosystem || got.Name != want.Name || got.Version != want.Version {
			t.Errorf("%s: %+v", in, got)
		}
	}
	if _, ok := ParsePURL("pkg:deb/debian/openssl@1.1"); ok {
		t.Error("deb accepted")
	}
}

func TestFromCycloneDX(t *testing.T) {
	doc := `{"components":[
	 {"purl":"pkg:npm/lodash@4.17.20","licenses":[{"license":{"id":"MIT"}}]},
	 {"purl":"pkg:npm/lodash@4.17.20"},
	 {"purl":"pkg:maven/a/b@1","components":[{"purl":"pkg:maven/c/d@2","licenses":[{"expression":"GPL-3.0-only"}]}]},
	 {"name":"no purl"}]}`
	cs, err := FromCycloneDX([]byte(doc))
	if err != nil || len(cs) != 3 || cs[2].Licenses[0] != "MIT" {
		t.Fatalf("%+v %v", cs, err)
	}
	if !RiskyLicense("GPL-3.0-only") || RiskyLicense("LGPL-2.1") || RiskyLicense("MIT") || !RiskyLicense("AGPL-3.0") {
		t.Fatal("licenses")
	}
}

func rec(t *testing.T, js string) *Record {
	var r Record
	if err := json.Unmarshal([]byte(js), &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

func TestMatchRecordRanges(t *testing.T) {
	ix := Index{}
	ix.Add(Component{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"})
	ix.Add(Component{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"})
	ix.Add(Component{Ecosystem: "Maven", Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1"})
	ix.Add(Component{Ecosystem: "PyPI", Name: "Django", Version: "3.2.0"})
	r := rec(t, `{"id":"GHSA-1","aliases":["CVE-2021-23337"],"summary":"Command injection","database_specific":{"severity":"HIGH"},
	  "affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"fixed":"4.17.21"},{"introduced":"0"}]}]}]}`)
	ms := MatchRecord(r, ix)
	if len(ms) != 1 || ms[0].Version != "4.17.20" || ms[0].Fixed != "4.17.21" || ms[0].Severity != "high" || CVE(ms[0].VulnID, ms[0].Aliases) != "CVE-2021-23337" {
		t.Fatalf("%+v", ms)
	}
	r = rec(t, `{"id":"GHSA-log4shell","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
	  "affected":[{"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0-beta9"},{"fixed":"2.15.0"}]}]}]}`)
	if ms := MatchRecord(r, ix); len(ms) != 1 || ms[0].Severity != "critical" {
		t.Fatalf("log4shell %+v", ms)
	}
	r = rec(t, `{"id":"PYSEC-1","affected":[{"package":{"ecosystem":"PyPI","name":"django"},"versions":["3.2.0"]}]}`)
	if ms := MatchRecord(r, ix); len(ms) != 1 || ms[0].Severity != "medium" {
		t.Fatalf("pypi versions %+v", ms)
	}
	r = rec(t, `{"id":"W","withdrawn":"2024-01-01","affected":[{"package":{"ecosystem":"npm","name":"lodash"},"versions":["4.17.20"]}]}`)
	if ms := MatchRecord(r, ix); len(ms) != 0 {
		t.Fatal("withdrawn matched")
	}
	r = rec(t, `{"id":"LA","affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"4.0.0"},{"last_affected":"4.17.20"}]}]}]}`)
	if ms := MatchRecord(r, ix); len(ms) != 1 || ms[0].Version != "4.17.20" {
		t.Fatalf("last_affected %+v", ms)
	}
}

func TestCVSS3(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N": 4.3,
		"CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N": 0,
	}
	for v, want := range cases {
		if got, ok := CVSS3(v); !ok || got != want {
			t.Errorf("%s = %v want %v", v, got, want)
		}
	}
}

func TestMatchZip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "npm.zip")
	f, _ := os.Create(p)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("GHSA-1.json")
	_, _ = w.Write([]byte(`{"id":"GHSA-1","affected":[{"package":{"ecosystem":"npm","name":"lodash"},"versions":["4.17.20"]}]}`))
	_ = zw.Close()
	_ = f.Close()
	ix := Index{}
	ix.Add(Component{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"})
	ms, n, err := MatchZip(p, ix)
	if err != nil || n != 1 || len(ms) != 1 {
		t.Fatalf("%v %d %v", ms, n, err)
	}
}
