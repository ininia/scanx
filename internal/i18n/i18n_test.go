package i18n

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestCatalogsHaveSameKeys(t *testing.T) {
	a, b := Keys(TR), Keys(EN)
	sort.Strings(a)
	sort.Strings(b)
	if strings.Join(a, ",") != strings.Join(b, ",") {
		for _, k := range a {
			if _, ok := en[k]; !ok {
				t.Errorf("missing in en: %s", k)
			}
		}
		for _, k := range b {
			if _, ok := tr[k]; !ok {
				t.Errorf("missing in tr: %s", k)
			}
		}
	}
}

// Every p.T("...") key used in templates must exist.
func TestTemplateKeysExist(t *testing.T) {
	re := regexp.MustCompile(`\.T\("([a-z0-9_.]+)"`)
	files, _ := filepath.Glob(filepath.Join("..", "ui", "*.templ"))
	if len(files) == 0 {
		t.Fatal("no templates found")
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			if strings.HasSuffix(m[1], ".") { // dynamic key: "role." + role
				found := false
				for _, k := range Keys(EN) {
					found = found || strings.HasPrefix(k, m[1])
				}
				if !found {
					t.Errorf("%s: no keys with prefix %q", filepath.Base(f), m[1])
				}
				continue
			}
			if !Has(m[1]) {
				t.Errorf("%s: unknown key %q", filepath.Base(f), m[1])
			}
		}
	}
}

func TestTAndDetect(t *testing.T) {
	if T(TR, "nav.projects") != "Projeler" || T(EN, "nav.projects") != "Projects" || T("de", "nav.projects") != "Projects" {
		t.Fatal("T")
	}
	if T(EN, "invite.title", "Acme") != "Invitation to Acme" || T(EN, "no.such.key") != "no.such.key" {
		t.Fatal("args/fallback")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Language", "de-DE, en-US;q=0.8")
	if Detect(r, "", "lang", TR) != EN {
		t.Fatal("accept-language")
	}
	if Detect(r, "tr", "lang", EN) != TR {
		t.Fatal("user locale wins")
	}
	r2 := httptest.NewRequest("GET", "/", nil)
	if Detect(r2, "", "lang", "xx") != TR {
		t.Fatal("default")
	}
}
