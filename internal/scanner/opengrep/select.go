package opengrep

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Loading and validating every rule costs minutes on a small server, so only
// rule files for languages present in the repository are passed to opengrep.
// Language-independent rules (generic, regex) are always kept, and so is any
// file whose languages cannot be read (fail open: never lose coverage).

var (
	inlineLangs = regexp.MustCompile(`(?m)^\s*-?\s*languages:\s*\[([^\]]*)\]`)
	blockLangs  = regexp.MustCompile(`(?m)^(\s*)-?\s*languages:\s*\n((?:\s*-\s*[^\n]+\n?)+)`)
	listItem    = regexp.MustCompile(`(?m)^\s*-\s*["']?([A-Za-z0-9#+_-]+)["']?`)
)

// langAliases maps opengrep language names to scanX detect names.
var langAliases = map[string]string{
	"js": "javascript", "ts": "typescript", "py": "python", "c#": "csharp", "cs": "csharp",
	"golang": "go", "rb": "ruby", "kt": "kotlin", "tf": "hcl", "terraform": "hcl", "sh": "bash",
	"docker": "dockerfile", "yml": "yaml", "c++": "cpp", "cplusplus": "cpp", "javascriptreact": "javascript",
	"typescriptreact": "typescript", "none": "generic",
}

// alwaysLangs are not tied to one source language.
var alwaysLangs = map[string]bool{"generic": true, "regex": true}

func normLang(l string) string {
	l = strings.ToLower(strings.Trim(strings.TrimSpace(l), `"'`))
	if a, ok := langAliases[l]; ok {
		return a
	}
	return l
}

// ruleLanguages returns the languages a rule file targets (nil if unknown).
func ruleLanguages(data []byte) []string {
	seen := map[string]bool{}
	for _, m := range inlineLangs.FindAllSubmatch(data, -1) {
		for _, l := range strings.Split(string(m[1]), ",") {
			if l = normLang(l); l != "" {
				seen[l] = true
			}
		}
	}
	for _, m := range blockLangs.FindAllSubmatch(data, -1) {
		for _, it := range listItem.FindAllSubmatch(m[2], -1) {
			if l := normLang(string(it[1])); l != "" {
				seen[l] = true
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for l := range seen {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// selectRuleFiles lists the rule files under dirs that apply to langs.
// It returns all dirs unchanged when langs is empty (unknown repository).
func selectRuleFiles(dirs []string, langs []string) (configs []string, kept, total int) {
	if len(langs) == 0 {
		return dirs, 0, 0
	}
	want := map[string]bool{}
	for _, l := range langs {
		want[normLang(l)] = true
	}
	for _, d := range dirs {
		_ = filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if ext != ".yml" && ext != ".yaml" {
				return nil
			}
			total++
			data, err := os.ReadFile(p) //nolint:gosec // rule bundle inside the image
			if err != nil {
				return nil
			}
			ls := ruleLanguages(data)
			keep := ls == nil
			for _, l := range ls {
				keep = keep || want[l] || alwaysLangs[l]
			}
			if keep {
				configs = append(configs, p)
				kept++
			}
			return nil
		})
	}
	sort.Strings(configs)
	if len(configs) == 0 {
		// Nothing matched (e.g. a docs-only repository): run the generic set
		// via the directories so opengrep still validates the bundle.
		return dirs, 0, total
	}
	return configs, kept, total
}
