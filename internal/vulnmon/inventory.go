// Package vulnmon keeps a software inventory (from the CycloneDX SBOMs of
// repository scans) and matches it every day against the OSV open
// vulnerability database, so newly published advisories are found without
// rescanning code.
package vulnmon

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// Component is one package of a project.
type Component struct {
	Ecosystem string   `json:"ecosystem"` // OSV ecosystem name: npm, PyPI, Maven, NuGet, Go...
	Name      string   `json:"name"`      // OSV package name (maven: group:artifact)
	Version   string   `json:"version"`
	PURL      string   `json:"purl"`
	Licenses  []string `json:"licenses,omitempty"`
}

// purlEcosystem maps purl types to OSV ecosystems.
var purlEcosystem = map[string]string{
	"npm": "npm", "pypi": "PyPI", "maven": "Maven", "nuget": "NuGet", "golang": "Go", "cargo": "crates.io",
	"gem": "RubyGems", "composer": "Packagist", "pub": "Pub", "hex": "Hex", "swift": "SwiftURL", "cocoapods": "CocoaPods",
	"conan": "ConanCenter",
}

// Ecosystems are the OSV ecosystems the monitor downloads.
var Ecosystems = []string{"npm", "PyPI", "Maven", "NuGet", "Go", "crates.io", "RubyGems", "Packagist", "Pub", "Hex"}

// ParsePURL turns "pkg:npm/%40scope/name@1.2.3" into a component (ok
// false for types OSV does not cover).
func ParsePURL(purl string) (Component, bool) {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return Component{}, false
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")
	typ, path, ok := strings.Cut(rest, "/")
	if !ok {
		return Component{}, false
	}
	eco, ok := purlEcosystem[strings.ToLower(typ)]
	if !ok {
		return Component{}, false
	}
	version := ""
	if i := strings.LastIndex(path, "@"); i > 0 {
		path, version = path[:i], path[i+1:]
	}
	if v, err := url.PathUnescape(version); err == nil {
		version = v
	}
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if u, err := url.PathUnescape(p); err == nil {
			parts[i] = u
		}
	}
	var name string
	switch eco {
	case "Maven":
		if len(parts) < 2 {
			return Component{}, false
		}
		name = parts[0] + ":" + parts[1]
	case "PyPI":
		name = strings.ToLower(strings.ReplaceAll(strings.Join(parts, "/"), "_", "-"))
	default:
		name = strings.Join(parts, "/")
	}
	if name == "" || version == "" {
		return Component{}, false
	}
	return Component{Ecosystem: eco, Name: name, Version: version, PURL: purl}, true
}

// FromCycloneDX extracts the components of a CycloneDX JSON SBOM
// (de-duplicated, sorted).
func FromCycloneDX(data []byte) ([]Component, error) {
	var doc struct {
		Components []cdxComponent `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []Component
	var walk func([]cdxComponent)
	walk = func(cs []cdxComponent) {
		for _, c := range cs {
			if c.PURL != "" && !seen[c.PURL] {
				if comp, ok := ParsePURL(c.PURL); ok {
					seen[c.PURL] = true
					comp.Licenses = c.licenses()
					out = append(out, comp)
				}
			}
			walk(c.Components)
		}
	}
	walk(doc.Components)
	sort.Slice(out, func(i, j int) bool { return out[i].PURL < out[j].PURL })
	return out, nil
}

type cdxComponent struct {
	PURL     string `json:"purl"`
	Licenses []struct {
		License struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"license"`
		Expression string `json:"expression"`
	} `json:"licenses"`
	Components []cdxComponent `json:"components"`
}

func (c cdxComponent) licenses() []string {
	var out []string
	for _, l := range c.Licenses {
		switch {
		case l.License.ID != "":
			out = append(out, l.License.ID)
		case l.License.Name != "":
			out = append(out, l.License.Name)
		case l.Expression != "":
			out = append(out, l.Expression)
		}
	}
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}
