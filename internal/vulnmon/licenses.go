package vulnmon

import "strings"

// License classes, from the fewest to the most obligations.
const (
	LicPublic     = "public"     // public domain dedications
	LicPermissive = "permissive" // keep the notice (MIT, Apache, BSD…)
	LicWeak       = "weak"       // file/library-level copyleft (LGPL, MPL, EPL…)
	LicUnknown    = "unknown"    // no or unrecognised license
	LicStrong     = "strong"     // whole-program copyleft (GPL…)
	LicNetwork    = "network"    // copyleft that also covers network use (AGPL…)
	LicRestricted = "restricted" // not open source: non-commercial, source-available
)

var classRank = map[string]int{
	LicPublic: 0, LicPermissive: 1, LicWeak: 2, LicUnknown: 3, LicStrong: 4, LicNetwork: 5, LicRestricted: 6,
}

// RiskyLicense flags licenses whose obligations need a legal review before
// the software is shipped (strong/network copyleft, non-open-source).
func RiskyLicense(l string) bool {
	return classRank[LicenseClass(l)] >= classRank[LicStrong]
}

// LicenseClass classifies an SPDX id or expression. For "A OR B" the user
// may pick the friendlier license; for "A AND B" both apply.
func LicenseClass(l string) string {
	return licenseFamily(l).class
}

// LicenseFamily returns a stable key for well-known license families
// ("mit", "apache", "gpl3"…) or "" when there is no specific description.
func LicenseFamily(l string) string {
	return licenseFamily(l).key
}

type family struct{ key, class string }

func licenseFamily(l string) family {
	l = strings.TrimSpace(strings.Trim(strings.TrimSpace(l), "()"))
	u := strings.ToUpper(l)
	if parts := splitExpr(u, " OR "); len(parts) > 1 {
		best := family{class: LicRestricted}
		for _, p := range parts {
			if f := licenseFamily(p); classRank[f.class] < classRank[best.class] {
				best = f
			}
		}
		return best
	}
	if parts := splitExpr(u, " AND "); len(parts) > 1 {
		worst := family{class: LicPublic}
		for _, p := range parts {
			if f := licenseFamily(p); classRank[f.class] >= classRank[worst.class] {
				worst = f
			}
		}
		return worst
	}
	u, _, _ = strings.Cut(u, " WITH ") // exceptions only relax the license
	return single(strings.TrimSpace(u))
}

func splitExpr(u, op string) []string {
	if !strings.Contains(u, op) {
		return nil
	}
	return strings.Split(u, op)
}

func single(u string) family {
	has := func(s ...string) bool {
		for _, x := range s {
			if strings.HasPrefix(u, x) {
				return true
			}
		}
		return false
	}
	switch {
	case u == "" || u == "(UNKNOWN)" || u == "UNKNOWN" || u == "NOASSERTION" || u == "NONE" ||
		has("HTTP://", "HTTPS://", "LICENSEREF-", "SEE LICENSE"):
		return family{"unknown", LicUnknown}
	case has("UNLICENSE"):
		return family{"unlicense", LicPublic}
	case has("CC0"):
		return family{"cc0", LicPublic}
	case u == "0BSD" || has("WTFPL", "PUBLIC DOMAIN", "PUBLIC-DOMAIN"):
		return family{"cc0", LicPublic}
	case has("AGPL"):
		return family{"agpl", LicNetwork}
	case has("SSPL"):
		return family{"sspl", LicRestricted}
	case has("BUSL", "ELASTIC-", "COMMONS-CLAUSE", "POLYFORM-NONCOMMERCIAL"):
		return family{"busl", LicRestricted}
	case has("CC-BY-NC"):
		return family{"ccbync", LicRestricted}
	case has("LGPL"):
		return family{"lgpl", LicWeak}
	case has("GPL-2", "GPL2", "GPLV2"):
		return family{"gpl2", LicStrong}
	case has("GPL"):
		return family{"gpl3", LicStrong}
	case has("EUPL"):
		return family{"eupl", LicStrong}
	case has("OSL-"):
		return family{"", LicNetwork}
	case has("CC-BY-SA", "ODBL"):
		return family{"ccbysa", LicStrong}
	case has("MPL"):
		return family{"mpl", LicWeak}
	case has("EPL", "CPL-"):
		return family{"epl", LicWeak}
	case has("CDDL"):
		return family{"cddl", LicWeak}
	case has("MS-RL", "APSL", "CECILL-C", "CPAL"):
		return family{"", LicWeak}
	case has("APACHE"):
		return family{"apache", LicPermissive}
	case has("MIT", "X11", "EXPAT"):
		return family{"mit", LicPermissive}
	case has("BSD"):
		return family{"bsd", LicPermissive}
	case has("ISC"):
		return family{"isc", LicPermissive}
	case has("CC-BY"):
		return family{"ccby", LicPermissive}
	case has("ZLIB", "BSL-1.0", "BOOST", "PSF", "PYTHON", "UNICODE", "MS-PL", "POSTGRESQL", "ARTISTIC-2",
		"BLUEOAK", "NCSA", "OFL", "UPL", "W3C", "CURL", "OPENSSL"):
		return family{"", LicPermissive}
	}
	return family{"", LicUnknown}
}
