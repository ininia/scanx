package ui

import (
	"github.com/ininia/scanx/internal/i18n"
	"github.com/ininia/scanx/internal/vulnmon"
)

// LicClass is the obligation class of a license (see vulnmon.LicenseClass).
func LicClass(l string) string { return vulnmon.LicenseClass(l) }

// LicBadge is the badge colour for a license class.
func LicBadge(class string) string {
	switch class {
	case vulnmon.LicPublic, vulnmon.LicPermissive:
		return "sbadge ok"
	case vulnmon.LicWeak:
		return "sbadge run"
	case vulnmon.LicUnknown:
		return "sbadge warn"
	}
	return "sbadge bad"
}

// LicInfo describes a well-known license family ("" if none).
func (p *Page) LicInfo(l string) string {
	if k := vulnmon.LicenseFamily(l); k != "" {
		return p.T("sbom.licinfo." + k)
	}
	return ""
}

// EcoInfo explains a package ecosystem ("" if unknown).
func (p *Page) EcoInfo(eco string) string {
	if k := "sbom.eco." + eco; i18n.Has(k) {
		return p.T(k)
	}
	return ""
}
