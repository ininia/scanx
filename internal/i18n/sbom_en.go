package i18n

// SBOM inventory and continuous vulnerability monitoring.
var enSBOM = map[string]string{
	"nav.sbom":               "SBOM & CVE",
	"sbom.title":             "SBOM & CVE monitoring",
	"sbom.subtitle":          "An inventory of every package your projects use; newly published vulnerabilities are checked daily without rescanning code.",
	"sbom.export_inventory":  "Download inventory (CSV)",
	"sbom.export_vulns":      "Download vulnerabilities (CSV)",
	"sbom.check_now":         "Check now",
	"sbom.running":           "Updating the vulnerability database and checking the inventory…",
	"sbom.components":        "Components",
	"sbom.packages_projects": "%d packages · %d projects",
	"sbom.open":              "Open vulnerabilities",
	"sbom.crit_high":         "%d critical · %d high",
	"sbom.resolved30":        "Resolved in 30 days",
	"sbom.last_run":          "Last check",
	"sbom.advisories":        "%d advisories checked",
	"sbom.tab.vulns":         "Vulnerabilities",
	"sbom.tab.components":    "Components",
	"sbom.tab.licenses":      "Licenses",
	"sbom.tab.resolved":      "Resolved",
	"sbom.search":            "Search packages (e.g. log4j, lodash)…",
	"sbom.run_log":           "Log of the last check",
	"sbom.no_vulns":          "No known vulnerability affects the packages in the inventory.",
	"sbom.advisory":          "Advisory",
	"sbom.package":           "Package",
	"sbom.version":           "Version",
	"sbom.fixed":             "Fixed in",
	"sbom.no_fix":            "none yet",
	"sbom.first_seen":        "First seen",
	"sbom.top_hint":          "The packages used by the most projects. Click one to see which projects use which version.",
	"sbom.ecosystem":         "Ecosystem",
	"sbom.projects":          "Projects",
	"sbom.versions":          "Versions",
	"sbom.license":           "License",
	"sbom.license_hint":      "Licenses of the dependencies. Strong copyleft licenses (GPL, AGPL…) can require sharing source code when the software is distributed.",
	"sbom.copyleft":          "copyleft",
	"sbom.none_resolved":     "Nothing resolved in the last 30 days.",
	"sbom.resolved_at":       "Resolved",
	"sbom.notify.project":    "Dependency vulnerabilities",
	"sbom.notify.branch":     "%d projects",
	"sbom.notify.note":       "%d new vulnerabilities were published for packages you use.",

	"event.sbom.vuln":     "New vulnerability in a used package",
	"module.sbom":         "SBOM & CVE monitoring",
	"module.sbom.desc":    "Dependency inventory, licenses and daily tracking of new vulnerabilities (fed by repository scans).",
	"module.sbom.max":     "Maximum (unused)",
	"flash.sbom_checking": "Check queued.",
}

func init() {
	for k, v := range enSBOM {
		en[k] = v
	}
}
