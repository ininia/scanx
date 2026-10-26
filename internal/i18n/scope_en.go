package i18n

// Repository scan scope and duration forecast.
var enScope = map[string]string{
	"forecast.estimate":         "Estimated scan time ~%d min (time limit %d min).",
	"forecast.too_long":         "This scan may take ~%d min; the time limit of %d min may not be enough.",
	"forecast.too_long_hint":    "Before time runs out the slowest scanners are stopped and the result is marked partial. Exclude the large folders below, switch off slow scanners or raise the code-analysis time limit.",
	"forecast.coverage":         "Code analysis of the last scan covered %d files (%s); %d files (%s) were left out.",
	"forecast.last.completed":   "the last scan took %d min",
	"forecast.last.partial":     "the last scan took %d min, some scanners did not finish (partial)",
	"forecast.last.timeout":     "the last scan hit the time limit after %d min",
	"forecast.last.failed":      "the last scan failed after %d min",
	"forecast.suggest":          "Folders where code analysis spends the most time; click to exclude:",
	"forecast.exclude_confirm":  "Exclude “%s” from all scanners in future scans?",
	"forecast.exclude_hint":     "Leave this folder out of scans",
	"scope.open":                "Edit scan scope",
	"scope.title":               "Scan scope",
	"scope.help":                "Choose what scans cover. Bundled themes, libraries, minified files and media make code analysis slower without producing findings. Vulnerable dependencies (SCA) and leaked secrets are still searched in the whole repository.",
	"scope.last_skipped":        "Left out of code analysis in the last scan: %d files, %s",
	"scope.last_largest":        "Largest folders code analysis covered: %d files, %s in total",
	"scope.path":                "Path",
	"scope.reason":              "Reason",
	"scope.size":                "Size",
	"scope.files":               "%d files",
	"scope.root_files":          "(files at the repository root)",
	"scope.exclude":             "Exclude",
	"scope.reason.excluded":     "exclude list (vendor, build output, asset files or a path you added)",
	"scope.reason.bundle":       "bundled theme / library folder (detected)",
	"scope.reason.minified":     "minified or bundled JS/CSS",
	"scope.reason.large":        "above the file size limit",
	"scope.all_tools":           "Exclude from all scanners",
	"scope.all_tools_hint":      "Ticked file types are left out of every scanner, secret scanning included.",
	"scope.skip_docs":           "Documents (PDF, Word, Excel, PowerPoint…)",
	"scope.skip_archives":       "Archives (zip, rar, 7z, tar.gz…)",
	"scope.skip_media":          "Images, video and audio",
	"scope.skip_fonts":          "Font files",
	"scope.code_analysis":       "Exclude from code analysis",
	"scope.code_analysis_hint":  "Only affects code analysis and quality tools (opengrep, DevSkim, Psalm, Lizard…).",
	"scope.skip_bundles":        "Detect and skip bundled theme and library folders (SmartAdmin, Metronic, CKEditor…)",
	"scope.skip_minified":       "Skip minified / bundled JS and CSS files",
	"scope.max_file_mb":         "File size limit (MB)",
	"scope.max_file_mb_hint":    "Larger source files are not analysed (usually generated code or data). 0 = no limit.",
	"scope.exclude_paths":       "Paths to exclude",
	"scope.exclude_placeholder": "smartadmin\npublic/assets/plugins\n*.sql",
	"scope.exclude_hint":        "One folder, file or pattern per line. Patterns without “/” match at any level (e.g. *.sql, testdata); with “/” they are paths from the repository root. These paths are not scanned by any scanner.",
	"scope.scanners":            "Scanners that run",
	"scope.scanners_hint":       "Unticked scanners do not run for this project. Estimates are based on the last scan; those above 5 min are highlighted. Scanners irrelevant to the languages and files are skipped automatically anyway.",
	"scope.minutes":             "%d min",
	"flash.scope_invalid":       "The scan scope was not saved: invalid path or value.",
	"flash.scope_excluded":      "The folder is excluded from the next scan on.",
}

func init() {
	for k, v := range enScope {
		en[k] = v
	}
}
