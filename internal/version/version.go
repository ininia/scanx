// Package version holds build metadata injected via -ldflags.
package version

// These are overridden at build time with -ldflags "-X ...".
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)
