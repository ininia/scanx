//go:build !unix

package engine

import "os/exec"

// configureProcessGroup is a no-op where process groups are unavailable;
// exec.CommandContext still kills the direct child on timeout.
func configureProcessGroup(*exec.Cmd) {}
