//go:build unix

package engine

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup puts the tool in its own process group so a timeout
// kills every child it spawned (e.g. opengrep → opengrep-core).
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
