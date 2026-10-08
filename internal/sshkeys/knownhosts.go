package sshkeys

import "strings"

// KnownHosts returns the known_hosts content for host: the pinned key of a
// well-known service, or the matching lines of extra (operator-supplied
// known_hosts for self-hosted Git servers, SCANX_SSH_KNOWN_HOSTS). It
// returns "" when nothing is trusted for host; the connection is then
// refused, because trust-on-first-use would let a network attacker
// impersonate the Git server.
func KnownHosts(host, extra string) string {
	host = strings.ToLower(host)
	var b strings.Builder
	if k, ok := knownHosts[host]; ok {
		b.WriteString(host + " " + k + "\n")
	}
	for _, line := range strings.Split(extra, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		for _, h := range strings.Split(strings.ToLower(f[0]), ",") {
			if h == host || h == "["+host+"]" || strings.HasPrefix(h, "["+host+"]:") {
				b.WriteString(line + "\n")
				break
			}
		}
	}
	return b.String()
}
