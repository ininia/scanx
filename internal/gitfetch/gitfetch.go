// Package gitfetch implements `scanx git-fetch`: it runs inside the scanner
// image, in a throw-away container that has network access but no source
// mounted other than the scan's empty work volume. It clones one branch with
// the project's deploy key, verifying the server against pinned host keys,
// and prints a JSON result on stdout. The worker never runs git itself.
package gitfetch

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/gitutil"
)

// Modes.
const (
	ModeClone     = "clone"
	ModeLsRemote  = "ls-remote"
	resultPrefix  = "SCANX_RESULT "
	defaultMaxMB  = 2048
	keyFileName   = "deploy_key"
	knownHostFile = "known_hosts"
)

// Request is read from the environment (never from argv, so the key does not
// appear in process listings).
type Request struct {
	Mode       string // clone | ls-remote
	RepoURL    string
	Branch     string
	Commit     string // optional: exact commit to check out
	BaseCommit string // optional: diff base; the changed files are listed
	SSHKey     []byte // OpenSSH private key (may be empty for public https repos)
	KnownHosts string
	Dest       string
	Depth      int // 0 = full history
	MaxMB      int
}

// Result is printed as one JSON line prefixed with SCANX_RESULT.
type Result struct {
	OK       bool     `json:"ok"`
	Error    string   `json:"error,omitempty"`
	Code     string   `json:"code,omitempty"` // auth | host_key | not_found | too_large | timeout | git
	Commit   string   `json:"commit,omitempty"`
	Message  string   `json:"message,omitempty"`
	Author   string   `json:"author,omitempty"`
	SizeMB   int      `json:"size_mb,omitempty"`
	Branches []string `json:"branches,omitempty"`
	Default  string   `json:"default_branch,omitempty"`
	Diff     *Diff    `json:"diff,omitempty"`
}

// MaxDiffFiles is the largest incremental scan; bigger pushes are scanned in
// full (a diff gains nothing).
const MaxDiffFiles = 2000

// Diff lists the files changed between BaseCommit and the checkout. The
// added/modified paths are also written to ChangedListFile (one per line)
// next to the checkout for the scan step.
type Diff struct {
	OK      bool     `json:"ok"`
	Reason  string   `json:"reason,omitempty"` // why a full scan is needed
	Base    string   `json:"base,omitempty"`
	Changed []string `json:"changed,omitempty"` // added, copied, modified
	Deleted []string `json:"deleted,omitempty"`
}

// ChangedListFile is written next to the checkout (…/work/changed.txt).
const ChangedListFile = "changed.txt"

// FromEnv builds a Request from SCANX_* variables.
func FromEnv(getenv func(string) string) (*Request, error) {
	r := &Request{
		Mode: getenv("SCANX_FETCH_MODE"), RepoURL: getenv("SCANX_REPO_URL"), Branch: getenv("SCANX_BRANCH"),
		Commit: getenv("SCANX_COMMIT"), BaseCommit: getenv("SCANX_BASE_COMMIT"), KnownHosts: getenv("SCANX_KNOWN_HOSTS"), Dest: getenv("SCANX_DEST"),
		MaxMB: defaultMaxMB,
	}
	if r.Mode == "" {
		r.Mode = ModeClone
	}
	if r.Dest == "" {
		r.Dest = "/work/src"
	}
	if k := getenv("SCANX_SSH_KEY"); k != "" {
		b, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			return nil, errors.New("SCANX_SSH_KEY must be base64")
		}
		r.SSHKey = b
	}
	if v := getenv("SCANX_FETCH_DEPTH"); v != "" {
		d, err := strconv.Atoi(v)
		if err != nil || d < 0 {
			return nil, errors.New("SCANX_FETCH_DEPTH must be a non-negative integer")
		}
		r.Depth = d
	}
	if v := getenv("SCANX_MAX_REPO_MB"); v != "" {
		m, err := strconv.Atoi(v)
		if err != nil || m < 1 {
			return nil, errors.New("SCANX_MAX_REPO_MB must be a positive integer")
		}
		r.MaxMB = m
	}
	return r, r.validate()
}

var (
	shaRe    = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	branchRe = regexp.MustCompile(`^[A-Za-z0-9._/@+-]{1,200}$`)
)

func (r *Request) validate() error {
	if r.Mode != ModeClone && r.Mode != ModeLsRemote {
		return fmt.Errorf("unknown mode %q", r.Mode)
	}
	if _, err := gitutil.ParseRepoURL(r.RepoURL); err != nil {
		return err
	}
	if r.Mode == ModeClone {
		if !ValidBranch(r.Branch) {
			return errors.New("invalid branch")
		}
		if r.Commit != "" && !shaRe.MatchString(r.Commit) {
			return errors.New("invalid commit")
		}
		if r.BaseCommit != "" && !shaRe.MatchString(r.BaseCommit) {
			return errors.New("invalid base commit")
		}
	}
	return nil
}

// ValidBranch reports whether b is a safe branch name (no option injection,
// no ref traversal).
func ValidBranch(b string) bool {
	return branchRe.MatchString(b) && !strings.HasPrefix(b, "-") && !strings.Contains(b, "..") &&
		!strings.HasPrefix(b, "/") && !strings.HasSuffix(b, "/") && !strings.HasSuffix(b, ".lock")
}

// Run executes the request. tmp is a private writable directory (tmpfs).
func Run(ctx context.Context, r *Request, tmp string, stderr io.Writer) *Result {
	repo, _ := gitutil.ParseRepoURL(r.RepoURL)
	env, err := gitEnv(r, repo, tmp)
	if err != nil {
		return fail("git", err.Error())
	}
	g := &git{env: env, stderr: stderr}
	if r.Mode == ModeLsRemote {
		return g.lsRemote(ctx, r.RepoURL)
	}
	return g.clone(ctx, r)
}

// gitEnv writes the key and known_hosts into tmp and returns git's
// environment. Repository-controlled configuration (hooks, fsmonitor,
// file/ext protocols, submodules) is disabled.
func gitEnv(r *Request, repo *gitutil.RepoURL, tmp string) ([]string, error) {
	env := []string{
		"HOME=" + tmp, "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8",
		"GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_ASKPASS=/bin/false", "SSH_ASKPASS=/bin/false", "GIT_LFS_SKIP_SMUDGE=1",
		"GIT_PROTOCOL_FROM_USER=0", "GIT_ALLOW_PROTOCOL=https:ssh",
	}
	if repo.Scheme == "ssh" {
		if len(r.SSHKey) == 0 {
			return nil, errors.New("no deploy key for an SSH repository")
		}
		if strings.TrimSpace(r.KnownHosts) == "" {
			return nil, fmt.Errorf("host %s is not trusted: no pinned SSH host key (set SCANX_SSH_KNOWN_HOSTS)", repo.Host)
		}
		key := filepath.Join(tmp, keyFileName)
		kh := filepath.Join(tmp, knownHostFile)
		if err := os.WriteFile(key, append(bytes.TrimSpace(r.SSHKey), '\n'), 0o600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(kh, []byte(r.KnownHosts), 0o600); err != nil {
			return nil, err
		}
		env = append(env, "GIT_SSH_COMMAND=ssh -F /dev/null -i "+key+" -o IdentitiesOnly=yes -o IdentityAgent=none"+
			" -o UserKnownHostsFile="+kh+" -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes"+
			" -o BatchMode=yes -o ConnectTimeout=20 -o ServerAliveInterval=15 -o ServerAliveCountMax=4"+
			" -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no")
	}
	return env, nil
}

type git struct {
	env    []string
	stderr io.Writer
	dir    string
}

var safeConfig = []string{
	"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.symlinks=false",
	"-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never", "-c", "submodule.recurse=false",
	"-c", "credential.helper=", "-c", "http.followRedirects=false", "-c", "advice.detachedHead=false",
	"-c", "init.defaultBranch=main", "-c", "safe.directory=*",
}

func (g *git) run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append(append([]string{}, safeConfig...), args...)...) //nolint:gosec // fixed binary, argument array
	cmd.Env = g.env
	cmd.Dir = g.dir
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.MultiWriter(&errb, g.stderr)
	if err := cmd.Run(); err != nil {
		return out.String(), &gitError{msg: strings.TrimSpace(errb.String()), err: err}
	}
	return out.String(), nil
}

type gitError struct {
	msg string
	err error
}

func (e *gitError) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return e.err.Error()
}

// classify maps git/ssh error output to a stable code for the UI.
func classify(err error) *Result {
	if errors.Is(err, context.DeadlineExceeded) {
		return fail("timeout", "git operation timed out")
	}
	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "host key verification failed"), strings.Contains(low, "remote host identification has changed"),
		strings.Contains(low, "no matching host key"):
		return fail("host_key", lastLines(msg, 3))
	case strings.Contains(low, "permission denied"), strings.Contains(low, "authentication failed"),
		strings.Contains(low, "could not read username"), strings.Contains(low, "access denied"):
		return fail("auth", lastLines(msg, 3))
	case strings.Contains(low, "couldn't find remote ref"), strings.Contains(low, "repository not found"),
		strings.Contains(low, "not found"), strings.Contains(low, "does not appear to be a git repository"):
		return fail("not_found", lastLines(msg, 3))
	default:
		return fail("git", lastLines(msg, 5))
	}
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := strings.Join(lines, "\n")
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out
}

func fail(code, msg string) *Result { return &Result{OK: false, Code: code, Error: msg} }

func (g *git) lsRemote(ctx context.Context, url string) *Result {
	out, err := g.run(ctx, "ls-remote", "--symref", "--heads", "--", url, "HEAD")
	if err != nil {
		// --symref HEAD may be rejected by old servers; retry heads only.
		out, err = g.run(ctx, "ls-remote", "--heads", "--", url)
		if err != nil {
			return classify(err)
		}
	}
	res := &Result{OK: true}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) == 3 && f[0] == "ref:" && f[2] == "HEAD":
			res.Default = strings.TrimPrefix(f[1], "refs/heads/")
		case len(f) == 2 && strings.HasPrefix(f[1], "refs/heads/"):
			res.Branches = append(res.Branches, strings.TrimPrefix(f[1], "refs/heads/"))
		}
	}
	sort.Strings(res.Branches)
	if len(res.Branches) > 500 {
		res.Branches = res.Branches[:500]
	}
	return res
}

func (g *git) clone(ctx context.Context, r *Request) *Result {
	if err := os.MkdirAll(r.Dest, 0o750); err != nil {
		return fail("git", err.Error())
	}
	if entries, _ := os.ReadDir(r.Dest); len(entries) > 0 {
		return fail("git", "destination is not empty")
	}
	g.dir = r.Dest
	if _, err := g.run(ctx, "init", "-q", "."); err != nil {
		return classify(err)
	}
	if _, err := g.run(ctx, "remote", "add", "origin", "--", r.RepoURL); err != nil {
		return classify(err)
	}
	fetch := []string{"fetch", "-q", "--no-tags", "--no-recurse-submodules", "--prune"}
	if r.Depth > 0 {
		fetch = append(fetch, "--depth", strconv.Itoa(r.Depth))
	}
	ref := "+refs/heads/" + r.Branch + ":refs/remotes/origin/" + r.Branch
	if _, err := g.run(ctx, append(fetch, "origin", ref)...); err != nil {
		return classify(err)
	}
	target := "refs/remotes/origin/" + r.Branch
	if r.Commit != "" {
		// The pushed commit must be on the fetched branch (it may already be
		// behind the tip if more pushes followed; that is fine).
		if _, err := g.run(ctx, "cat-file", "-e", r.Commit+"^{commit}"); err != nil {
			return fail("not_found", "commit "+r.Commit+" not found on branch "+r.Branch)
		}
		target = r.Commit
	}
	if _, err := g.run(ctx, "checkout", "-q", "--detach", target); err != nil {
		return classify(err)
	}
	size, err := dirSizeMB(r.Dest)
	if err != nil {
		return fail("git", err.Error())
	}
	if size > r.MaxMB {
		return &Result{
			OK: false, Code: "too_large", SizeMB: size,
			Error: fmt.Sprintf("repository is %d MB, limit is %d MB (SCANX_MAX_REPO_MB)", size, r.MaxMB),
		}
	}
	out, err := g.run(ctx, "log", "-1", "--format=%H%x00%an <%ae>%x00%s", "HEAD")
	if err != nil {
		return classify(err)
	}
	parts := strings.SplitN(strings.TrimRight(out, "\n"), "\x00", 3)
	res := &Result{OK: true, SizeMB: size}
	if len(parts) == 3 {
		res.Commit, res.Author, res.Message = parts[0], truncate(parts[1], 200), truncate(parts[2], 500)
	}
	if r.BaseCommit != "" {
		res.Diff = g.diff(ctx, r)
	}
	return res
}

// diff lists the files changed since r.BaseCommit. Any problem (force push,
// unknown base, huge push) yields OK=false and the caller scans everything.
func (g *git) diff(ctx context.Context, r *Request) *Diff {
	d := &Diff{Base: r.BaseCommit}
	if _, err := g.run(ctx, "cat-file", "-e", r.BaseCommit+"^{commit}"); err != nil {
		// Shallow clones may miss the base: fetch just that commit.
		if _, err := g.run(ctx, "fetch", "-q", "--no-tags", "--depth", "1", "origin", r.BaseCommit); err != nil {
			d.Reason = "base commit not found (force push or first push)"
			return d
		}
	}
	list := func(filter string) ([]string, error) {
		out, err := g.run(ctx, "diff", "--name-only", "-z", "--no-renames", "--diff-filter="+filter, r.BaseCommit, "HEAD", "--")
		if err != nil {
			return nil, err
		}
		var files []string
		for _, f := range strings.Split(out, "\x00") {
			if f != "" {
				files = append(files, f)
			}
		}
		return files, nil
	}
	var err error
	if d.Changed, err = list("ACMT"); err != nil {
		d.Reason = "git diff failed"
		return d
	}
	if d.Deleted, err = list("D"); err != nil {
		d.Reason = "git diff failed"
		return d
	}
	if len(d.Changed)+len(d.Deleted) > MaxDiffFiles {
		d.Changed, d.Deleted = nil, nil
		d.Reason = fmt.Sprintf("more than %d files changed", MaxDiffFiles)
		return d
	}
	listFile := filepath.Join(filepath.Dir(r.Dest), ChangedListFile)
	if err := os.WriteFile(listFile, []byte(strings.Join(d.Changed, "\n")), 0o640); err != nil { //nolint:gosec // inside the scan volume
		d.Reason = "cannot write the changed-file list"
		return d
	}
	d.OK = true
	return d
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func dirSizeMB(dir string) (int, error) {
	var total int64
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			total += info.Size()
		}
		return nil
	})
	return int((total + (1<<20 - 1)) >> 20), err
}

// Main is the `scanx git-fetch` entry point. The result is always printed
// (even on failure) so the worker can show a precise reason. Exit code: 0
// success, 1 git failure, 3 bad request.
func Main(ctx context.Context, stdout, stderr io.Writer) int {
	req, err := FromEnv(os.Getenv)
	if err != nil {
		writeResult(stdout, fail("request", err.Error()))
		return 3
	}
	tmp, err := os.MkdirTemp("", "scanx-git-")
	if err != nil {
		writeResult(stdout, fail("git", err.Error()))
		return 1
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	res := Run(ctx, req, tmp, stderr)
	writeResult(stdout, res)
	if !res.OK {
		return 1
	}
	return 0
}

func writeResult(w io.Writer, r *Result) {
	b, _ := json.Marshal(r)
	fmt.Fprintf(w, "%s%s\n", resultPrefix, b)
}

// ParseResult extracts the result line from the container's stdout.
func ParseResult(stdout []byte) (*Result, error) {
	lines := strings.Split(string(stdout), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(lines[i]), resultPrefix); ok {
			var r Result
			if err := json.Unmarshal([]byte(rest), &r); err != nil {
				return nil, fmt.Errorf("git-fetch result: %w", err)
			}
			return &r, nil
		}
	}
	return nil, errors.New("git-fetch produced no result")
}
