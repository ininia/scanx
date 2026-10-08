// Package worker executes queued jobs: repository scans and connection
// tests. Each scan runs in two throw-away containers sharing one volume:
//
//  1. git-fetch — has network (egress-only bridge), clones one branch with
//     the project's deploy key, verifies the host key;
//  2. scan — no network at all, runs every scanner on the checkout.
//
// The worker then copies the reports out, stores issues and reports, deletes
// the containers and the volume (the source code never outlives the scan)
// and sends notifications (spec §4.2, §5.2).
package worker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ininia/scanx/internal/crypto"
	"github.com/ininia/scanx/internal/gitfetch"
	"github.com/ininia/scanx/internal/gitutil"
	"github.com/ininia/scanx/internal/notify"
	"github.com/ininia/scanx/internal/sandbox"
	"github.com/ininia/scanx/internal/service"
	"github.com/ininia/scanx/internal/sshkeys"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
)

// Config tunes the worker.
type Config struct {
	Image                string
	EgressNetwork        string
	KnownHostsExtra      string
	Concurrency          int
	ScanTimeout          time.Duration
	FetchTimeout         time.Duration
	MemoryBytes          int64
	NanoCPUs             int64
	MaxRepoMB            int
	CloneDepth           int
	Runtime              string
	Profile              string
	Parallelism          int
	AllowPrivateGitHosts bool
	BaseURL              string
	PollInterval         time.Duration
}

// Worker claims and runs jobs.
type Worker struct {
	db       *store.DB
	box      *crypto.Box
	docker   *sandbox.Client
	notifier *notify.Sender
	cfg      Config
	log      *slog.Logger
	id       string
	resolver func(ctx context.Context, host string) ([]net.IP, error)
}

// New creates a worker.
func New(d *store.DB, box *crypto.Box, docker *sandbox.Client, n *notify.Sender, cfg Config, log *slog.Logger) *Worker {
	host, _ := os.Hostname()
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 2 * time.Second
	}
	if cfg.FetchTimeout == 0 {
		cfg.FetchTimeout = 15 * time.Minute
	}
	return &Worker{
		db: d, box: box, docker: docker, notifier: n, cfg: cfg, log: log,
		id: host + "-" + uuid.NewString()[:8],
		resolver: func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		},
	}
}

var superadmin = store.Scope{Superadmin: true}

// Run processes jobs until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	if err := w.waitForDocker(ctx); err != nil {
		return err
	}
	if ok, err := w.docker.ImageExists(ctx, w.cfg.Image); err != nil || !ok {
		w.log.Warn("scanner image not found locally; scans will fail until it is built",
			"image", w.cfg.Image, "hint", "./deploy/quickstart.sh builds it")
	}
	if err := w.docker.EnsureNetwork(ctx, w.cfg.EgressNetwork, map[string]string{"scanx.network": "egress"}); err != nil {
		return fmt.Errorf("egress network: %w", err)
	}
	w.reap(ctx, 0)
	go w.housekeeping(ctx)

	var wg sync.WaitGroup
	for i := 0; i < w.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.loop(ctx)
		}()
	}
	w.log.Info("worker started", "id", w.id, "concurrency", w.cfg.Concurrency, "image", w.cfg.Image)
	wg.Wait()
	return nil
}

func (w *Worker) waitForDocker(ctx context.Context) error {
	for i := 0; ; i++ {
		err := w.docker.Ping(ctx)
		if err == nil {
			return nil
		}
		if i%15 == 0 {
			w.log.Warn("waiting for the Docker API", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func (w *Worker) loop(ctx context.Context) {
	for {
		job, err := w.claim(ctx)
		if err != nil && ctx.Err() == nil {
			w.log.Error("claim job", "err", err)
		}
		if job == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(w.cfg.PollInterval):
				continue
			}
		}
		w.process(ctx, job)
	}
}

const lockFor = 2 * time.Minute

func (w *Worker) claim(ctx context.Context) (*db.Job, error) {
	var job *db.Job
	err := w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		until := time.Now().Add(lockFor)
		j, err := q.ClaimJob(ctx, db.ClaimJobParams{Worker: w.id, LockedUntil: &until})
		if err != nil {
			return store.NotFound(err)
		}
		job = &j
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return job, err
}

func (w *Worker) process(ctx context.Context, job *db.Job) {
	log := w.log.With("job", job.ID, "kind", job.Kind, "attempt", job.Attempts)
	hbCtx, stopHB := context.WithCancel(ctx)
	go w.heartbeat(hbCtx, job.ID)
	defer stopHB()

	var result any
	var err error
	switch job.Kind {
	case service.JobTestConnection:
		result, err = w.testConnection(ctx, job)
	case service.JobScan:
		err = w.runScan(ctx, job, log)
	default:
		err = fmt.Errorf("unknown job kind %q", job.Kind)
	}
	if ctx.Err() != nil {
		// Shutting down: leave the job locked; it is retried after the lock
		// expires.
		return
	}
	status, msg := "done", ""
	if err != nil {
		status, msg = "failed", err.Error()
		log.Warn("job failed", "err", err)
	}
	raw := json.RawMessage(`{}`)
	if result != nil {
		if b, mErr := json.Marshal(result); mErr == nil {
			raw = b
		}
	}
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := w.db.Tx(fctx, superadmin, func(q *db.Queries) error {
		return q.FinishJob(fctx, db.FinishJobParams{ID: job.ID, Status: status, Result: raw, Error: trunc(msg, 2000)})
	}); err != nil {
		log.Error("finish job", "err", err)
	}
}

func (w *Worker) heartbeat(ctx context.Context, id uuid.UUID) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			until := time.Now().Add(lockFor)
			_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
				return q.ExtendJobLock(ctx, db.ExtendJobLockParams{ID: id, LockedUntil: &until})
			})
		}
	}
}

// housekeeping fails jobs abandoned by dead workers and removes leftover
// sandbox resources and retired deploy keys.
func (w *Worker) housekeeping(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
			stale, err := q.FailStaleJobs(ctx)
			if err != nil {
				return err
			}
			for _, j := range stale {
				if j.ScanID != nil {
					_ = q.FinishScan(ctx, db.FinishScanParams{
						ID: *j.ScanID, Status: "failed",
						StatusReason: "The worker stopped responding during this scan.", Summary: json.RawMessage(`{"failure_code":"worker_lost"}`),
					})
				}
			}
			_, err = q.DeleteOldSSHKeys(ctx)
			return err
		})
		w.reap(ctx, w.cfg.ScanTimeout+w.cfg.FetchTimeout+10*time.Minute)
	}
}

// reap removes sandbox containers/volumes older than age (0 = all; used at
// startup when no scan of this host can still be running).
func (w *Worker) reap(ctx context.Context, age time.Duration) {
	cutoff := time.Now().Add(-age)
	if cs, err := w.docker.ListContainers(ctx, "scanx.scan"); err == nil {
		for _, c := range cs {
			if age == 0 || c.Created.Before(cutoff) {
				_ = w.docker.RemoveContainer(ctx, c.ID)
			}
		}
	}
	if vs, err := w.docker.ListVolumes(ctx, "scanx.scan"); err == nil {
		for _, v := range vs {
			if age == 0 || v.Created.Before(cutoff) {
				_ = w.docker.RemoveVolume(ctx, v.ID)
			}
		}
	}
}

// ---------- fetch step ----------

// fetchError is a clone failure with a user-facing reason.
type fetchError struct {
	code string
	msg  string
}

func (e *fetchError) Error() string { return e.msg }

// fetchEnv prepares git-fetch's environment for a project.
func (w *Worker) fetchEnv(ctx context.Context, p *db.Project, mode string) ([]string, error) {
	repo, err := gitutil.ParseRepoURL(p.RepoUrl)
	if err != nil {
		return nil, &fetchError{code: "request", msg: "The repository URL is invalid."}
	}
	if err := w.checkHost(ctx, repo.Host); err != nil {
		return nil, err
	}
	env := []string{
		"SCANX_FETCH_MODE=" + mode, "SCANX_REPO_URL=" + p.RepoUrl, "SCANX_DEST=/work/src",
		"SCANX_MAX_REPO_MB=" + strconv.Itoa(w.cfg.MaxRepoMB), "SCANX_FETCH_DEPTH=" + strconv.Itoa(w.cfg.CloneDepth),
	}
	if repo.Scheme == "ssh" {
		kh := sshkeys.KnownHosts(repo.Host, w.cfg.KnownHostsExtra)
		if kh == "" {
			return nil, &fetchError{code: "host_key", msg: fmt.Sprintf(
				"scanX does not know the SSH host key of %s. Add it to SCANX_SSH_KNOWN_HOSTS (ssh-keyscan %s) and restart.",
				repo.Host, repo.Host)}
		}
		key, err := w.deployKey(ctx, p)
		if err != nil {
			return nil, err
		}
		env = append(env, "SCANX_KNOWN_HOSTS="+kh, "SCANX_SSH_KEY="+base64.StdEncoding.EncodeToString(key))
	}
	return env, nil
}

func (w *Worker) deployKey(ctx context.Context, p *db.Project) ([]byte, error) {
	var k db.SshKey
	err := w.db.Tx(ctx, store.Scope{OrgID: p.OrgID}, func(q *db.Queries) error {
		var err error
		k, err = q.GetActiveSSHKey(ctx, db.GetActiveSSHKeyParams{OrgID: p.OrgID, ProjectID: p.ID})
		return store.NotFound(err)
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, &fetchError{code: "auth", msg: "This project has no deploy key yet. Open the project page once to create it."}
	}
	if err != nil {
		return nil, err
	}
	pem, err := w.box.Open(k.PrivateKeyEnc, k.Nonce, service.DeployKeyAAD(p.ID))
	if err != nil {
		return nil, fmt.Errorf("decrypt deploy key: %w", err)
	}
	return pem, nil
}

// checkHost refuses Git servers on private networks unless allowed (SSRF:
// a project URL must not let users reach internal services).
func (w *Worker) checkHost(ctx context.Context, host string) error {
	if w.cfg.AllowPrivateGitHosts {
		return nil
	}
	ips, err := w.resolver(ctx, host)
	if err != nil || len(ips) == 0 {
		return &fetchError{code: "not_found", msg: fmt.Sprintf("Cannot resolve the Git server %s.", host)}
	}
	for _, ip := range ips {
		if !notify.PublicIP(ip) {
			return &fetchError{code: "private_host", msg: fmt.Sprintf(
				"%s resolves to a private address. To scan repositories on an internal Git server set SCANX_ALLOW_PRIVATE_GIT_HOSTS=true.", host)}
		}
	}
	return nil
}

func labels(job *db.Job, step string) map[string]string {
	l := map[string]string{"scanx.scan": job.ID.String(), "scanx.org": job.OrgID.String(), "scanx.step": step}
	if job.ScanID != nil {
		l["scanx.scan"] = job.ScanID.String()
	}
	return l
}

// runContainer creates, starts and waits for a sandbox container. The
// container is removed before returning; its output is returned through
// collect (called while it still exists).
func (w *Worker) runContainer(ctx context.Context, spec sandbox.ContainerSpec, collect func(id string) error) (int, []byte, []byte, error) {
	id, err := w.docker.CreateContainer(ctx, spec)
	if err != nil {
		return -1, nil, nil, err
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_ = w.docker.RemoveContainer(rctx, id)
	}()
	if err := w.docker.StartContainer(ctx, id); err != nil {
		return -1, nil, nil, err
	}
	st, err := w.docker.Wait(ctx, id, 2*time.Second)
	if err != nil {
		kctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		_ = w.docker.KillContainer(kctx, id)
		cancel()
		if ctx.Err() != nil {
			return -1, nil, nil, context.Cause(ctx)
		}
		return -1, nil, nil, err
	}
	res := struct {
		code int
		err  error
	}{code: st.ExitCode}
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	stdout, stderr, _ := w.docker.Logs(lctx, id, 1<<20)
	if st.OOMKilled {
		res.err = errOOM
	}
	if res.err == nil && collect != nil {
		res.err = collect(id)
	}
	return res.code, stdout, stderr, res.err
}

var errOOM = errors.New("out of memory")

func (w *Worker) fetchSpec(job *db.Job, env []string, volume string) sandbox.ContainerSpec {
	mounts := []sandbox.Mount{}
	if volume != "" {
		mounts = append(mounts, sandbox.Mount{Type: "volume", Source: volume, Target: "/work"})
	}
	return sandbox.ContainerSpec{
		Image: w.cfg.Image, Cmd: []string{"git-fetch"}, Env: env, User: "65532:65532",
		Labels: labels(job, "fetch"), Mounts: mounts, Network: w.cfg.EgressNetwork,
		Tmpfs:       map[string]string{"/tmp": "rw,noexec,nosuid,size=64m"},
		MemoryBytes: 1 << 30, NanoCPUs: 1e9, PidsLimit: 256, Runtime: w.cfg.Runtime,
	}
}

func (w *Worker) testConnection(ctx context.Context, job *db.Job) (*service.ConnectionResult, error) {
	p, err := w.project(ctx, job.ProjectID)
	if err != nil {
		return nil, err
	}
	env, err := w.fetchEnv(ctx, p, gitfetch.ModeLsRemote)
	var fe *fetchError
	if errors.As(err, &fe) {
		return &service.ConnectionResult{Code: fe.code, Message: fe.msg}, nil
	}
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	_, stdout, stderr, err := w.runContainer(ctx, w.fetchSpec(job, env, ""), nil)
	if err != nil {
		return nil, fmt.Errorf("connection test container: %w", err)
	}
	r, err := gitfetch.ParseResult(stdout)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, tail(stderr, 500))
	}
	return &service.ConnectionResult{OK: r.OK, Code: r.Code, Message: r.Error, Branches: r.Branches, Default: r.Default}, nil
}

// friendlyGitError explains common clone failures to non-developers.
func friendlyGitError(code, raw string) string {
	switch code {
	case "":
		return ""
	case "auth":
		return "The Git server rejected the deploy key. Add the deploy key shown on the project page to the repository " +
			"(GitHub: Settings → Deploy keys) — or, for public repositories, use the https:// URL. Details: " + raw
	case "host_key":
		return "The Git server's SSH host key does not match the pinned key (possible man-in-the-middle). Details: " + raw
	case "not_found":
		return "Repository or branch not found. Check the URL and branch name. Details: " + raw
	case "too_large":
		return raw
	case "timeout":
		return "Cloning took too long and was stopped."
	default:
		return raw
	}
}

func (w *Worker) project(ctx context.Context, id uuid.UUID) (*db.Project, error) {
	var p db.Project
	err := w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		var err error
		p, err = q.GetProjectByID(ctx, id)
		return store.NotFound(err)
	})
	return &p, err
}

func tail(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		s = "…" + s[len(s)-n:]
	}
	return s
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
