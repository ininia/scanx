// Package sandbox runs scan steps in throw-away, hardened containers through
// the Docker Engine API (spec §5.2, ADR-008). It speaks plain HTTP to the
// engine (normally through a docker-socket-proxy) so no Docker SDK is needed.
package sandbox

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// apiVersion is supported by Docker Engine 24+ (spec minimum).
const apiVersion = "v1.43"

// ErrNotFound is returned for 404 responses.
var ErrNotFound = errors.New("docker: not found")

// Client is a minimal Docker Engine API client.
type Client struct {
	hc   *http.Client
	base string
}

// NewClient connects to host: "unix:///var/run/docker.sock" or
// "tcp://docker-proxy:2375" (DOCKER_HOST syntax).
func NewClient(host string) (*Client, error) {
	if host == "" {
		host = "unix:///var/run/docker.sock"
	}
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("docker host: %w", err)
	}
	tr := &http.Transport{MaxIdleConns: 10, IdleConnTimeout: 30 * time.Second}
	base := ""
	switch u.Scheme {
	case "unix":
		path := u.Path
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}
		base = "http://docker"
	case "tcp", "http":
		base = "http://" + u.Host
	default:
		return nil, fmt.Errorf("docker host: unsupported scheme %q", u.Scheme)
	}
	return &Client{hc: &http.Client{Transport: tr}, base: base + "/" + apiVersion}, nil
}

type apiError struct {
	Message string `json:"message"`
}

func (c *Client) do(ctx context.Context, method, path string, q url.Values, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker %s %s: %w", method, path, err)
	}
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotModified {
		defer func() { _ = resp.Body.Close() }()
		var ae apiError
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = json.Unmarshal(raw, &ae)
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, ae.Message)
		}
		msg := ae.Message
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
		}
		return nil, fmt.Errorf("docker %s %s: %d %s", method, path, resp.StatusCode, msg)
	}
	return resp, nil
}

func (c *Client) json(ctx context.Context, method, path string, q url.Values, body, out any) error {
	resp, err := c.do(ctx, method, path, q, body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Ping checks the engine is reachable.
func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, "/_ping", nil, nil)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// ImageExists reports whether an image is present locally.
func (c *Client) ImageExists(ctx context.Context, ref string) (bool, error) {
	err := c.json(ctx, http.MethodGet, "/images/"+ref+"/json", nil, nil, nil)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// CreateVolume creates a named volume.
func (c *Client) CreateVolume(ctx context.Context, name string, labels map[string]string) error {
	return c.json(ctx, http.MethodPost, "/volumes/create", nil, map[string]any{"Name": name, "Labels": labels}, nil)
}

// RemoveVolume removes a volume (missing is not an error).
func (c *Client) RemoveVolume(ctx context.Context, name string) error {
	err := c.json(ctx, http.MethodDelete, "/volumes/"+url.PathEscape(name), url.Values{"force": {"true"}}, nil, nil)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// EnsureNetwork creates a bridge network if it does not exist.
func (c *Client) EnsureNetwork(ctx context.Context, name string, labels map[string]string) error {
	err := c.json(ctx, http.MethodGet, "/networks/"+url.PathEscape(name), nil, nil, nil)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	return c.json(ctx, http.MethodPost, "/networks/create", nil, map[string]any{
		"Name": name, "Driver": "bridge", "Labels": labels, "CheckDuplicate": true,
		"Options": map[string]string{"com.docker.network.bridge.enable_icc": "false"},
	}, nil)
}

// Mount is a volume or tmpfs mount.
type Mount struct {
	Type         string        `json:"Type"` // volume | tmpfs
	Source       string        `json:"Source,omitempty"`
	Target       string        `json:"Target"`
	ReadOnly     bool          `json:"ReadOnly,omitempty"`
	TmpfsOptions *TmpfsOptions `json:"TmpfsOptions,omitempty"`
}

// TmpfsOptions sizes a tmpfs mount.
type TmpfsOptions struct {
	SizeBytes int64 `json:"SizeBytes,omitempty"`
	Mode      int   `json:"Mode,omitempty"`
}

// ContainerSpec describes a sandbox container. Hardening that is not
// configurable (capabilities, privileges, read-only root) is always applied.
type ContainerSpec struct {
	Name        string
	Image       string
	Cmd         []string
	Env         []string
	User        string
	Labels      map[string]string
	Mounts      []Mount
	Tmpfs       map[string]string // path → mount options
	Network     string            // "none" or a network name
	MemoryBytes int64
	NanoCPUs    int64
	PidsLimit   int64
	Runtime     string // runc | runsc
}

func (s ContainerSpec) body() map[string]any {
	host := map[string]any{
		"NetworkMode":    s.Network,
		"ReadonlyRootfs": true,
		"CapDrop":        []string{"ALL"},
		"SecurityOpt":    []string{"no-new-privileges:true"},
		"Privileged":     false,
		"Mounts":         s.Mounts,
		"Tmpfs":          s.Tmpfs,
		"Memory":         s.MemoryBytes,
		"MemorySwap":     s.MemoryBytes, // no swap beyond the memory limit
		"NanoCPUs":       s.NanoCPUs,
		"PidsLimit":      s.PidsLimit,
		"IpcMode":        "private",
		"Init":           true,
		"LogConfig":      map[string]any{"Type": "json-file", "Config": map[string]string{"max-size": "10m"}},
	}
	if s.Runtime != "" && s.Runtime != "runc" {
		host["Runtime"] = s.Runtime
	}
	return map[string]any{
		"Image": s.Image, "Cmd": s.Cmd, "Env": s.Env, "User": s.User, "Labels": s.Labels,
		"WorkingDir": "/tmp", "AttachStdout": false, "AttachStderr": false, "Tty": false,
		"NetworkDisabled": s.Network == "none",
		"HostConfig":      host,
	}
}

// CreateContainer creates (but does not start) a container and returns its id.
func (c *Client) CreateContainer(ctx context.Context, s ContainerSpec) (string, error) {
	var out struct {
		ID string `json:"Id"`
	}
	q := url.Values{}
	if s.Name != "" {
		q.Set("name", s.Name)
	}
	if err := c.json(ctx, http.MethodPost, "/containers/create", q, s.body(), &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// StartContainer starts a created container.
func (c *Client) StartContainer(ctx context.Context, id string) error {
	return c.json(ctx, http.MethodPost, "/containers/"+id+"/start", nil, nil, nil)
}

// KillContainer stops a running container immediately.
func (c *Client) KillContainer(ctx context.Context, id string) error {
	err := c.json(ctx, http.MethodPost, "/containers/"+id+"/kill", nil, nil, nil)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// RemoveContainer force-removes a container and its anonymous volumes.
func (c *Client) RemoveContainer(ctx context.Context, id string) error {
	err := c.json(ctx, http.MethodDelete, "/containers/"+id, url.Values{"force": {"true"}, "v": {"true"}}, nil, nil)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// State is the runtime state of a container.
type State struct {
	Running   bool `json:"Running"`
	ExitCode  int  `json:"ExitCode"`
	OOMKilled bool `json:"OOMKilled"`
	Status    string
}

// Inspect returns the container state.
func (c *Client) Inspect(ctx context.Context, id string) (State, error) {
	var out struct {
		State State `json:"State"`
	}
	err := c.json(ctx, http.MethodGet, "/containers/"+id+"/json", nil, nil, &out)
	return out.State, err
}

// Wait polls until the container stops. Polling (instead of the blocking
// /wait endpoint) survives proxies with request timeouts shorter than a scan.
func (c *Client) Wait(ctx context.Context, id string, every time.Duration) (State, error) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		st, err := c.Inspect(ctx, id)
		if err != nil {
			return st, err
		}
		if !st.Running && st.Status != "created" {
			return st, nil
		}
		select {
		case <-ctx.Done():
			return st, ctx.Err()
		case <-t.C:
		}
	}
}

// Logs returns the container's stdout and stderr (each capped at limit bytes).
func (c *Client) Logs(ctx context.Context, id string, limit int) (stdout, stderr []byte, err error) {
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+id+"/logs", url.Values{"stdout": {"1"}, "stderr": {"1"}}, nil)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var o, e bytes.Buffer
	err = demux(resp.Body, &capWriter{w: &o, n: limit}, &capWriter{w: &e, n: limit})
	return o.Bytes(), e.Bytes(), err
}

// demux splits Docker's multiplexed log stream (8-byte frame headers).
func demux(r io.Reader, stdout, stderr io.Writer) error {
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		n := int64(binary.BigEndian.Uint32(hdr[4:]))
		w := io.Discard
		switch hdr[0] {
		case 1:
			w = stdout
		case 2:
			w = stderr
		}
		if _, err := io.CopyN(w, r, n); err != nil {
			return err
		}
	}
}

type capWriter struct {
	w io.Writer
	n int
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.n <= 0 {
		return len(p), nil
	}
	q := p
	if len(q) > c.n {
		q = q[:c.n]
	}
	c.n -= len(q)
	if _, err := c.w.Write(q); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Archive streams a tar archive of path inside the container (works on
// stopped containers, including volume mounts). The caller closes it.
func (c *Client) Archive(ctx context.Context, id, path string) (io.ReadCloser, error) {
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+id+"/archive", url.Values{"path": {path}}, nil)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// Resource is a leftover container or volume found by List*.
type Resource struct {
	ID      string
	Created time.Time
	Labels  map[string]string
}

// ListContainers lists containers (any state) carrying label key.
func (c *Client) ListContainers(ctx context.Context, label string) ([]Resource, error) {
	f, _ := json.Marshal(map[string][]string{"label": {label}})
	var out []struct {
		ID      string            `json:"Id"`
		Created int64             `json:"Created"`
		Labels  map[string]string `json:"Labels"`
	}
	if err := c.json(ctx, http.MethodGet, "/containers/json", url.Values{"all": {"1"}, "filters": {string(f)}}, nil, &out); err != nil {
		return nil, err
	}
	res := make([]Resource, 0, len(out))
	for _, o := range out {
		res = append(res, Resource{ID: o.ID, Created: time.Unix(o.Created, 0), Labels: o.Labels})
	}
	return res, nil
}

// ListVolumes lists volumes carrying label key.
func (c *Client) ListVolumes(ctx context.Context, label string) ([]Resource, error) {
	f, _ := json.Marshal(map[string][]string{"label": {label}})
	var out struct {
		Volumes []struct {
			Name      string            `json:"Name"`
			CreatedAt time.Time         `json:"CreatedAt"`
			Labels    map[string]string `json:"Labels"`
		} `json:"Volumes"`
	}
	if err := c.json(ctx, http.MethodGet, "/volumes", url.Values{"filters": {string(f)}}, nil, &out); err != nil {
		return nil, err
	}
	res := make([]Resource, 0, len(out.Volumes))
	for _, v := range out.Volumes {
		res = append(res, Resource{ID: v.Name, Created: v.CreatedAt, Labels: v.Labels})
	}
	return res, nil
}
