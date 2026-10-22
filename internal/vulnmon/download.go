package vulnmon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BaseURL is the OSV export bucket (public, read-only).
var BaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

const maxZipBytes = 2 << 30

// ZipPath is where an ecosystem export is kept.
func ZipPath(dir, eco string) string { return filepath.Join(dir, safeName(eco)+".zip") }

func safeName(eco string) string {
	return strings.NewReplacer("/", "_", ":", "_", ".", "_").Replace(eco)
}

// Download refreshes one ecosystem export; it returns false when the
// copy on disk is already current (ETag).
func Download(ctx context.Context, client *http.Client, dir, eco string) (bool, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return false, err
	}
	etagFile := filepath.Join(dir, safeName(eco)+".etag")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, BaseURL+"/"+url.PathEscape(eco)+"/all.zip", nil)
	if err != nil {
		return false, err
	}
	if b, err := os.ReadFile(etagFile); err == nil { //nolint:gosec // our own cache directory
		if _, serr := os.Stat(ZipPath(dir, eco)); serr == nil {
			req.Header.Set("If-None-Match", strings.TrimSpace(string(b)))
		}
	}
	req.Header.Set("User-Agent", "scanX-vulnmon")
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return false, nil
	case http.StatusOK:
	default:
		return false, fmt.Errorf("download %s: HTTP %d", eco, resp.StatusCode)
	}
	tmp, err := os.CreateTemp(dir, safeName(eco)+"-*.part")
	if err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxZipBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return false, err
	}
	if n > maxZipBytes {
		return false, errors.New("download too large")
	}
	if err := os.Rename(tmp.Name(), ZipPath(dir, eco)); err != nil {
		return false, err
	}
	if et := resp.Header.Get("ETag"); et != "" {
		_ = os.WriteFile(etagFile, []byte(et), 0o600)
	}
	return true, nil
}

// Age is how old an ecosystem export on disk is (0 if missing).
func Age(dir, eco string) time.Duration {
	st, err := os.Stat(ZipPath(dir, eco))
	if err != nil {
		return 0
	}
	return time.Since(st.ModTime())
}
