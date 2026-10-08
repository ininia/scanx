package sandbox

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func frame(stream byte, s string) []byte {
	h := make([]byte, 8)
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:], uint32(len(s)))
	return append(h, s...)
}

func TestDemux(t *testing.T) {
	var in bytes.Buffer
	in.Write(frame(1, "out1 "))
	in.Write(frame(2, "err1"))
	in.Write(frame(1, "out2"))
	var o, e bytes.Buffer
	if err := demux(&in, &o, &e); err != nil {
		t.Fatal(err)
	}
	if o.String() != "out1 out2" || e.String() != "err1" {
		t.Fatalf("%q %q", o.String(), e.String())
	}
}

func testClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewClient("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Every container carries the sandbox hardening, whatever the spec says.
func TestCreateContainerHardening(t *testing.T) {
	var got map[string]any
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/containers/create") {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"Id":"abc"}`))
	})
	id, err := c.CreateContainer(t.Context(), ContainerSpec{Image: "img", Network: "none", MemoryBytes: 1 << 30, PidsLimit: 100})
	if err != nil || id != "abc" {
		t.Fatal(id, err)
	}
	hc := got["HostConfig"].(map[string]any)
	if hc["ReadonlyRootfs"] != true || hc["Privileged"] != false || hc["NetworkMode"] != "none" ||
		hc["CapDrop"].([]any)[0] != "ALL" || got["NetworkDisabled"] != true {
		t.Fatalf("hardening missing: %v", hc)
	}
	if !strings.Contains(hc["SecurityOpt"].([]any)[0].(string), "no-new-privileges") {
		t.Fatal("no-new-privileges missing")
	}
}

func TestNotFoundHandling(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"no such image"}`))
	})
	ok, err := c.ImageExists(t.Context(), "x")
	if ok || err != nil {
		t.Fatal(ok, err)
	}
	if err := c.RemoveVolume(t.Context(), "v"); err != nil {
		t.Fatal(err)
	}
}

func TestWaitPolls(t *testing.T) {
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls < 3 {
			_, _ = w.Write([]byte(`{"State":{"Running":true,"Status":"running"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"State":{"Running":false,"Status":"exited","ExitCode":1,"OOMKilled":true}}`))
	})
	st, err := c.Wait(t.Context(), "x", 1)
	if err != nil || st.ExitCode != 1 || !st.OOMKilled || calls != 3 {
		t.Fatal(st, err, calls)
	}
}
