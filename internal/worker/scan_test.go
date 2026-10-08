package worker

import (
	"archive/tar"
	"bytes"
	"testing"
)

func TestExtractReports(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(name, body string) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.WriteHeader(&tar.Header{Name: "out/", Typeflag: tar.TypeDir, Mode: 0o755})
	add("out/scanx.json", `{"issues":[]}`)
	add("out/scanx.sarif", `{}`)
	add("out/raw/scanx.json", `nested`)
	add("out/other.txt", `x`)
	_ = tw.Close()
	files := map[string][]byte{}
	if err := extractReports(&buf, files); err != nil {
		t.Fatal(err)
	}
	if string(files["json"]) != `{"issues":[]}` || string(files["sarif"]) != `{}` || len(files) != 2 {
		t.Fatalf("%v", files)
	}
}

func TestFriendlyGitError(t *testing.T) {
	if m := friendlyGitError("auth", "denied"); m == "denied" || m == "" {
		t.Fatal(m)
	}
}
