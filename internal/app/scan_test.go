package app

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunScanConfigErrors(t *testing.T) {
	dir := t.TempDir()
	base := ScanOptions{Path: dir, Out: t.TempDir(), Formats: []string{"json"}, FailOn: "high", Engine: "exec", Profile: "default"}
	cases := map[string]func(*ScanOptions){
		"bad fail-on": func(o *ScanOptions) { o.FailOn = "urgent" },
		"bad format":  func(o *ScanOptions) { o.Formats = []string{"pdf"} },
		"bad profile": func(o *ScanOptions) { o.Profile = "turbo" },
		"bad engine":  func(o *ScanOptions) { o.Engine = "podman" },
		"no path":     func(o *ScanOptions) { o.Path = dir + "/missing" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			o := base
			mut(&o)
			var out, errb bytes.Buffer
			if code := RunScan(context.Background(), o, &out, &errb); code != ExitConfig {
				t.Fatalf("code %d (stderr %s)", code, errb.String())
			}
		})
	}
}

func TestDockerArgsAreHardened(t *testing.T) {
	o := ScanOptions{
		Path: "/src/repo", Out: "/tmp/out", Formats: []string{"json", "sarif"}, FailOn: "high",
		Profile: "fast", History: false, Parallelism: 2, Exclude: []string{"docs"}, Branch: "main", NoSnippets: true,
	}
	args := strings.Join(dockerArgs(o, "img:1"), " ")
	for _, need := range []string{
		"--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges:true",
		"--tmpfs /tmp:rw,noexec,nosuid", "/src/repo:/work/src:ro", "/tmp/out:/work/out",
		"img:1 scan --engine exec", "--format json,sarif", "--history=false", "--no-snippets", "--exclude docs", "--branch main",
	} {
		if !strings.Contains(args, need) {
			t.Errorf("missing %q in %s", need, args)
		}
	}
}

func TestImageTag(t *testing.T) {
	if !strings.HasSuffix(DefaultScannerImage, ":dev") {
		t.Fatalf("dev build should use :dev image, got %s", DefaultScannerImage)
	}
}

func TestToolsAvailableNeedsLayout(t *testing.T) {
	t.Setenv("SCANX_RULES_DIR", "")
	if toolsAvailable() {
		t.Fatal("without SCANX_RULES_DIR tools are not considered available")
	}
}
