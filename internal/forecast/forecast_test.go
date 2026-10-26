package forecast

import (
	"testing"
	"time"
)

func TestEstimate(t *testing.T) {
	small := Estimate(Input{Tools: []string{"opengrep", "devskim", "gitleaks-dir"}, AnalysisBytes: 10 << 20, FullBytes: 500 << 20, Parallelism: 1})
	big := Estimate(Input{Tools: []string{"opengrep", "devskim", "gitleaks-dir"}, AnalysisBytes: 400 << 20, FullBytes: 500 << 20, Parallelism: 1})
	if small >= big || small > 15*time.Minute {
		t.Fatalf("small %v big %v", small, big)
	}
	par := Estimate(Input{Tools: []string{"opengrep", "devskim", "gitleaks-dir"}, AnalysisBytes: 400 << 20, FullBytes: 500 << 20, Parallelism: 3})
	if par >= big {
		t.Fatalf("parallel %v not faster than %v", par, big)
	}
	if Correct(10*time.Minute, 5*time.Minute, 10*time.Minute) != 20*time.Minute ||
		Correct(10*time.Minute, time.Minute, 60*time.Minute) != 30*time.Minute {
		t.Fatal("correct")
	}
	o := Order([]string{"opengrep", "zizmor", "gitleaks-dir"}, 10<<20, 10<<20)
	if o[0] != "zizmor" || o[2] != "opengrep" {
		t.Fatalf("order %v", o)
	}
}
