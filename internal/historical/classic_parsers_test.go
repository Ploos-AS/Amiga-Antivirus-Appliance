package historical

import (
	"strings"
	"testing"
	"time"
)

func TestClassicScannerParsersFailClosed(t *testing.T) {
	for _, engine := range []string{"virusz3", "virusexecutor", "viruschecker2", "virusslayer2", "mill"} {
		t.Run(engine, func(t *testing.T) {
			verdict, detection, err := ParseClassicScannerOutput(engine, []byte("scanner finished"), true)
			if err != nil {
				t.Fatal(err)
			}
			if verdict != VerdictUnknown || detection != "" {
				t.Fatalf("got (%q,%q), want unknown", verdict, detection)
			}
		})
	}
}

func TestClassicScannerParserFixtures(t *testing.T) {
	tests := []struct {
		name      string
		engine    string
		output    string
		completed bool
		verdict   Verdict
		detection string
		wantErr   bool
	}{
		{name: "virusz infected", engine: "virusz3", output: "Virus found: SCA\r\n", completed: true, verdict: VerdictInfected, detection: "SCA"},
		{name: "executor clean", engine: "virusexecutor", output: "No viruses found\r\n", completed: true, verdict: VerdictClean},
		{name: "checker suspicious", engine: "viruschecker2", output: "Unknown bootblock\r\n", completed: true, verdict: VerdictSuspicious},
		{name: "slayer infected", engine: "virusslayer2", output: "Infected: Byte Bandit\r\n", completed: true, verdict: VerdictInfected, detection: "Byte Bandit"},
		{name: "mill clean", engine: "mill", output: "Nothing found\r\n", completed: true, verdict: VerdictClean},
		{name: "runtime failure", engine: "mill", output: "partial", completed: false, verdict: VerdictError, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verdict, detection, err := ParseClassicScannerOutput(tc.engine, []byte(tc.output), tc.completed)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v wantErr=%v", err, tc.wantErr)
			}
			if verdict != tc.verdict || detection != tc.detection {
				t.Fatalf("got (%q,%q), want (%q,%q)", verdict, detection, tc.verdict, tc.detection)
			}
		})
	}
}

func TestClassicScannerResultPreservesEvidenceAndProfile(t *testing.T) {
	start := time.Date(2026, 9, 6, 20, 0, 0, 0, time.UTC)
	base := Result{
		EngineID:            "virusz3",
		EngineName:          "VirusZ III",
		EngineVersion:       "1.04ß",
		OSProfile:           OS31,
		ScannerBinarySHA256: strings.Repeat("a", 64),
		RawExit:             "completed",
		RawLog:              []byte("Virus found: SCA\r\n"),
		InputSHA256:         strings.Repeat("b", 64),
		StartedAt:           start,
		FinishedAt:          start.Add(time.Second),
	}
	result, err := ClassicScannerResult(base, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != VerdictInfected || result.DetectionName != "SCA" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.RawLogSHA256 != HashBytes(base.RawLog) {
		t.Fatal("raw log evidence digest mismatch")
	}

	base.OSProfile = OS13
	if _, err := ClassicScannerResult(base, true); err == nil {
		t.Fatal("expected unsupported os13 rejection for VirusZ III")
	}
}

func TestClassicScannerRejectsUnsupportedEngine(t *testing.T) {
	if _, _, err := ParseClassicScannerOutput("vtschutz", []byte("No virus found"), true); err == nil {
		t.Fatal("expected VT-Schutz to remain on its dedicated M8.3 adapter")
	}
}
