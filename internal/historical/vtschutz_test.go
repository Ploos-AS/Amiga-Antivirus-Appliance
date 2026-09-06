package historical

import (
	"strings"
	"testing"
	"time"
)

func TestParseVTSchutzOutput(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		completed bool
		verdict   Verdict
		detection string
		wantErr   bool
	}{
		{name: "clean", output: "VT-Schutz 3.17\r\nNo virus found\r\n", completed: true, verdict: VerdictClean},
		{name: "infected", output: "VT-Schutz 3.17\r\nVirus found: SCA\r\n", completed: true, verdict: VerdictInfected, detection: "SCA"},
		{name: "german infected", output: "Virus gefunden: Byte Bandit\r\n", completed: true, verdict: VerdictInfected, detection: "Byte Bandit"},
		{name: "suspicious", output: "Suspicious bootblock\r\n", completed: true, verdict: VerdictSuspicious},
		{name: "unknown", output: "VT-Schutz 3.17 ready\r\n", completed: true, verdict: VerdictUnknown},
		{name: "empty", completed: true, verdict: VerdictUnknown},
		{name: "failed runtime", output: "partial output", completed: false, verdict: VerdictError, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verdict, detection, err := ParseVTSchutzOutput([]byte(tc.output), tc.completed)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v wantErr=%v", err, tc.wantErr)
			}
			if verdict != tc.verdict || detection != tc.detection {
				t.Fatalf("got (%q,%q), want (%q,%q)", verdict, detection, tc.verdict, tc.detection)
			}
		})
	}
}

func TestVTSchutzResultPreservesEvidence(t *testing.T) {
	start := time.Date(2026, 9, 6, 16, 0, 0, 0, time.UTC)
	base := Result{
		EngineID:            VTSchutzEngineID,
		EngineName:          "VT-Schutz",
		EngineVersion:       "3.17",
		OSProfile:           OS13,
		ScannerBinarySHA256: strings.Repeat("a", 64),
		RawExit:             "completed",
		RawLog:              []byte("VT-Schutz 3.17\r\nVirus found: SCA\r\n"),
		InputSHA256:         strings.Repeat("b", 64),
		StartedAt:           start,
		FinishedAt:          start.Add(time.Second),
	}
	result, err := VTSchutzResult(base, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != VerdictInfected || result.DetectionName != "SCA" {
		t.Fatalf("unexpected normalized result: %#v", result)
	}
	if result.RawLogSHA256 != HashBytes(base.RawLog) {
		t.Fatal("raw VT-Schutz evidence digest mismatch")
	}
}

func TestVTSchutzRequiresOS13(t *testing.T) {
	start := time.Now().UTC()
	base := Result{
		EngineID:            VTSchutzEngineID,
		EngineName:          "VT-Schutz",
		EngineVersion:       "3.17",
		OSProfile:           OS31,
		ScannerBinarySHA256: strings.Repeat("a", 64),
		RawExit:             "completed",
		RawLog:              []byte("No virus found"),
		InputSHA256:         strings.Repeat("b", 64),
		StartedAt:           start,
		FinishedAt:          start,
	}
	if _, err := VTSchutzResult(base, true); err == nil {
		t.Fatal("expected os31 rejection")
	}
}

func TestVTSchutzUnknownOutputDoesNotBecomeClean(t *testing.T) {
	verdict, _, err := ParseVTSchutzOutput([]byte("VT-Schutz finished"), true)
	if err != nil {
		t.Fatal(err)
	}
	if verdict != VerdictUnknown {
		t.Fatalf("verdict=%q want unknown", verdict)
	}
}
