package engineevidence

import (
	"strings"
	"testing"
	"time"
)

func TestCompletedResultValidates(t *testing.T) {
	started := time.Unix(10, 0).UTC()
	finished := time.Unix(11, 0).UTC()
	r := Result{
		Kind:          KindHistorical,
		EngineID:      "virusz-iii",
		EngineName:    "VirusZ III",
		EngineVersion: "1.04b",
		Status:        StatusCompleted,
		Verdict:       "infected",
		DetectionName: "Synthetic.Test",
		InputSHA256:   strings.Repeat("a", 64),
		StartedAt:     &started,
		FinishedAt:    &finished,
		Components: []Component{{
			Kind:    "xvs-library",
			Name:    "xvs.library",
			Version: "33.49",
			SHA256:  strings.Repeat("b", 64),
		}},
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestCompletedResultRequiresVersion(t *testing.T) {
	r := Result{
		Kind:        KindNative,
		EngineID:    "aaa-native",
		EngineName:  "AAA native analyzer",
		Status:      StatusCompleted,
		Verdict:     "clean",
		InputSHA256: strings.Repeat("a", 64),
	}
	if err := r.Validate(); err == nil {
		t.Fatal("expected missing version rejection")
	}
}

func TestErrorResultAllowsUnknownVersion(t *testing.T) {
	r := Result{
		Kind:        KindClamAV,
		EngineID:    "clamav",
		EngineName:  "ClamAV",
		Status:      StatusError,
		Verdict:     "error",
		InputSHA256: strings.Repeat("a", 64),
		Error:       "executable unavailable",
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestDuplicateComponentKindsRejected(t *testing.T) {
	r := Result{
		Kind:          KindHistorical,
		EngineID:      "virusz-iii",
		EngineName:    "VirusZ III",
		EngineVersion: "1.04b",
		Status:        StatusCompleted,
		Verdict:       "clean",
		InputSHA256:   strings.Repeat("a", 64),
		Components: []Component{
			{Kind: "xvs-library", Name: "xvs.library", Version: "33.49"},
			{Kind: "xvs-library", Name: "xvs.library", Version: "33.48"},
		},
	}
	if err := r.Validate(); err == nil {
		t.Fatal("expected duplicate component kind rejection")
	}
}
