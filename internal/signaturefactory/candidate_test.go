package signaturefactory

import (
	"strings"
	"testing"
	"time"
)

func TestNewExactFileCandidate(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	created := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	candidate, err := NewExactCandidate(ExactCandidateInput{
		Family:        "TestVirus",
		Kind:          KindFileSHA256,
		MalwareName:   "Test Virus",
		SampleSHA256:  hash,
		SampleSize:    1234,
		Format:        "amiga-hunk-executable",
		SourceEngine:  "aaa-native",
		DetectionName: "synthetic-test-detection",
		Confidence:    ConfidenceConfirmed,
		CreatedAt:     created,
	})
	if err != nil {
		t.Fatal(err)
	}
	if candidate.ID != "AAA.Amiga.TestVirus."+hash[:16] {
		t.Fatalf("unexpected id %q", candidate.ID)
	}
	if candidate.Status != StatusCandidate || candidate.CreatedBy != CreatedBy {
		t.Fatalf("unexpected candidate metadata: %+v", candidate)
	}
	if err := candidate.Validate(); err != nil {
		t.Fatalf("generated candidate failed validation: %v", err)
	}
}

func TestNewExactBootblockCandidateRequiresBothHashes(t *testing.T) {
	_, err := NewExactCandidate(ExactCandidateInput{
		Family:          "BootVirus",
		Kind:            KindBootblockSHA256,
		MalwareName:     "Boot Virus",
		BootblockSHA256: strings.Repeat("cd", 32),
		SourceEngine:    "aaa-native",
		DetectionName:   "synthetic-boot-detection",
		Confidence:      ConfidenceConfirmed,
		CreatedAt:       time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("expected missing sample hash to fail")
	}
}

func TestCandidateRejectsPathTraversalID(t *testing.T) {
	candidate := Candidate{
		Schema:        SchemaVersion,
		ID:            "AAA.Amiga.Test.../escape",
		Status:        StatusCandidate,
		Kind:          KindFileSHA256,
		MalwareName:   "Test",
		SampleSHA256:  strings.Repeat("ab", 32),
		SourceEngine:  "aaa-native",
		DetectionName: "test",
		Confidence:    ConfidenceConfirmed,
		CreatedAt:     time.Now().UTC(),
		CreatedBy:     CreatedBy,
	}
	if err := candidate.Validate(); err == nil {
		t.Fatal("expected traversal-like candidate id to fail")
	}
}

func TestCandidateRejectsUppercaseSHA256(t *testing.T) {
	_, err := NewExactCandidate(ExactCandidateInput{
		Family:        "TestVirus",
		Kind:          KindFileSHA256,
		MalwareName:   "Test Virus",
		SampleSHA256:  strings.Repeat("AB", 32),
		SourceEngine:  "aaa-native",
		DetectionName: "test",
		Confidence:    ConfidenceConfirmed,
		CreatedAt:     time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("expected uppercase hash to fail")
	}
}

func TestPatternCandidateDisabledInM70(t *testing.T) {
	candidate := Candidate{
		Schema:        SchemaVersion,
		ID:            "AAA.Amiga.TestVirus.0123456789abcdef",
		Status:        StatusCandidate,
		Kind:          KindPattern,
		MalwareName:   "Test Virus",
		SourceEngine:  "aaa-native",
		DetectionName: "test",
		Confidence:    ConfidenceConfirmed,
		CreatedAt:     time.Now().UTC(),
		CreatedBy:     CreatedBy,
	}
	if err := candidate.Validate(); err == nil {
		t.Fatal("expected pattern candidate to remain disabled")
	}
}
