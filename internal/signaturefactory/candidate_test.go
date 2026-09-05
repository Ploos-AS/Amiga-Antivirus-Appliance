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

func TestNewPatternCandidateAnyOffset(t *testing.T) {
	sampleHash := strings.Repeat("ab", 32)
	pattern := FixedPattern{BytesHex: "0011223344556677"}
	candidate, err := NewPatternCandidate(PatternCandidateInput{
		Family:        "TestVirus",
		MalwareName:   "Test Virus",
		SampleSHA256:  sampleHash,
		SampleSize:    1234,
		Format:        "amiga-hunk-executable",
		Pattern:       pattern,
		SourceEngine:  "aaa-native",
		DetectionName: "synthetic-pattern",
		Confidence:    ConfidenceConfirmed,
		CreatedAt:     time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := pattern.IdentitySHA256()
	if err != nil {
		t.Fatal(err)
	}
	if candidate.ID != "AAA.Amiga.TestVirus."+identity[:16] {
		t.Fatalf("unexpected pattern id %q", candidate.ID)
	}
	if candidate.Pattern == nil || candidate.Pattern.BytesHex != pattern.BytesHex || candidate.Pattern.Offset != nil {
		t.Fatalf("unexpected pattern candidate: %+v", candidate)
	}
	if err := candidate.Validate(); err != nil {
		t.Fatalf("generated pattern candidate failed validation: %v", err)
	}
}

func TestPatternIdentityIncludesOffsetSemantics(t *testing.T) {
	offset := int64(0)
	anywhere := FixedPattern{BytesHex: "0011223344556677"}
	fixed := FixedPattern{BytesHex: "0011223344556677", Offset: &offset}
	anyHash, err := anywhere.IdentitySHA256()
	if err != nil {
		t.Fatal(err)
	}
	fixedHash, err := fixed.IdentitySHA256()
	if err != nil {
		t.Fatal(err)
	}
	if anyHash == fixedHash {
		t.Fatal("offset-constrained and unconstrained patterns must have different identities")
	}
}

func TestPatternCandidateRejectsTooShortPattern(t *testing.T) {
	_, err := NewPatternCandidate(PatternCandidateInput{
		Family:        "TestVirus",
		MalwareName:   "Test Virus",
		SampleSHA256:  strings.Repeat("ab", 32),
		Pattern:       FixedPattern{BytesHex: "00112233445566"},
		SourceEngine:  "aaa-native",
		DetectionName: "test",
		Confidence:    ConfidenceConfirmed,
		CreatedAt:     time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("expected pattern shorter than minimum to fail")
	}
}

func TestPatternCandidateRejectsUppercaseOrOddHex(t *testing.T) {
	for _, bytesHex := range []string{"00112233445566AABB", "001122334455667"} {
		_, err := NewPatternCandidate(PatternCandidateInput{
			Family:        "TestVirus",
			MalwareName:   "Test Virus",
			SampleSHA256:  strings.Repeat("ab", 32),
			Pattern:       FixedPattern{BytesHex: bytesHex},
			SourceEngine:  "aaa-native",
			DetectionName: "test",
			Confidence:    ConfidenceConfirmed,
			CreatedAt:     time.Now().UTC(),
		})
		if err == nil {
			t.Fatalf("expected unsafe pattern encoding %q to fail", bytesHex)
		}
	}
}

func TestPatternCandidateRejectsNegativeOffset(t *testing.T) {
	offset := int64(-1)
	_, err := NewPatternCandidate(PatternCandidateInput{
		Family:        "TestVirus",
		MalwareName:   "Test Virus",
		SampleSHA256:  strings.Repeat("ab", 32),
		Pattern:       FixedPattern{BytesHex: "0011223344556677", Offset: &offset},
		SourceEngine:  "aaa-native",
		DetectionName: "test",
		Confidence:    ConfidenceConfirmed,
		CreatedAt:     time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("expected negative pattern offset to fail")
	}
}

func TestPatternCandidateIDMustMatchPatternIdentity(t *testing.T) {
	candidate, err := NewPatternCandidate(PatternCandidateInput{
		Family:        "TestVirus",
		MalwareName:   "Test Virus",
		SampleSHA256:  strings.Repeat("ab", 32),
		Pattern:       FixedPattern{BytesHex: "0011223344556677"},
		SourceEngine:  "aaa-native",
		DetectionName: "test",
		Confidence:    ConfidenceConfirmed,
		CreatedAt:     time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate.ID = "AAA.Amiga.TestVirus.0123456789abcdef"
	if err := candidate.Validate(); err == nil {
		t.Fatal("expected mismatched pattern identity to fail")
	}
}

func TestExactCandidateRejectsPatternField(t *testing.T) {
	candidate, err := NewExactCandidate(ExactCandidateInput{
		Family:        "TestVirus",
		Kind:          KindFileSHA256,
		MalwareName:   "Test Virus",
		SampleSHA256:  strings.Repeat("ab", 32),
		SourceEngine:  "aaa-native",
		DetectionName: "test",
		Confidence:    ConfidenceConfirmed,
		CreatedAt:     time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate.Pattern = &FixedPattern{BytesHex: "0011223344556677"}
	if err := candidate.Validate(); err == nil {
		t.Fatal("expected exact candidate with pattern field to fail")
	}
}
