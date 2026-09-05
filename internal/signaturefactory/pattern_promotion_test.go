package signaturefactory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPromoteRejectsPatternWithoutQualification(t *testing.T) {
	store, candidate := newPatternPromotionFixture(t)
	if _, err := store.Promote(candidate.ID); err == nil || !strings.Contains(err.Error(), "require a passing M7.3 corpus validation result") {
		t.Fatalf("expected direct pattern promotion to fail, got %v", err)
	}
	if _, err := store.ReadCandidate(candidate.ID); err != nil {
		t.Fatalf("candidate must remain pending after rejected promotion: %v", err)
	}
}

func TestPromotePatternRequiresExactCandidateAndPatternBinding(t *testing.T) {
	store, candidate := newPatternPromotionFixture(t)
	result := passingPatternResult(t, candidate)
	result.CandidateID = "AAA.Amiga.Other.0123456789abcdef"
	if _, err := store.PromotePattern(candidate.ID, result); err == nil || !strings.Contains(err.Error(), "candidate id mismatch") {
		t.Fatalf("expected candidate binding mismatch, got %v", err)
	}

	result = passingPatternResult(t, candidate)
	result.PatternSHA256 = strings.Repeat("cd", 32)
	if _, err := store.PromotePattern(candidate.ID, result); err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("expected pattern identity mismatch, got %v", err)
	}
}

func TestPromotePatternRequiresPassingCorpusGate(t *testing.T) {
	store, candidate := newPatternPromotionFixture(t)
	result := passingPatternResult(t, candidate)
	result.CleanMatches = []string{strings.Repeat("11", 32)}
	result.CleanMatchCount = 1
	result.CleanSampleCount = 1
	if _, err := store.PromotePattern(candidate.ID, result); err == nil || !strings.Contains(err.Error(), "does not pass") {
		t.Fatalf("expected clean false positive to block promotion, got %v", err)
	}
}

func TestPromotePatternWithPassingQualification(t *testing.T) {
	store, candidate := newPatternPromotionFixture(t)
	result := passingPatternResult(t, candidate)
	promoted, err := store.PromotePattern(candidate.ID, result)
	if err != nil {
		t.Fatal(err)
	}
	if promoted.Status != StatusPromoted {
		t.Fatalf("unexpected status %q", promoted.Status)
	}
	if _, err := store.ReadCandidate(candidate.ID); err == nil {
		t.Fatal("promoted candidate must no longer remain in candidates")
	}
	data, err := os.ReadFile(filepath.Join(store.Root, "promoted", candidate.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCandidateStrict(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Status != StatusPromoted || decoded.ID != candidate.ID {
		t.Fatalf("unexpected promoted record: %+v", decoded)
	}
}

func TestDecodeCorpusValidationResultStrictRejectsUnknownAndTrailingData(t *testing.T) {
	_, candidate := newPatternPromotionFixture(t)
	result := passingPatternResult(t, candidate)
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	withUnknown := append([]byte(nil), encoded[:len(encoded)-1]...)
	withUnknown = append(withUnknown, []byte(`,"unknown":true}`)...)
	if _, err := DecodeCorpusValidationResultStrict(withUnknown); err == nil {
		t.Fatal("expected unknown validation field to fail")
	}
	withTrailing := append([]byte(nil), encoded...)
	withTrailing = append(withTrailing, []byte(` {}`)...)
	if _, err := DecodeCorpusValidationResultStrict(withTrailing); err == nil {
		t.Fatal("expected trailing validation data to fail")
	}
	if _, err := DecodeCorpusValidationResultStrict(encoded); err != nil {
		t.Fatalf("valid result should decode: %v", err)
	}
}

func newPatternPromotionFixture(t *testing.T) (*Store, Candidate) {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := NewPatternCandidate(PatternCandidateInput{
		Family:        "M73Promotion",
		MalwareName:   "M7.3 promotion synthetic",
		SampleSHA256:  strings.Repeat("ab", 32),
		SampleSize:    64,
		Pattern:       FixedPattern{BytesHex: strings.Repeat("01", MinFixedPatternBytes)},
		SourceEngine:  "aaa-native",
		DetectionName: "m73-promotion-synthetic",
		Confidence:    ConfidenceConfirmed,
		CreatedAt:     time.Date(2026, 9, 5, 19, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteCandidate(candidate); err != nil {
		t.Fatal(err)
	}
	return store, candidate
}

func passingPatternResult(t *testing.T, candidate Candidate) CorpusValidationResult {
	t.Helper()
	patternSHA, err := candidate.Pattern.IdentitySHA256()
	if err != nil {
		t.Fatal(err)
	}
	return CorpusValidationResult{
		Schema:                CorpusSchemaVersion,
		CandidateID:           candidate.ID,
		PatternSHA256:         patternSHA,
		CleanManifestSHA256:   strings.Repeat("11", 32),
		MalwareManifestSHA256: strings.Repeat("22", 32),
		CleanSampleCount:      2,
		CleanMatchCount:       0,
		MalwareSampleCount:    2,
		MalwareMatchCount:     1,
		MalwareMatches:        []string{strings.Repeat("33", 32)},
		ValidatedAt:           time.Date(2026, 9, 5, 19, 5, 0, 0, time.UTC),
	}
}
