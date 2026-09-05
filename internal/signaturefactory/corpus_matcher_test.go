package signaturefactory

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMatchPatternCorporaVerifiesAndMatchesDeterministically(t *testing.T) {
	root := t.TempDir()
	needle := []byte("AAA-M7.3-PATTERN")
	cleanA := writeCorpusFixture(t, root, []byte("clean sample alpha"))
	cleanB := writeCorpusFixture(t, root, []byte("clean sample beta"))
	malwareA := writeCorpusFixture(t, root, append([]byte("prefix-"), append(needle, []byte("-suffix")...)...))
	malwareB := writeCorpusFixture(t, root, append([]byte("other-"), needle...))

	candidate := newMatcherPatternCandidate(t, hex.EncodeToString(needle), nil)
	created := time.Date(2026, 9, 5, 18, 30, 0, 0, time.UTC)
	clean := CorpusManifest{Schema: CorpusSchemaVersion, Class: CorpusClassClean, ID: "clean-test", CreatedAt: created, Entries: []CorpusEntry{cleanB, cleanA}}
	malware := CorpusManifest{Schema: CorpusSchemaVersion, Class: CorpusClassMalware, ID: "malware-test", CreatedAt: created, Entries: []CorpusEntry{malwareB, malwareA}}

	result, err := MatchPatternCorpora(candidate, clean, malware, SHA256CorpusResolver(root), created.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !result.PassingPatternGate() {
		t.Fatalf("expected passing pattern gate: %+v", result)
	}
	if result.CleanMatchCount != 0 || result.MalwareMatchCount != 2 {
		t.Fatalf("unexpected match counts: %+v", result)
	}
	if len(result.MalwareMatches) != 2 || result.MalwareMatches[0] >= result.MalwareMatches[1] {
		t.Fatalf("malware matches not deterministic: %v", result.MalwareMatches)
	}
	cleanID, _ := clean.SHA256()
	malwareID, _ := malware.SHA256()
	patternID, _ := candidate.Pattern.IdentitySHA256()
	if result.CleanManifestSHA256 != cleanID || result.MalwareManifestSHA256 != malwareID || result.PatternSHA256 != patternID {
		t.Fatal("result identities are not bound to exact manifests/pattern")
	}
}

func TestMatchPatternCorporaFailsClosedOnChangedSample(t *testing.T) {
	root := t.TempDir()
	needle := []byte("AAA-M7.3-PATTERN")
	clean := writeCorpusFixture(t, root, []byte("clean original"))
	malware := writeCorpusFixture(t, root, append([]byte("x"), needle...))
	if err := os.WriteFile(filepath.Join(root, clean.SHA256), []byte("clean changed!"), 0o600); err != nil {
		t.Fatal(err)
	}
	created := time.Now().UTC()
	_, err := MatchPatternCorpora(
		newMatcherPatternCandidate(t, hex.EncodeToString(needle), nil),
		CorpusManifest{Schema: CorpusSchemaVersion, Class: CorpusClassClean, ID: "clean", CreatedAt: created, Entries: []CorpusEntry{clean}},
		CorpusManifest{Schema: CorpusSchemaVersion, Class: CorpusClassMalware, ID: "malware", CreatedAt: created, Entries: []CorpusEntry{malware}},
		SHA256CorpusResolver(root), created,
	)
	if err == nil || (!strings.Contains(err.Error(), "size mismatch") && !strings.Contains(err.Error(), "sha256 mismatch")) {
		t.Fatalf("expected changed sample to fail closed, got %v", err)
	}
}

func TestMatchPatternCorporaFixedOffset(t *testing.T) {
	root := t.TempDir()
	needle := []byte("12345678")
	clean := writeCorpusFixture(t, root, []byte("abcdefgh"))
	malwareHit := writeCorpusFixture(t, root, append([]byte("ABCD"), needle...))
	malwareMiss := writeCorpusFixture(t, root, append([]byte("X"), append(needle, []byte("tail")...)...))
	offset := int64(4)
	created := time.Now().UTC()
	result, err := MatchPatternCorpora(
		newMatcherPatternCandidate(t, hex.EncodeToString(needle), &offset),
		CorpusManifest{Schema: CorpusSchemaVersion, Class: CorpusClassClean, ID: "clean", CreatedAt: created, Entries: []CorpusEntry{clean}},
		CorpusManifest{Schema: CorpusSchemaVersion, Class: CorpusClassMalware, ID: "malware", CreatedAt: created, Entries: []CorpusEntry{malwareMiss, malwareHit}},
		SHA256CorpusResolver(root), created,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.MalwareMatchCount != 1 || result.MalwareMatches[0] != malwareHit.SHA256 {
		t.Fatalf("fixed offset semantics failed: %+v", result)
	}
}

func TestMatchPatternCorporaReportsCleanFalsePositive(t *testing.T) {
	root := t.TempDir()
	needle := []byte("12345678")
	clean := writeCorpusFixture(t, root, append([]byte("clean-"), needle...))
	malware := writeCorpusFixture(t, root, append([]byte("bad-"), needle...))
	created := time.Now().UTC()
	result, err := MatchPatternCorpora(
		newMatcherPatternCandidate(t, hex.EncodeToString(needle), nil),
		CorpusManifest{Schema: CorpusSchemaVersion, Class: CorpusClassClean, ID: "clean", CreatedAt: created, Entries: []CorpusEntry{clean}},
		CorpusManifest{Schema: CorpusSchemaVersion, Class: CorpusClassMalware, ID: "malware", CreatedAt: created, Entries: []CorpusEntry{malware}},
		SHA256CorpusResolver(root), created,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.CleanMatchCount != 1 || result.PassingPatternGate() {
		t.Fatalf("clean match must fail promotion gate: %+v", result)
	}
}

func TestMatchPatternCorporaRequiresCorrectClasses(t *testing.T) {
	created := time.Now().UTC()
	entry := CorpusEntry{SHA256: strings.Repeat("ab", 32), Size: 1}
	manifest := CorpusManifest{Schema: CorpusSchemaVersion, Class: CorpusClassMalware, ID: "wrong", CreatedAt: created, Entries: []CorpusEntry{entry}}
	_, err := MatchPatternCorpora(newMatcherPatternCandidate(t, strings.Repeat("01", 8), nil), manifest, manifest, func(CorpusEntry) (string, error) { return "unused", nil }, created)
	if err == nil || !strings.Contains(err.Error(), "clean manifest has class") {
		t.Fatalf("expected class mismatch failure, got %v", err)
	}
}

func writeCorpusFixture(t *testing.T, root string, data []byte) CorpusEntry {
	t.Helper()
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(root, hash), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return CorpusEntry{SHA256: hash, Size: int64(len(data))}
}

func newMatcherPatternCandidate(t *testing.T, bytesHex string, offset *int64) Candidate {
	t.Helper()
	candidate, err := NewPatternCandidate(PatternCandidateInput{
		Family:        "M73Matcher",
		MalwareName:   "M7.3 synthetic matcher sample",
		SampleSHA256:  strings.Repeat("ab", 32),
		SampleSize:    123,
		Pattern:       FixedPattern{BytesHex: bytesHex, Offset: offset},
		SourceEngine:  "aaa-native",
		DetectionName: "m73-synthetic",
		Confidence:    ConfidenceConfirmed,
		CreatedAt:     time.Date(2026, 9, 5, 18, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}
