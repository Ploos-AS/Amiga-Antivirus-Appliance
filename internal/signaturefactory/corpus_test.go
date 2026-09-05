package signaturefactory

import (
	"strings"
	"testing"
	"time"
)

func TestCorpusManifestCanonicalIdentityIndependentOfEntryOrder(t *testing.T) {
	created := time.Date(2026, 9, 5, 18, 30, 0, 0, time.FixedZone("test", 2*60*60))
	first := CorpusManifest{
		Schema:    CorpusSchemaVersion,
		Class:     CorpusClassClean,
		ID:        "clean-reference-1",
		CreatedAt: created,
		Entries: []CorpusEntry{
			{SHA256: strings.Repeat("bb", 32), Size: 2, Format: "adf"},
			{SHA256: strings.Repeat("aa", 32), Size: 1, Format: "amiga-hunk-executable"},
		},
	}
	second := first
	second.Entries = []CorpusEntry{first.Entries[1], first.Entries[0]}

	firstHash, err := first.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	secondHash, err := second.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	if firstHash != secondHash {
		t.Fatalf("entry ordering changed canonical identity: %s != %s", firstHash, secondHash)
	}

	encoded, err := first.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"created_at":"2026-09-05T16:30:00Z"`) {
		t.Fatalf("canonical timestamp was not UTC: %s", encoded)
	}
}

func TestCorpusManifestValidationFailsClosed(t *testing.T) {
	base := testCorpusManifest()

	cases := []struct {
		name string
		edit func(*CorpusManifest)
	}{
		{"schema", func(m *CorpusManifest) { m.Schema = 2 }},
		{"class", func(m *CorpusManifest) { m.Class = "other" }},
		{"id", func(m *CorpusManifest) { m.ID = " " }},
		{"created", func(m *CorpusManifest) { m.CreatedAt = time.Time{} }},
		{"empty", func(m *CorpusManifest) { m.Entries = nil }},
		{"bad-hash", func(m *CorpusManifest) { m.Entries[0].SHA256 = "ABC" }},
		{"negative-size", func(m *CorpusManifest) { m.Entries[0].Size = -1 }},
		{"duplicate", func(m *CorpusManifest) { m.Entries = append(m.Entries, m.Entries[0]) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest := base
			manifest.Entries = append([]CorpusEntry(nil), base.Entries...)
			tc.edit(&manifest)
			if err := manifest.Validate(); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
}

func TestDecodeCorpusManifestStrictRejectsUnknownAndTrailingData(t *testing.T) {
	manifest := testCorpusManifest()
	encoded, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCorpusManifestStrict(encoded); err != nil {
		t.Fatalf("canonical manifest rejected: %v", err)
	}

	unknown := strings.Replace(string(encoded), `"entries":`, `"unexpected":true,"entries":`, 1)
	if _, err := DecodeCorpusManifestStrict([]byte(unknown)); err == nil {
		t.Fatal("unknown JSON field was accepted")
	}
	if _, err := DecodeCorpusManifestStrict(append(encoded, []byte("{}\n")...)); err == nil {
		t.Fatal("trailing JSON value was accepted")
	}
}

func TestCorpusValidationResultPatternGate(t *testing.T) {
	result := CorpusValidationResult{
		Schema:                CorpusSchemaVersion,
		CandidateID:           "AAA.Amiga.TestVirus.0123456789abcdef",
		PatternSHA256:         strings.Repeat("11", 32),
		CleanManifestSHA256:   strings.Repeat("22", 32),
		MalwareManifestSHA256: strings.Repeat("33", 32),
		CleanSampleCount:      100,
		CleanMatchCount:       0,
		MalwareSampleCount:    2,
		MalwareMatchCount:     1,
		MalwareMatches:        []string{strings.Repeat("44", 32)},
		ValidatedAt:           time.Date(2026, 9, 5, 18, 30, 0, 0, time.UTC),
	}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	if !result.PassingPatternGate() {
		t.Fatal("valid zero-clean-match result did not pass pattern gate")
	}

	withFalsePositive := result
	withFalsePositive.CleanMatchCount = 1
	withFalsePositive.CleanMatches = []string{strings.Repeat("55", 32)}
	if withFalsePositive.PassingPatternGate() {
		t.Fatal("clean-corpus match passed pattern gate")
	}

	withoutMalwareCoverage := result
	withoutMalwareCoverage.MalwareMatchCount = 0
	withoutMalwareCoverage.MalwareMatches = nil
	if withoutMalwareCoverage.PassingPatternGate() {
		t.Fatal("zero malware matches passed pattern gate")
	}
}

func TestCorpusValidationResultRejectsInconsistentMatchLists(t *testing.T) {
	result := CorpusValidationResult{
		Schema:                CorpusSchemaVersion,
		CandidateID:           "AAA.Amiga.TestVirus.0123456789abcdef",
		PatternSHA256:         strings.Repeat("11", 32),
		CleanManifestSHA256:   strings.Repeat("22", 32),
		MalwareManifestSHA256: strings.Repeat("33", 32),
		CleanSampleCount:      1,
		MalwareSampleCount:    2,
		MalwareMatchCount:     2,
		MalwareMatches: []string{
			strings.Repeat("55", 32),
			strings.Repeat("44", 32),
		},
		ValidatedAt: time.Date(2026, 9, 5, 18, 30, 0, 0, time.UTC),
	}
	if err := result.Validate(); err == nil {
		t.Fatal("unsorted match list was accepted")
	}

	result.MalwareMatches = []string{strings.Repeat("44", 32)}
	if err := result.Validate(); err == nil {
		t.Fatal("match-count/list mismatch was accepted")
	}
}

func testCorpusManifest() CorpusManifest {
	return CorpusManifest{
		Schema:    CorpusSchemaVersion,
		Class:     CorpusClassClean,
		ID:        "clean-reference-1",
		CreatedAt: time.Date(2026, 9, 5, 18, 30, 0, 0, time.UTC),
		Entries: []CorpusEntry{
			{SHA256: strings.Repeat("aa", 32), Size: 901120, Format: "adf", Provenance: "synthetic-test"},
		},
	}
}
