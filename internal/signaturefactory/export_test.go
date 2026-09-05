package signaturefactory

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestExportNativeBootblocksPromotedOnly(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	promoted := mustExactCandidate(t, ExactCandidateInput{
		Family:          "TestVirus",
		Kind:            KindBootblockSHA256,
		MalwareName:     "Test Virus",
		SampleSHA256:    strings.Repeat("1", 64),
		BootblockSHA256: strings.Repeat("2", 64),
		SampleSize:      901120,
		Format:          "adf",
		SourceEngine:    "aaa-native",
		DetectionName:   "Test Virus",
		Confidence:      ConfidenceConfirmed,
		CreatedAt:       time.Unix(1, 0).UTC(),
	})
	if _, err := store.WriteCandidate(promoted); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Promote(promoted.ID); err != nil {
		t.Fatal(err)
	}

	pending := mustExactCandidate(t, ExactCandidateInput{
		Family:          "PendingVirus",
		Kind:            KindBootblockSHA256,
		MalwareName:     "Pending Virus",
		SampleSHA256:    strings.Repeat("3", 64),
		BootblockSHA256: strings.Repeat("4", 64),
		SourceEngine:    "aaa-native",
		DetectionName:   "Pending Virus",
		Confidence:      ConfidenceSingleEngine,
		CreatedAt:       time.Unix(2, 0).UTC(),
	})
	if _, err := store.WriteCandidate(pending); err != nil {
		t.Fatal(err)
	}

	fileOnly := mustExactCandidate(t, ExactCandidateInput{
		Family:        "FileOnly",
		Kind:          KindFileSHA256,
		MalwareName:   "File Only",
		SampleSHA256:  strings.Repeat("5", 64),
		SourceEngine:  "clamav",
		DetectionName: "File.Only.Test",
		Confidence:    ConfidenceSingleEngine,
		CreatedAt:     time.Unix(3, 0).UTC(),
	})
	if _, err := store.WriteCandidate(fileOnly); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Promote(fileOnly.ID); err != nil {
		t.Fatal(err)
	}

	path, count, err := store.ExportNativeBootblocks()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var database nativeBootblockDatabase
	if err := json.Unmarshal(data, &database); err != nil {
		t.Fatal(err)
	}
	if database.Schema != 1 || len(database.Entries) != 1 {
		t.Fatalf("unexpected database: %#v", database)
	}
	entry := database.Entries[0]
	if entry.SHA256 != promoted.BootblockSHA256 {
		t.Fatalf("sha256 = %q", entry.SHA256)
	}
	if entry.Status != "known-malicious" {
		t.Fatalf("status = %q", entry.Status)
	}
	if entry.Name != promoted.MalwareName {
		t.Fatalf("name = %q", entry.Name)
	}
	if entry.Source != "signature-factory:"+promoted.ID {
		t.Fatalf("source = %q", entry.Source)
	}
}

func TestExportNativeBootblocksRejectsDuplicateHash(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bootHash := strings.Repeat("a", 64)
	for i, family := range []string{"FamilyOne", "FamilyTwo"} {
		candidate := mustExactCandidate(t, ExactCandidateInput{
			Family:          family,
			Kind:            KindBootblockSHA256,
			MalwareName:     family,
			SampleSHA256:    strings.Repeat(string(rune('b'+i)), 64),
			BootblockSHA256: bootHash,
			SourceEngine:    "aaa-native",
			DetectionName:   family,
			Confidence:      ConfidenceConfirmed,
			CreatedAt:       time.Unix(int64(i+1), 0).UTC(),
		})
		if _, err := store.WriteCandidate(candidate); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Promote(candidate.ID); err != nil {
			t.Fatal(err)
		}
	}

	if _, _, err := store.ExportNativeBootblocks(); err == nil {
		t.Fatal("expected duplicate bootblock hash to fail")
	}
}

func TestListPromotedFailsClosedOnWrongStatus(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	candidate := mustExactCandidate(t, ExactCandidateInput{
		Family:        "WrongStatus",
		Kind:          KindFileSHA256,
		MalwareName:   "Wrong Status",
		SampleSHA256:  strings.Repeat("d", 64),
		SourceEngine:  "clamav",
		DetectionName: "Wrong.Status",
		Confidence:    ConfidenceSingleEngine,
		CreatedAt:     time.Unix(1, 0).UTC(),
	})
	encoded, err := marshalCandidate(candidate)
	if err != nil {
		t.Fatal(err)
	}
	path := store.Root + "/promoted/" + candidate.ID + ".json"
	if err := os.WriteFile(path, encoded, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListPromoted(); err == nil {
		t.Fatal("expected wrong promoted status to fail")
	}
}

func mustExactCandidate(t *testing.T, input ExactCandidateInput) Candidate {
	t.Helper()
	candidate, err := NewExactCandidate(input)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}
