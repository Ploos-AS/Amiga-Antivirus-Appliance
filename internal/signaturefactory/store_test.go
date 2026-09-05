package signaturefactory

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreInitCreatesLayout(t *testing.T) {
	root := filepath.Join(t.TempDir(), "signatures")
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if store.Root != root {
		t.Fatalf("unexpected root %q", store.Root)
	}
	for _, rel := range []string{
		"candidates",
		"promoted",
		filepath.Join("generated", "aaa"),
		filepath.Join("generated", "clamav"),
		"rejected",
		"state",
	} {
		info, err := os.Stat(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("missing %s: %v", rel, err)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory", rel)
		}
	}
}

func TestStoreCandidateRoundTripAndIdempotence(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "signatures"))
	if err != nil {
		t.Fatal(err)
	}
	candidate := testStoreCandidate(t)

	path1, err := store.WriteCandidate(candidate)
	if err != nil {
		t.Fatal(err)
	}
	path2, err := store.WriteCandidate(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if path1 != path2 {
		t.Fatalf("idempotent write changed path: %q != %q", path1, path2)
	}

	got, err := store.ReadCandidate(candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != candidate.ID || got.SampleSHA256 != candidate.SampleSHA256 || got.CreatedAt != candidate.CreatedAt {
		t.Fatalf("unexpected round-trip candidate: %+v", got)
	}
}

func TestStoreRejectsConflictingCandidate(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "signatures"))
	if err != nil {
		t.Fatal(err)
	}
	candidate := testStoreCandidate(t)
	if _, err := store.WriteCandidate(candidate); err != nil {
		t.Fatal(err)
	}

	conflict := candidate
	conflict.DetectionName = "different-evidence"
	if _, err := store.WriteCandidate(conflict); !errors.Is(err, ErrCandidateConflict) {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

func TestStoreRejectsTraversalID(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "signatures"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadCandidate("../../escape"); err == nil {
		t.Fatal("expected traversal id to fail")
	}
}

func TestStoreRejectsUnknownJSONFields(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "signatures"))
	if err != nil {
		t.Fatal(err)
	}
	candidate := testStoreCandidate(t)
	path, err := store.candidatePath(candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	data := `{"schema":1,"id":"` + candidate.ID + `","status":"candidate","kind":"file-sha256","malware_name":"Test Virus","sample_sha256":"` + candidate.SampleSHA256 + `","source_engine":"aaa-native","detection_name":"test","confidence":"confirmed","created_at":"2026-09-05T12:00:00Z","created_by":"aaa-signature-factory","unexpected":true}`
	if err := os.WriteFile(path, []byte(data), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadCandidate(candidate.ID); err == nil {
		t.Fatal("expected unknown JSON field to fail")
	}
}

func testStoreCandidate(t *testing.T) Candidate {
	t.Helper()
	candidate, err := NewExactCandidate(ExactCandidateInput{
		Family:        "TestVirus",
		Kind:          KindFileSHA256,
		MalwareName:   "Test Virus",
		SampleSHA256:  strings.Repeat("ab", 32),
		SampleSize:    1234,
		Format:        "amiga-hunk-executable",
		SourceEngine:  "aaa-native",
		DetectionName: "synthetic-test-detection",
		Confidence:    ConfidenceConfirmed,
		CreatedAt:     time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}
