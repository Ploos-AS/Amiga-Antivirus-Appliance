package signaturefactory

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestListCandidatesSorted(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "signatures"))
	if err != nil {
		t.Fatal(err)
	}
	first := testStoreCandidate(t)
	second := first
	second.ID = "AAA.Amiga.TestVirus.ffffffffffffffff"
	second.SampleSHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := store.WriteCandidate(second); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteCandidate(first); err != nil {
		t.Fatal(err)
	}
	items, err := store.ListCandidates()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(items))
	}
	if items[0].ID > items[1].ID {
		t.Fatalf("candidates not sorted: %q > %q", items[0].ID, items[1].ID)
	}
}

func TestPromoteMovesCandidate(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "signatures"))
	if err != nil {
		t.Fatal(err)
	}
	candidate := testStoreCandidate(t)
	if _, err := store.WriteCandidate(candidate); err != nil {
		t.Fatal(err)
	}
	promoted, err := store.Promote(candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	if promoted.Status != StatusPromoted {
		t.Fatalf("unexpected status %q", promoted.Status)
	}
	if _, err := store.ReadCandidate(candidate.ID); err == nil {
		t.Fatal("candidate source still exists")
	}
	path := filepath.Join(store.Root, "promoted", candidate.ID+".json")
	data, err := os.ReadFile(path)
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

func TestRejectMovesCandidate(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "signatures"))
	if err != nil {
		t.Fatal(err)
	}
	candidate := testStoreCandidate(t)
	if _, err := store.WriteCandidate(candidate); err != nil {
		t.Fatal(err)
	}
	rejected, err := store.Reject(candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rejected.Status != StatusRejected {
		t.Fatalf("unexpected status %q", rejected.Status)
	}
	if _, err := os.Stat(filepath.Join(store.Root, "rejected", candidate.ID+".json")); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionRefusesConflictingDestination(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "signatures"))
	if err != nil {
		t.Fatal(err)
	}
	candidate := testStoreCandidate(t)
	if _, err := store.WriteCandidate(candidate); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Root, "promoted", candidate.ID+".json")
	if err := os.WriteFile(path, []byte("conflict\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Promote(candidate.ID); !errors.Is(err, ErrCandidateConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if _, err := store.ReadCandidate(candidate.ID); err != nil {
		t.Fatalf("source candidate should remain after conflict: %v", err)
	}
}

func TestValidateCandidatesFailsClosed(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "signatures"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Root, "candidates", "AAA.Amiga.Bad.0123456789abcdef.json"), []byte("{}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateCandidates(); err == nil {
		t.Fatal("expected malformed candidate validation failure")
	}
}
