package signaturefactory

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
)

func TestRecordClamAVResultCreatesCandidate(t *testing.T) {
	store := mustTestStore(t)
	scan := scanner.Result{
		SHA256: strings.Repeat("a", 64),
		Size:   1234,
		Format: "hunk",
	}
	clam := testClamAVInfected()
	createdAt := time.Unix(100, 0).UTC()

	candidate, created, err := RecordClamAVResult(store, scan, clam, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("created = false, want true")
	}
	if candidate.Kind != KindFileSHA256 {
		t.Fatalf("kind = %q", candidate.Kind)
	}
	if candidate.SampleSHA256 != scan.SHA256 {
		t.Fatalf("sample sha256 = %q", candidate.SampleSHA256)
	}
	if candidate.SourceEngine != "clamav" {
		t.Fatalf("source engine = %q", candidate.SourceEngine)
	}
	if candidate.Confidence != ConfidenceSingleEngine {
		t.Fatalf("confidence = %q", candidate.Confidence)
	}
	if len(candidate.Evidence) != 1 || candidate.Evidence[0].CorrelationKey != "clamav-db:27123" {
		t.Fatalf("unexpected evidence: %#v", candidate.Evidence)
	}
	stored, err := store.ReadCandidate(candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	equal, err := candidatesEqual(stored, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !equal {
		t.Fatal("stored candidate differs from returned candidate")
	}
}

func TestRecordClamAVResultCleanCreatesNothing(t *testing.T) {
	store := mustTestStore(t)
	candidate, created, err := RecordClamAVResult(store, scanner.Result{}, ClamAVScanResult{Verdict: "clean"}, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("created = true, want false")
	}
	if candidate.ID != "" {
		t.Fatalf("candidate id = %q, want empty", candidate.ID)
	}
}

func TestRecordClamAVResultRequiresNormalizedEvidence(t *testing.T) {
	store := mustTestStore(t)
	clam := testClamAVInfected()
	clam.Evidence = nil
	_, _, err := RecordClamAVResult(store, scanner.Result{SHA256: strings.Repeat("b", 64)}, clam, time.Unix(1, 0).UTC())
	if err == nil {
		t.Fatal("expected missing evidence to fail")
	}
}

func TestRecordClamAVResultRejectsInvalidSHA256(t *testing.T) {
	store := mustTestStore(t)
	for _, sha := range []string{"", "not-a-sha256"} {
		_, _, err := RecordClamAVResult(store, scanner.Result{SHA256: sha}, testClamAVInfected(), time.Unix(1, 0).UTC())
		if err == nil {
			t.Fatalf("sha256 %q unexpectedly accepted", sha)
		}
	}
}

func TestRecordClamAVResultExactRepeatIsIdempotent(t *testing.T) {
	store := mustTestStore(t)
	scan := scanner.Result{SHA256: strings.Repeat("c", 64), Size: 42, Format: "file"}
	clam := testClamAVInfected()
	createdAt := time.Unix(2, 0).UTC()

	first, created, err := RecordClamAVResult(store, scan, clam, createdAt)
	if err != nil || !created {
		t.Fatalf("first record: created=%t err=%v", created, err)
	}
	second, created, err := RecordClamAVResult(store, scan, clam, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("repeat created = true, want false")
	}
	equal, err := candidatesEqual(first, second)
	if err != nil {
		t.Fatal(err)
	}
	if !equal {
		t.Fatal("idempotent repeat returned different candidate")
	}
}

func TestRecordClamAVResultConflictingSameIDFails(t *testing.T) {
	store := mustTestStore(t)
	scan := scanner.Result{SHA256: strings.Repeat("d", 64), Size: 10, Format: "file"}
	clam := testClamAVInfected()

	first, created, err := RecordClamAVResult(store, scan, clam, time.Unix(3, 0).UTC())
	if err != nil || !created {
		t.Fatalf("first record: created=%t err=%v", created, err)
	}

	conflicting := first
	conflicting.CreatedAt = time.Unix(4, 0).UTC()
	if _, err := storePathOverwriteForTest(store, conflicting); err != nil {
		t.Fatal(err)
	}

	_, created, err = RecordClamAVResult(store, scan, clam, time.Unix(3, 0).UTC())
	if !errors.Is(err, ErrCandidateConflict) {
		t.Fatalf("err = %v, want ErrCandidateConflict", err)
	}
	if created {
		t.Fatal("conflicting repeat created = true")
	}
}

func mustTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testClamAVInfected() ClamAVScanResult {
	evidence := Evidence{
		Type:               "engine-detection",
		Detail:             "sample.bin: Win.Test FOUND",
		SourceEngine:       "clamav",
		SourceVersion:      "1.4.2",
		SignatureDBVersion: "27123",
		CorrelationKey:     "clamav-db:27123",
	}
	return ClamAVScanResult{
		Verdict:            "infected",
		DetectionName:      "Win.Test",
		EngineVersion:      "1.4.2",
		SignatureDBVersion: "27123",
		RawResult:          evidence.Detail,
		Evidence:           &evidence,
	}
}

func storePathOverwriteForTest(store *Store, candidate Candidate) (string, error) {
	path, err := store.candidatePath(candidate.ID)
	if err != nil {
		return "", err
	}
	encoded, err := marshalCandidate(candidate)
	if err != nil {
		return "", err
	}
	return path, writeTestFile(path, encoded)
}

func writeTestFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o640)
}
