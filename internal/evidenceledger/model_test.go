package evidenceledger

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

const testObjectSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestBuildFirstRecordIsDeterministicAndZeroLinked(t *testing.T) {
	when := time.Date(2026, 9, 8, 10, 0, 0, 123456789, time.FixedZone("CEST", 2*60*60))
	record, err := BuildRecord(1, when, EventBundleCreated, ObjectEvidenceBundle, testObjectSHA, nil, "case A")
	if err != nil {
		t.Fatal(err)
	}
	if record.PreviousRecordSHA256 != ZeroLinkHash {
		t.Fatalf("previous hash = %s", record.PreviousRecordSHA256)
	}
	if record.RecordedAt.Location() != time.UTC {
		t.Fatalf("recorded_at location = %v", record.RecordedAt.Location())
	}
	first, err := record.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	second, err := record.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("deterministic marshal changed bytes")
	}
	if len(first) == 0 || first[len(first)-1] != '\n' {
		t.Fatal("record is not LF terminated")
	}
	if bytes.Contains(first, []byte("+02:00")) {
		t.Fatalf("recorded_at was not normalized to UTC: %s", first)
	}
}

func TestVerifyValidThreeRecordChain(t *testing.T) {
	ledger, lines := buildTestLedger(t, 3)
	result, err := Verify(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if result.Records != 3 || result.TailSequence != 3 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.TailLineSHA256 != sha256Hex(lines[2]) {
		t.Fatalf("tail line hash = %s", result.TailLineSHA256)
	}
	if result.TailRecordSHA256 == "" {
		t.Fatal("missing tail record hash")
	}
}

func TestVerifyRejectsModifiedRecord(t *testing.T) {
	ledger, _ := buildTestLedger(t, 2)
	tampered := bytes.Replace(ledger, []byte("note-1"), []byte("note-X"), 1)
	if _, err := Verify(tampered); err == nil || !strings.Contains(err.Error(), "record SHA-256") {
		t.Fatalf("expected record hash failure, got %v", err)
	}
}

func TestVerifyRejectsDeletedInteriorRecord(t *testing.T) {
	_, lines := buildTestLedger(t, 3)
	ledger := append(append([]byte(nil), lines[0]...), lines[2]...)
	if _, err := Verify(ledger); err == nil || !strings.Contains(err.Error(), "sequence") {
		t.Fatalf("expected sequence failure, got %v", err)
	}
}

func TestVerifyRejectsReorderedRecords(t *testing.T) {
	_, lines := buildTestLedger(t, 2)
	ledger := append(append([]byte(nil), lines[1]...), lines[0]...)
	if _, err := Verify(ledger); err == nil || !strings.Contains(err.Error(), "sequence") {
		t.Fatalf("expected sequence failure, got %v", err)
	}
}

func TestVerifyRejectsBrokenPreviousLink(t *testing.T) {
	_, lines := buildTestLedger(t, 2)
	line := bytes.Replace(lines[1], []byte(`"previous_record_sha256":"`+sha256Hex(lines[0])+`"`), []byte(`"previous_record_sha256":"`+ZeroLinkHash+`"`), 1)
	ledger := append(append([]byte(nil), lines[0]...), line...)
	if _, err := Verify(ledger); err == nil {
		t.Fatal("expected broken-link failure")
	}
}

func TestVerifyRejectsPartialFinalRecordAndBlankLine(t *testing.T) {
	ledger, _ := buildTestLedger(t, 1)
	if _, err := Verify(ledger[:len(ledger)-1]); err == nil || !strings.Contains(err.Error(), "partial final") {
		t.Fatalf("expected partial-final failure, got %v", err)
	}
	if _, err := Verify(append(append([]byte(nil), ledger...), '\n')); err == nil || !strings.Contains(err.Error(), "blank") {
		t.Fatalf("expected blank-line failure, got %v", err)
	}
}

func TestDecodeRecordStrictRejectsUnknownAndTrailingJSON(t *testing.T) {
	_, lines := buildTestLedger(t, 1)
	line := bytes.TrimSuffix(lines[0], []byte{'\n'})
	unknown := bytes.Replace(line, []byte(`"schema":`), []byte(`"unknown":1,"schema":`), 1)
	if _, err := DecodeRecordStrict(unknown); err == nil {
		t.Fatal("expected unknown-field failure")
	}
	trailing := append(append([]byte(nil), line...), []byte(` {}`)...)
	if _, err := DecodeRecordStrict(trailing); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("expected trailing JSON failure, got %v", err)
	}
}

func TestRecordValidationRejectsUnsupportedValuesAndBadHashes(t *testing.T) {
	record, err := BuildRecord(1, time.Date(2026, 9, 8, 8, 0, 0, 0, time.UTC), EventBundleCreated, ObjectEvidenceBundle, testObjectSHA, nil, "")
	if err != nil {
		t.Fatal(err)
	}

	badEvent := record
	badEvent.Event = Event("unknown")
	if err := badEvent.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported ledger event") {
		t.Fatalf("expected event failure, got %v", err)
	}

	badKind := record
	badKind.ObjectKind = ObjectKind("unknown")
	if err := badKind.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported ledger object kind") {
		t.Fatalf("expected kind failure, got %v", err)
	}

	badHash := record
	badHash.ObjectSHA256 = strings.ToUpper(testObjectSHA)
	if err := badHash.Validate(); err == nil || !strings.Contains(err.Error(), "object SHA-256") {
		t.Fatalf("expected hash failure, got %v", err)
	}
}

func TestBuildRecordEnforcesSequencePreviousBytesContract(t *testing.T) {
	when := time.Date(2026, 9, 8, 8, 0, 0, 0, time.UTC)
	if _, err := BuildRecord(0, when, EventBundleCreated, ObjectEvidenceBundle, testObjectSHA, nil, ""); err == nil {
		t.Fatal("expected zero-sequence failure")
	}
	if _, err := BuildRecord(1, when, EventBundleCreated, ObjectEvidenceBundle, testObjectSHA, []byte("previous\n"), ""); err == nil {
		t.Fatal("expected first-record previous-bytes failure")
	}
	if _, err := BuildRecord(2, when, EventBundleCreated, ObjectEvidenceBundle, testObjectSHA, nil, ""); err == nil {
		t.Fatal("expected missing previous-bytes failure")
	}
}

func TestNoteRejectsLineBreakingControlCharacters(t *testing.T) {
	when := time.Date(2026, 9, 8, 8, 0, 0, 0, time.UTC)
	for _, note := range []string{"a\nb", "a\rb", "a\x00b"} {
		if _, err := BuildRecord(1, when, EventBundleCreated, ObjectEvidenceBundle, testObjectSHA, nil, note); err == nil {
			t.Fatalf("expected note %q to fail", note)
		}
	}
}

func TestVerifyEmptyLedger(t *testing.T) {
	result, err := Verify(nil)
	if err != nil {
		t.Fatal(err)
	}
	if result != (Verification{}) {
		t.Fatalf("unexpected empty result: %+v", result)
	}
}

func buildTestLedger(t *testing.T, count int) ([]byte, [][]byte) {
	t.Helper()
	var ledger []byte
	var lines [][]byte
	var previous []byte
	for i := 1; i <= count; i++ {
		record, err := BuildRecord(
			uint64(i),
			time.Date(2026, 9, 8, 8, i, 0, 0, time.UTC),
			EventBundleCreated,
			ObjectEvidenceBundle,
			testObjectSHA,
			previous,
			"note-"+string(rune('0'+i)),
		)
		if err != nil {
			t.Fatal(err)
		}
		line, err := record.MarshalDeterministic()
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, append([]byte(nil), line...))
		ledger = append(ledger, line...)
		previous = line
	}
	return ledger, lines
}
