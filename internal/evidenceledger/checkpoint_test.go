package evidenceledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

func TestCheckpointRoundTripAndLedgerVerification(t *testing.T) {
	ledger := checkpointTestLedger(t, 3)
	privateKey := checkpointTestPrivateKey()
	publicKey := privateKey.Public().(ed25519.PublicKey)

	checkpoint, err := BuildCheckpoint(ledger, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Sequence != 3 {
		t.Fatalf("sequence = %d", checkpoint.Sequence)
	}
	first, err := checkpoint.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	second, err := checkpoint.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("checkpoint serialization is not deterministic")
	}
	decoded, err := DecodeCheckpointStrict(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyLedgerAgainstCheckpoint(ledger, decoded, publicKey); err != nil {
		t.Fatal(err)
	}
}

func TestCheckpointAllowsLedgerExtension(t *testing.T) {
	shortLedger := checkpointTestLedger(t, 2)
	longLedger := checkpointTestLedger(t, 4)
	privateKey := checkpointTestPrivateKey()
	checkpoint, err := BuildCheckpoint(shortLedger, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyLedgerAgainstCheckpoint(longLedger, checkpoint, privateKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
}

func TestCheckpointRejectsSuffixRemoval(t *testing.T) {
	ledger := checkpointTestLedger(t, 3)
	privateKey := checkpointTestPrivateKey()
	checkpoint, err := BuildCheckpoint(ledger, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	shortLedger := checkpointTestLedger(t, 2)
	if err := VerifyLedgerAgainstCheckpoint(shortLedger, checkpoint, privateKey.Public().(ed25519.PublicKey)); err == nil || !strings.Contains(err.Error(), "before checkpoint sequence") {
		t.Fatalf("expected suffix-removal rejection, got %v", err)
	}
}

func TestCheckpointRejectsWrongKeyAndTamperedSignature(t *testing.T) {
	ledger := checkpointTestLedger(t, 1)
	privateKey := checkpointTestPrivateKey()
	checkpoint, err := BuildCheckpoint(ledger, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongSeed := sha256.Sum256([]byte("wrong-checkpoint-key"))
	wrongKey := ed25519.NewKeyFromSeed(wrongSeed[:])
	if err := VerifyCheckpointSignature(checkpoint, wrongKey.Public().(ed25519.PublicKey)); err == nil || !strings.Contains(err.Error(), "key ID") {
		t.Fatalf("expected wrong-key rejection, got %v", err)
	}

	tampered := checkpoint
	if tampered.Signature[0] == '0' {
		tampered.Signature = "1" + tampered.Signature[1:]
	} else {
		tampered.Signature = "0" + tampered.Signature[1:]
	}
	if err := VerifyCheckpointSignature(tampered, privateKey.Public().(ed25519.PublicKey)); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("expected signature rejection, got %v", err)
	}
}

func TestCheckpointStrictDecodeRejectsUnknownAndTrailingJSON(t *testing.T) {
	ledger := checkpointTestLedger(t, 1)
	checkpoint, err := BuildCheckpoint(ledger, checkpointTestPrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	data, err := checkpoint.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	unknown := bytes.Replace(data, []byte(`"schema":`), []byte(`"unknown":1,"schema":`), 1)
	if _, err := DecodeCheckpointStrict(unknown); err == nil {
		t.Fatal("expected unknown-field rejection")
	}
	trailing := append(append([]byte(nil), data...), []byte(`{}`)...)
	if _, err := DecodeCheckpointStrict(trailing); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("expected trailing-JSON rejection, got %v", err)
	}
}

func TestCheckpointRejectsEmptyLedger(t *testing.T) {
	if _, err := BuildCheckpoint(nil, checkpointTestPrivateKey()); err == nil || !strings.Contains(err.Error(), "empty ledger") {
		t.Fatalf("expected empty-ledger rejection, got %v", err)
	}
}

func checkpointTestPrivateKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("aaa-m14.3-checkpoint-test-key"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func checkpointTestLedger(t *testing.T, count int) []byte {
	t.Helper()
	var ledger []byte
	var previous []byte
	for i := 1; i <= count; i++ {
		record, err := BuildRecord(
			uint64(i),
			time.Date(2026, 9, 8, 10, i, 0, 0, time.UTC),
			EventBundleVerified,
			ObjectEvidenceBundle,
			testObjectSHA,
			previous,
			"checkpoint-test",
		)
		if err != nil {
			t.Fatal(err)
		}
		line, err := record.MarshalDeterministic()
		if err != nil {
			t.Fatal(err)
		}
		ledger = append(ledger, line...)
		previous = line
	}
	return ledger
}
