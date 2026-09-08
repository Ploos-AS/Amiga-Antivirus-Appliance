package evidenceledger

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestCheckpointTrustStoreResolveAndVerify(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ledger, _ := buildTestLedger(t, 2)
	checkpoint, err := BuildCheckpoint(ledger, private)
	if err != nil {
		t.Fatal(err)
	}
	store := CheckpointTrustStore{
		Schema: CheckpointTrustStoreSchema,
		Keys: []CheckpointTrustKey{{
			KeyID:     checkpointKeyID(public),
			PublicKey: hex.EncodeToString(public),
			Status:    CheckpointTrustKeyActive,
			Label:     "ledger checkpoint signer",
		}},
	}
	key, err := VerifyLedgerAgainstCheckpointTrustStore(ledger, checkpoint, store, time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if key.Label != "ledger checkpoint signer" {
		t.Fatalf("resolved label=%q", key.Label)
	}
}

func TestCheckpointTrustStoreRejectsRevokedUnknownAndValidityWindow(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ledger, _ := buildTestLedger(t, 1)
	checkpoint, err := BuildCheckpoint(ledger, private)
	if err != nil {
		t.Fatal(err)
	}
	base := CheckpointTrustKey{
		KeyID:     checkpointKeyID(public),
		PublicKey: hex.EncodeToString(public),
		Status:    CheckpointTrustKeyActive,
	}
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

	revoked := base
	revoked.Status = CheckpointTrustKeyRevoked
	revoked.RevokedAt = &now
	if _, err := VerifyLedgerAgainstCheckpointTrustStore(ledger, checkpoint, CheckpointTrustStore{Schema: CheckpointTrustStoreSchema, Keys: []CheckpointTrustKey{revoked}}, now); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("expected revoked failure, got %v", err)
	}

	otherPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	unknown := base
	unknown.KeyID = checkpointKeyID(otherPublic)
	unknown.PublicKey = hex.EncodeToString(otherPublic)
	if _, err := VerifyLedgerAgainstCheckpointTrustStore(ledger, checkpoint, CheckpointTrustStore{Schema: CheckpointTrustStoreSchema, Keys: []CheckpointTrustKey{unknown}}, now); err == nil || !strings.Contains(err.Error(), "not present") {
		t.Fatalf("expected unknown signer failure, got %v", err)
	}

	future := base
	notBefore := now.Add(time.Hour)
	future.NotBefore = &notBefore
	if _, err := VerifyLedgerAgainstCheckpointTrustStore(ledger, checkpoint, CheckpointTrustStore{Schema: CheckpointTrustStoreSchema, Keys: []CheckpointTrustKey{future}}, now); err == nil || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("expected not-yet-valid failure, got %v", err)
	}

	expired := base
	notAfter := now
	expired.NotAfter = &notAfter
	if _, err := VerifyLedgerAgainstCheckpointTrustStore(ledger, checkpoint, CheckpointTrustStore{Schema: CheckpointTrustStoreSchema, Keys: []CheckpointTrustKey{expired}}, now); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired failure, got %v", err)
	}
}

func TestCheckpointTrustStoreStrictDeterministicAndRoleSeparated(t *testing.T) {
	publicA, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	publicB, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	store := CheckpointTrustStore{
		Schema: CheckpointTrustStoreSchema,
		Keys: []CheckpointTrustKey{
			{KeyID: checkpointKeyID(publicB), PublicKey: hex.EncodeToString(publicB), Status: CheckpointTrustKeyActive},
			{KeyID: checkpointKeyID(publicA), PublicKey: hex.EncodeToString(publicA), Status: CheckpointTrustKeyActive},
		},
	}
	first, err := store.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("checkpoint trust-store serialization is not deterministic")
	}
	decoded, err := DecodeCheckpointTrustStoreStrict(first)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Schema != CheckpointTrustStoreSchema || len(decoded.Keys) != 2 {
		t.Fatalf("decoded store=%+v", decoded)
	}
	if _, err := DecodeCheckpointTrustStoreStrict([]byte(`{"schema":"aaa-evidence-trust-store-v1","keys":[]}`)); err == nil {
		t.Fatal("M13 evidence trust-store schema was accepted as checkpoint trust policy")
	}
	unknown := strings.Replace(string(first), `"schema":`, `"surprise":true,"schema":`, 1)
	if _, err := DecodeCheckpointTrustStoreStrict([]byte(unknown)); err == nil {
		t.Fatal("unknown checkpoint trust-store field accepted")
	}
	if _, err := DecodeCheckpointTrustStoreStrict(append(first, []byte("{}")...)); err == nil {
		t.Fatal("trailing checkpoint trust-store JSON accepted")
	}
}

func TestCheckpointTrustKeyValidation(t *testing.T) {
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key := CheckpointTrustKey{
		KeyID:     checkpointKeyID(public),
		PublicKey: hex.EncodeToString(public),
		Status:    CheckpointTrustKeyActive,
	}
	if err := key.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := key
	bad.KeyID = strings.Repeat("a", 64)
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected key-id mismatch, got %v", err)
	}
	bad = key
	bad.Status = "unknown"
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected status failure, got %v", err)
	}
}
