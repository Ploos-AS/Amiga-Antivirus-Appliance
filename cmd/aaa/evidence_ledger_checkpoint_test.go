package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidenceledger"
)

func TestEvidenceLedgerCheckpointSignVerifyAndSuffixRemoval(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "ledger.jsonl")
	object := filepath.Join(dir, "object.bin")
	if err := os.WriteFile(object, []byte("evidence-object"), 0o600); err != nil {
		t.Fatal(err)
	}
	objectSHA, _, err := hashRegularFile(object)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := appendEvidenceLedgerRecord(ledger, evidenceledger.EventBundleVerified, evidenceledger.ObjectEvidenceBundle, objectSHA, "checkpoint", time.Date(2026, 9, 8, 12, i, 0, 0, time.UTC)); err != nil {
			t.Fatal(err)
		}
	}

	seed := sha256.Sum256([]byte("aaa-m14.3-cli-test-key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	privatePath := filepath.Join(dir, "private.key")
	publicPath := filepath.Join(dir, "public.key")
	if err := os.WriteFile(privatePath, []byte(hex.EncodeToString(privateKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, []byte(hex.EncodeToString(publicKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	checkpointPath := filepath.Join(dir, "ledger.checkpoint.json")
	var out bytes.Buffer
	if err := runEvidenceLedgerCheckpoint([]string{"sign", "--ledger", ledger, "--private-key", privatePath, "--output", checkpointPath}, &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "sequence=3") {
		t.Fatalf("unexpected sign output: %s", out.String())
	}
	out.Reset()
	if err := runEvidenceLedgerCheckpoint([]string{"verify", "--ledger", ledger, "--trusted-key", publicPath, "--checkpoint", checkpointPath}, &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "checkpoint-sequence=3") {
		t.Fatalf("unexpected verify output: %s", out.String())
	}

	data, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	last := bytes.LastIndexByte(data[:len(data)-1], '\n')
	if last < 0 {
		t.Fatal("expected multiple ledger records")
	}
	if err := os.WriteFile(ledger, data[:last+1], 0o640); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceLedgerCheckpoint([]string{"verify", "--ledger", ledger, "--trusted-key", publicPath, "--checkpoint", checkpointPath}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "before checkpoint sequence") {
		t.Fatalf("expected suffix-removal rejection, got %v", err)
	}
}

func TestEvidenceLedgerCheckpointIsWriteOnce(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "ledger.jsonl")
	objectSHA := strings.Repeat("a", 64)
	if err := appendEvidenceLedgerRecord(ledger, evidenceledger.EventBundleCreated, evidenceledger.ObjectEvidenceBundle, objectSHA, "", time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("aaa-m14.3-write-once"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	privatePath := filepath.Join(dir, "private.key")
	if err := os.WriteFile(privatePath, []byte(hex.EncodeToString(privateKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	checkpointPath := filepath.Join(dir, "checkpoint.json")
	args := []string{"sign", "--ledger", ledger, "--private-key", privatePath, "--output", checkpointPath}
	if err := runEvidenceLedgerCheckpoint(args, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceLedgerCheckpoint(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected existing checkpoint output to be rejected")
	}
}

func TestEvidenceLedgerCheckpointTrustedLifecycle(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "ledger.jsonl")
	objectSHA := strings.Repeat("b", 64)
	if err := appendEvidenceLedgerRecord(ledger, evidenceledger.EventBundleVerified, evidenceledger.ObjectEvidenceBundle, objectSHA, "", time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("aaa-m14.5-trusted-checkpoint"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	privatePath := filepath.Join(dir, "private.key")
	if err := os.WriteFile(privatePath, []byte(hex.EncodeToString(privateKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	checkpointPath := filepath.Join(dir, "checkpoint.json")
	if err := runEvidenceLedgerCheckpoint([]string{"sign", "--ledger", ledger, "--private-key", privatePath, "--output", checkpointPath}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	keyID := sha256.Sum256(publicKey)
	store := evidenceledger.CheckpointTrustStore{
		Schema: evidenceledger.CheckpointTrustStoreSchema,
		Keys: []evidenceledger.CheckpointTrustKey{{
			KeyID:     hex.EncodeToString(keyID[:]),
			PublicKey: hex.EncodeToString(publicKey),
			Status:    evidenceledger.CheckpointTrustKeyActive,
			Label:     "checkpoint release signer",
		}},
	}
	storeData, err := store.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(dir, "checkpoint-trust.json")
	if err := os.WriteFile(storePath, storeData, 0o640); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runEvidenceLedgerCheckpoint([]string{"trust", "validate", storePath}, &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "active=1") {
		t.Fatalf("trust validate output=%q", out.String())
	}
	out.Reset()
	now := func() time.Time { return time.Date(2026, 9, 8, 13, 0, 0, 0, time.UTC) }
	if err := runEvidenceLedgerCheckpointVerifyTrusted([]string{"--ledger", ledger, "--trust-store", storePath, "--checkpoint", checkpointPath}, &out, &bytes.Buffer{}, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "signer-label=checkpoint release signer") {
		t.Fatalf("verify-trusted output=%q", out.String())
	}

	revokedAt := now()
	store.Keys[0].Status = evidenceledger.CheckpointTrustKeyRevoked
	store.Keys[0].RevokedAt = &revokedAt
	storeData, err = store.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storePath, storeData, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceLedgerCheckpointVerifyTrusted([]string{"--ledger", ledger, "--trust-store", storePath, "--checkpoint", checkpointPath}, &bytes.Buffer{}, &bytes.Buffer{}, now); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("expected revoked checkpoint signer rejection, got %v", err)
	}
}

func TestEvidenceLedgerCheckpointTrustRejectsEvidenceTrustStoreSchemaAndSymlink(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "wrong-store.json")
	if err := os.WriteFile(storePath, []byte("{\"schema\":\"aaa-evidence-trust-store-v1\",\"keys\":[]}"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceLedgerCheckpoint([]string{"trust", "validate", storePath}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("M13 evidence trust-store schema accepted for checkpoint trust")
	}
	link := filepath.Join(dir, "store-link.json")
	if err := os.Symlink(storePath, link); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceLedgerCheckpoint([]string{"trust", "validate", link}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("symlink checkpoint trust store accepted")
	}
}
