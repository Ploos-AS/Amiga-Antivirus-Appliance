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

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidenceledger"
)

func writeCheckpointTrustStoreFixture(t *testing.T, path string, public ed25519.PublicKey) {
	t.Helper()
	idSum := sha256.Sum256(public)
	store := evidenceledger.CheckpointTrustStore{
		Schema: evidenceledger.CheckpointTrustStoreSchema,
		Keys: []evidenceledger.CheckpointTrustKey{{
			KeyID:     hex.EncodeToString(idSum[:]),
			PublicKey: hex.EncodeToString(public),
			Status:    evidenceledger.CheckpointTrustKeyActive,
			Label:     "checkpoint signer",
		}},
	}
	data, err := store.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestCheckpointTrustUpdateCLIInstallReplayAndStatus(t *testing.T) {
	dir := t.TempDir()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signerPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rootPrivatePath := filepath.Join(dir, "root.private")
	rootPublicPath := filepath.Join(dir, "root.public")
	storePath := filepath.Join(dir, "checkpoint-trust.json")
	updatePath := filepath.Join(dir, "checkpoint-trust-update.json")
	stateRoot := filepath.Join(dir, "state")
	if err := os.WriteFile(rootPrivatePath, []byte(hex.EncodeToString(rootPrivate)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootPublicPath, []byte(hex.EncodeToString(rootPublic)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeCheckpointTrustStoreFixture(t, storePath, signerPublic)

	if err := runEvidenceLedgerCheckpointTrustUpdate([]string{
		"sign", "--root-private-key", rootPrivatePath, "--sequence", "1", "--output", updatePath, storePath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceLedgerCheckpointTrustUpdate([]string{
		"verify", "--root-public-key", rootPublicPath, storePath, updatePath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runEvidenceLedgerCheckpointTrustUpdate([]string{
		"install", "--root-public-key", rootPublicPath, "--state-root", stateRoot, storePath, updatePath,
	}, &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "sequence=1") {
		t.Fatalf("install output=%q", out.String())
	}
	if err := runEvidenceLedgerCheckpointTrustUpdate([]string{
		"install", "--root-public-key", rootPublicPath, "--state-root", stateRoot, storePath, updatePath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "not newer") {
		t.Fatalf("expected replay rejection, got %v", err)
	}
	out.Reset()
	if err := runEvidenceLedgerCheckpointTrustUpdate([]string{"status", "--state-root", stateRoot}, &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "sequence=1") || !strings.Contains(out.String(), "checkpoint-trust-store-00000000000000000001.json") {
		t.Fatalf("status output=%q", out.String())
	}
}

func TestCheckpointTrustStateRejectsTamperedInstalledStore(t *testing.T) {
	dir := t.TempDir()
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(nil)
	signerPublic, _, _ := ed25519.GenerateKey(nil)
	rootPrivatePath := filepath.Join(dir, "root.private")
	rootPublicPath := filepath.Join(dir, "root.public")
	storePath := filepath.Join(dir, "store.json")
	updatePath := filepath.Join(dir, "update.json")
	stateRoot := filepath.Join(dir, "state")
	_ = os.WriteFile(rootPrivatePath, []byte(hex.EncodeToString(rootPrivate)+"\n"), 0o600)
	_ = os.WriteFile(rootPublicPath, []byte(hex.EncodeToString(rootPublic)+"\n"), 0o600)
	writeCheckpointTrustStoreFixture(t, storePath, signerPublic)
	if err := runEvidenceLedgerCheckpointTrustUpdate([]string{"sign", "--root-private-key", rootPrivatePath, "--sequence", "2", "--output", updatePath, storePath}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceLedgerCheckpointTrustUpdate([]string{"install", "--root-public-key", rootPublicPath, "--state-root", stateRoot, storePath, updatePath}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(stateRoot, "checkpoint-trust-store-00000000000000000002.json")
	if err := os.WriteFile(installed, []byte("tampered\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCheckpointTrustState(stateRoot); err == nil {
		t.Fatal("tampered installed checkpoint trust store accepted")
	}
}
