package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidencebundle"
)

func TestRunEvidenceTrustValidate(t *testing.T) {
	root := t.TempDir()
	storePath := filepath.Join(root, "trust.json")
	key, _ := cliTrustKey(t, 21, evidencebundle.TrustKeyActive)
	store := evidencebundle.TrustStore{Schema: evidencebundle.TrustStoreSchema, Keys: []evidencebundle.TrustKey{key}}
	data, err := store.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storePath, data, 0o640); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runEvidenceTrust([]string{"validate", storePath}, &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "keys=1 active=1 revoked=0") {
		t.Fatalf("output=%q", out.String())
	}
}

func TestRunEvidenceVerifyTrustedAcceptsActiveAndRejectsRevoked(t *testing.T) {
	bundlePath, privateKey := createSignedTrustTestBundle(t)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := evidencebundle.KeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	trustKey := evidencebundle.TrustKey{
		KeyID:     keyID,
		PublicKey: hex.EncodeToString(publicKey),
		Status:    evidencebundle.TrustKeyActive,
		Label:     "release-2026",
	}
	storePath := filepath.Join(t.TempDir(), "trust.json")
	writeTrustStoreForTest(t, storePath, evidencebundle.TrustStore{Schema: evidencebundle.TrustStoreSchema, Keys: []evidencebundle.TrustKey{trustKey}})

	now := time.Date(2026, 9, 8, 5, 0, 0, 0, time.UTC)
	var out bytes.Buffer
	if err := runEvidenceVerifyTrusted([]string{"--trust-store", storePath, bundlePath}, &out, &bytes.Buffer{}, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "signer-label=release-2026") {
		t.Fatalf("output=%q", out.String())
	}

	revokedAt := now.Add(-time.Minute)
	trustKey.Status = evidencebundle.TrustKeyRevoked
	trustKey.RevokedAt = &revokedAt
	revokedPath := filepath.Join(t.TempDir(), "revoked.json")
	writeTrustStoreForTest(t, revokedPath, evidencebundle.TrustStore{Schema: evidencebundle.TrustStoreSchema, Keys: []evidencebundle.TrustKey{trustKey}})
	if err := runEvidenceVerifyTrusted([]string{"--trust-store", revokedPath, bundlePath}, &bytes.Buffer{}, &bytes.Buffer{}, func() time.Time { return now }); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("expected revoked signer rejection, got %v", err)
	}
}

func TestReadEvidenceTrustStoreRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	key, _ := cliTrustKey(t, 22, evidencebundle.TrustKeyActive)
	target := filepath.Join(root, "trust.json")
	writeTrustStoreForTest(t, target, evidencebundle.TrustStore{Schema: evidencebundle.TrustStoreSchema, Keys: []evidencebundle.TrustKey{key}})
	link := filepath.Join(root, "trust-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readEvidenceTrustStore(link); err == nil {
		t.Fatal("symlink trust store accepted")
	}
}

func cliTrustKey(t *testing.T, seedByte byte, status string) (evidencebundle.TrustKey, ed25519.PrivateKey) {
	t.Helper()
	seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := evidencebundle.KeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return evidencebundle.TrustKey{KeyID: keyID, PublicKey: hex.EncodeToString(publicKey), Status: status}, privateKey
}

func writeTrustStoreForTest(t *testing.T, path string, store evidencebundle.TrustStore) {
	t.Helper()
	data, err := store.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
}

func createSignedTrustTestBundle(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	root := t.TempDir()
	artifact := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(artifact, []byte("evidence"), 0o640); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	if err := runEvidenceCreate([]string{"--output", manifestPath, "--entry", "artifact:sample.bin:" + artifact}, &bytes.Buffer{}, &bytes.Buffer{}, time.Now); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "bundle.zip")
	if err := runEvidencePack([]string{"--manifest", manifestPath, "--root", root, "--output", bundlePath}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	_, privateKey := cliTrustKey(t, 23, evidencebundle.TrustKeyActive)
	privatePath := filepath.Join(t.TempDir(), "private.key")
	if err := os.WriteFile(privatePath, []byte(hex.EncodeToString(privateKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceSign([]string{"--private-key", privatePath, bundlePath}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	return bundlePath, privateKey
}
