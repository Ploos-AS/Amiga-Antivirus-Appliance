package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidencebundle"
)

func writeHexKeyFile(t *testing.T, path string, key []byte) {
	t.Helper()
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTrustStoreFixture(t *testing.T, path string, public ed25519.PublicKey) {
	t.Helper()
	id, err := evidencebundle.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	store := evidencebundle.TrustStore{
		Schema: evidencebundle.TrustStoreSchema,
		Keys: []evidencebundle.TrustKey{{
			KeyID:     id,
			PublicKey: hex.EncodeToString(public),
			Status:    evidencebundle.TrustKeyActive,
			Label:     "release signer",
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

func TestRunTrustUpdateSignAndVerify(t *testing.T) {
	root := t.TempDir()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signerPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(root, "root.private")
	publicPath := filepath.Join(root, "root.public")
	storePath := filepath.Join(root, "trust-store.json")
	updatePath := filepath.Join(root, "trust-update.json")
	writeHexKeyFile(t, privatePath, rootPrivate)
	writeHexKeyFile(t, publicPath, rootPublic)
	writeTrustStoreFixture(t, storePath, signerPublic)

	var signOut bytes.Buffer
	if err := runTrustUpdateSign([]string{
		"--root-private-key", privatePath,
		"--sequence", "9",
		"--output", updatePath,
		storePath,
	}, &signOut, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(signOut.String(), "sequence=9") {
		t.Fatalf("sign output=%q", signOut.String())
	}

	var verifyOut bytes.Buffer
	if err := runTrustUpdateVerify([]string{
		"--root-public-key", publicPath,
		"--current-sequence", "8",
		storePath,
		updatePath,
	}, &verifyOut, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verifyOut.String(), "verified trust update sequence=9 previous=8") {
		t.Fatalf("verify output=%q", verifyOut.String())
	}
}

func TestRunTrustUpdateRejectsReplayAndIsWriteOnce(t *testing.T) {
	root := t.TempDir()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signerPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(root, "root.private")
	publicPath := filepath.Join(root, "root.public")
	storePath := filepath.Join(root, "trust-store.json")
	updatePath := filepath.Join(root, "trust-update.json")
	writeHexKeyFile(t, privatePath, rootPrivate)
	writeHexKeyFile(t, publicPath, rootPublic)
	writeTrustStoreFixture(t, storePath, signerPublic)

	args := []string{"--root-private-key", privatePath, "--sequence", "3", "--output", updatePath, storePath}
	if err := runTrustUpdateSign(args, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(updatePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := runTrustUpdateSign(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("existing update document overwritten")
	}
	after, err := os.ReadFile(updatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("existing update document changed")
	}
	if err := runTrustUpdateVerify([]string{
		"--root-public-key", publicPath,
		"--current-sequence", "3",
		storePath,
		updatePath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("replayed sequence accepted")
	}
}
