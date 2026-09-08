package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidenceledger"
)

func TestEvidenceOperationsRecordIntegratedLedger(t *testing.T) {
	root := t.TempDir()
	artifactDir := filepath.Join(root, "artifacts")
	if err := os.MkdirAll(artifactDir, 0o750); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(artifactDir, "disk.adf")
	if err := os.WriteFile(artifact, []byte("amiga evidence"), 0o640); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "case.json")
	if err := runEvidenceCreate([]string{
		"--output", manifestPath,
		"--entry", "artifact:artifacts/disk.adf:" + artifact,
	}, &bytes.Buffer{}, &bytes.Buffer{}, time.Now); err != nil {
		t.Fatal(err)
	}

	ledger := filepath.Join(root, "ledger.jsonl")
	bundle := filepath.Join(root, "case.aaa-evidence.zip")
	if err := runEvidencePack([]string{
		"--manifest", manifestPath,
		"--root", root,
		"--output", bundle,
		"--ledger", ledger,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceVerifyBundle([]string{"--ledger", ledger, bundle}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(root, "signer.private")
	writeHexKeyFile(t, privatePath, privateKey)
	signaturePath := filepath.Join(root, "case.sig")
	if err := runEvidenceSign([]string{
		"--private-key", privatePath,
		"--output", signaturePath,
		"--ledger", ledger,
		bundle,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := evidenceledger.Verify(data)
	if err != nil {
		t.Fatal(err)
	}
	if verification.Records != 3 {
		t.Fatalf("ledger records=%d", verification.Records)
	}
	for _, want := range []string{
		`"event":"bundle-created"`,
		`"event":"bundle-verified"`,
		`"event":"bundle-signed"`,
		`"object_kind":"evidence-signature"`,
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("ledger missing %s: %s", want, data)
		}
	}
}

func TestTrustUpdateInstallRecordsIntegratedLedger(t *testing.T) {
	root := t.TempDir()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signerPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rootPrivatePath := filepath.Join(root, "root.private")
	rootPublicPath := filepath.Join(root, "root.public")
	storePath := filepath.Join(root, "trust-store.json")
	updatePath := filepath.Join(root, "trust-update.json")
	stateRoot := filepath.Join(root, "state")
	ledger := filepath.Join(root, "ledger.jsonl")
	writeHexKeyFile(t, rootPrivatePath, rootPrivate)
	writeHexKeyFile(t, rootPublicPath, rootPublic)
	writeTrustStoreFixture(t, storePath, signerPublic)
	if err := runTrustUpdateSign([]string{
		"--root-private-key", rootPrivatePath,
		"--sequence", "1",
		"--output", updatePath,
		storePath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := runTrustUpdateInstall([]string{
		"--root-public-key", rootPublicPath,
		"--state-root", stateRoot,
		"--ledger", ledger,
		storePath,
		updatePath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := evidenceledger.Verify(data)
	if err != nil {
		t.Fatal(err)
	}
	if verification.Records != 1 || !strings.Contains(string(data), `"event":"trust-store-installed"`) || !strings.Contains(string(data), `"object_kind":"evidence-trust-store"`) {
		t.Fatalf("unexpected ledger: %s", data)
	}
}

func TestIntegratedLedgerFailureDoesNotDeleteCompletedPrimaryArtifact(t *testing.T) {
	root := t.TempDir()
	artifact := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(artifact, []byte("sample"), 0o640); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(root, "manifest.json")
	if err := runEvidenceCreate([]string{
		"--output", manifest,
		"--entry", "artifact:sample.bin:" + artifact,
	}, &bytes.Buffer{}, &bytes.Buffer{}, time.Now); err != nil {
		t.Fatal(err)
	}
	ledger := filepath.Join(root, "invalid-ledger.jsonl")
	if err := os.WriteFile(ledger, []byte("partial"), 0o640); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(root, "bundle.zip")
	err := runEvidencePack([]string{
		"--manifest", manifest,
		"--root", root,
		"--output", bundle,
		"--ledger", ledger,
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "ledger append") {
		t.Fatalf("expected ledger failure, got %v", err)
	}
	if info, statErr := os.Stat(bundle); statErr != nil || !info.Mode().IsRegular() {
		t.Fatalf("completed bundle should remain for operator recovery: %v", statErr)
	}
}
