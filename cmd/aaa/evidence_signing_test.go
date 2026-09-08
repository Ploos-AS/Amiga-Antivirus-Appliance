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
)

func prepareEvidenceSigningCLI(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	artifactDir := filepath.Join(root, "artifacts")
	if err := os.MkdirAll(artifactDir, 0o750); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(artifactDir, "disk.adf")
	if err := os.WriteFile(artifact, []byte("signed evidence"), 0o640); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(root, "manifest.json")
	if err := runEvidenceCreate([]string{
		"--output", manifest,
		"--entry", "artifact:artifacts/disk.adf:" + artifact,
	}, &bytes.Buffer{}, &bytes.Buffer{}, func() time.Time { return time.Date(2026, 9, 8, 4, 30, 0, 0, time.UTC) }); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(root, "case.aaa-evidence.zip")
	if err := runEvidencePack([]string{"--manifest", manifest, "--root", root, "--output", bundle}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	privatePath := filepath.Join(root, "evidence-private.key")
	publicPath := filepath.Join(root, "evidence-public.key")
	if err := os.WriteFile(privatePath, []byte(hex.EncodeToString(privateKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, []byte(hex.EncodeToString(publicKey)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return bundle, privatePath, publicPath
}

func TestRunEvidenceSignAndVerifySigned(t *testing.T) {
	bundle, privatePath, publicPath := prepareEvidenceSigningCLI(t)
	var signOut bytes.Buffer
	if err := runEvidenceSign([]string{"--private-key", privatePath, bundle}, &signOut, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(signOut.String(), "signer-key-id=") || !strings.Contains(signOut.String(), "bundle-sha256=") {
		t.Fatalf("sign output=%q", signOut.String())
	}
	if _, err := os.Stat(bundle + ".sig"); err != nil {
		t.Fatalf("missing detached signature: %v", err)
	}

	var verifyOut bytes.Buffer
	if err := runEvidenceVerifySigned([]string{"--trusted-key", publicPath, bundle}, &verifyOut, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verifyOut.String(), "verified signed evidence bundle") {
		t.Fatalf("verify output=%q", verifyOut.String())
	}
}

func TestRunEvidenceSignIsWriteOnce(t *testing.T) {
	bundle, privatePath, _ := prepareEvidenceSigningCLI(t)
	sigPath := bundle + ".sig"
	if err := os.WriteFile(sigPath, []byte("keep"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceSign([]string{"--private-key", privatePath, bundle}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("existing signature was overwritten")
	}
	data, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep" {
		t.Fatalf("existing signature changed: %q", data)
	}
}

func TestRunEvidenceVerifySignedRejectsWrongKeyAndTampering(t *testing.T) {
	bundle, privatePath, publicPath := prepareEvidenceSigningCLI(t)
	if err := runEvidenceSign([]string{"--private-key", privatePath, bundle}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	wrongSeed := make([]byte, ed25519.SeedSize)
	wrongSeed[0] = 42
	wrongPublic := ed25519.NewKeyFromSeed(wrongSeed).Public().(ed25519.PublicKey)
	wrongPublicPath := filepath.Join(filepath.Dir(bundle), "wrong-public.key")
	if err := os.WriteFile(wrongPublicPath, []byte(hex.EncodeToString(wrongPublic)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceVerifySigned([]string{"--trusted-key", wrongPublicPath, bundle}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("wrong trusted key was accepted")
	}

	f, err := os.OpenFile(bundle, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("tamper")); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceVerifySigned([]string{"--trusted-key", publicPath, bundle}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("tampered bundle was accepted")
	}
}

func TestEvidenceSigningRejectsSymlinkKeyAndSignature(t *testing.T) {
	bundle, privatePath, publicPath := prepareEvidenceSigningCLI(t)
	privateLink := filepath.Join(filepath.Dir(bundle), "private-link.key")
	if err := os.Symlink(privatePath, privateLink); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceSign([]string{"--private-key", privateLink, bundle}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("symlink private key was accepted")
	}

	if err := runEvidenceSign([]string{"--private-key", privatePath, bundle}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	sigLink := filepath.Join(filepath.Dir(bundle), "signature-link.sig")
	if err := os.Symlink(bundle+".sig", sigLink); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceVerifySigned([]string{"--trusted-key", publicPath, "--signature", sigLink, bundle}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("symlink signature was accepted")
	}
}
