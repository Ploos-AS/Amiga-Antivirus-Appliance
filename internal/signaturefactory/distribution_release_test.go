package signaturefactory

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildSignVerifyDistributionBundle(t *testing.T) {
	storeRoot := t.TempDir()
	generated := filepath.Join(storeRoot, "generated")
	if err := os.MkdirAll(filepath.Join(generated, "aaa"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(generated, "clamav"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(generated, "aaa", "bootblocks.json"), []byte("{}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(generated, "clamav", "aaa.hsb"), []byte("hash:0:AAA.Test\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	bundleRoot := filepath.Join(t.TempDir(), "bundle")
	createdAt := time.Date(2026, 9, 6, 3, 0, 0, 0, time.UTC)
	manifest, err := BuildDistributionBundle(storeRoot, bundleRoot, "1.2.3", createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SignerKeyID != UnsignedDistributionSignerKeyID {
		t.Fatalf("unexpected unsigned signer id %q", manifest.SignerKeyID)
	}
	if _, err := os.Stat(filepath.Join(bundleRoot, DistributionSignatureFilename)); !os.IsNotExist(err) {
		t.Fatalf("build unexpectedly created signature: %v", err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, identity, err := SignDistributionBundle(bundleRoot, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := DistributionKeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if signed.SignerKeyID != keyID {
		t.Fatalf("signer id got %q want %q", signed.SignerKeyID, keyID)
	}
	trusted, err := NewTrustedDistributionKeys(hex.EncodeToString(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	verified, verifiedIdentity, err := VerifyDistributionBundle(bundleRoot, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Version != "1.2.3" || verifiedIdentity != identity {
		t.Fatalf("verified bundle mismatch: version=%q identity=%q", verified.Version, verifiedIdentity)
	}
}

func TestBuildDistributionBundleRefusesExistingOutput(t *testing.T) {
	storeRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(storeRoot, "generated"), 0o750); err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	if _, err := BuildDistributionBundle(storeRoot, output, "1.0.0", time.Now().UTC()); err == nil {
		t.Fatal("expected existing output rejection")
	}
}

func TestDistributionKeyFilesAreStrict(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateText := []byte(hex.EncodeToString(privateKey) + "\n")
	parsedPrivate, err := ParseDistributionPrivateKeyHexFile(privateText)
	if err != nil {
		t.Fatal(err)
	}
	if !parsedPrivate.Equal(privateKey) {
		t.Fatal("private key parse changed key material")
	}
	publicText := []byte(hex.EncodeToString(publicKey) + "\n")
	parsedPublic, err := ParseDistributionPublicKeyHexFile(publicText)
	if err != nil {
		t.Fatal(err)
	}
	if parsedPublic != hex.EncodeToString(publicKey) {
		t.Fatal("public key parse changed key material")
	}
	if _, err := ParseDistributionPrivateKeyHexFile(privateText[:len(privateText)-1]); err == nil {
		t.Fatal("expected missing private-key newline rejection")
	}
	if _, err := ParseDistributionPublicKeyHexFile([]byte("ABC\n")); err == nil {
		t.Fatal("expected malformed public-key rejection")
	}
}
