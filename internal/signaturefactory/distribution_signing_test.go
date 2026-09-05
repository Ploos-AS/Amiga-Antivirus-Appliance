package signaturefactory

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDistributionSigningAndTrustedVerification(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := DistributionKeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	manifest := distributionManifestFixture()
	manifest.SignerKeyID = keyID

	signature, err := SignDistributionManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) != DistributionSignatureHexLength || signature != strings.ToLower(signature) {
		t.Fatalf("unexpected signature encoding %q", signature)
	}

	trusted, err := NewTrustedDistributionKeys(hex.EncodeToString(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDistributionManifestSignature(manifest, signature, trusted); err != nil {
		t.Fatalf("verify valid manifest signature: %v", err)
	}
}

func TestDistributionSigningRejectsWrongSignerKeyID(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := distributionManifestFixture()
	if _, err := SignDistributionManifest(manifest, privateKey); err == nil {
		t.Fatal("expected signer key id mismatch")
	}
}

func TestDistributionVerificationRejectsUnknownWrongAndChangedManifest(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := DistributionKeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	manifest := distributionManifestFixture()
	manifest.SignerKeyID = keyID
	signature, err := SignDistributionManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	emptyTrusted, err := NewTrustedDistributionKeys()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDistributionManifestSignature(manifest, signature, emptyTrusted); err == nil || !strings.Contains(err.Error(), "unknown signer") {
		t.Fatalf("expected unknown signer failure, got %v", err)
	}

	wrongPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongTrusted, err := NewTrustedDistributionKeys(hex.EncodeToString(wrongPublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDistributionManifestSignature(manifest, signature, wrongTrusted); err == nil || !strings.Contains(err.Error(), "unknown signer") {
		t.Fatalf("expected wrong key to fail closed, got %v", err)
	}

	trusted, err := NewTrustedDistributionKeys(hex.EncodeToString(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	changed := manifest
	changed.Version = "1.2.4"
	if err := VerifyDistributionManifestSignature(changed, signature, trusted); err == nil || !strings.Contains(err.Error(), "invalid distribution manifest signature") {
		t.Fatalf("expected changed manifest failure, got %v", err)
	}
}

func TestDistributionVerificationRejectsMalformedSignatureAndPublicKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := DistributionKeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	manifest := distributionManifestFixture()
	manifest.SignerKeyID = keyID
	signature, err := SignDistributionManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := NewTrustedDistributionKeys(hex.EncodeToString(publicKey))
	if err != nil {
		t.Fatal(err)
	}

	malformed := []string{"", signature[:len(signature)-2], strings.ToUpper(signature), strings.Repeat("zz", ed25519.SignatureSize)}
	for _, value := range malformed {
		if err := VerifyDistributionManifestSignature(manifest, value, trusted); err == nil {
			t.Fatalf("expected malformed signature %q to fail", value)
		}
	}

	badKeys := []string{"", "00", strings.ToUpper(hex.EncodeToString(publicKey)), strings.Repeat("zz", ed25519.PublicKeySize)}
	for _, value := range badKeys {
		if _, _, err := ParseDistributionPublicKeyHex(value); err == nil {
			t.Fatalf("expected malformed public key %q to fail", value)
		}
	}
}

func TestTrustedDistributionKeysAreDerivedAndIdempotent(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := hex.EncodeToString(publicKey)
	trusted, err := NewTrustedDistributionKeys(encoded)
	if err != nil {
		t.Fatal(err)
	}
	firstID, err := DistributionKeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := trusted.AddPublicKeyHex(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if firstID != secondID {
		t.Fatalf("key ids differ: %q %q", firstID, secondID)
	}
}

func TestDistributionSigningRejectsMalformedPrivateKey(t *testing.T) {
	manifest := distributionManifestFixture()
	if _, err := SignDistributionManifest(manifest, ed25519.PrivateKey(make([]byte, 12))); err == nil {
		t.Fatal("expected malformed private key failure")
	}
}
