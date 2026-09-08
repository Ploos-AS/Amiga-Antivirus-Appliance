package evidencebundle

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func buildSignedArchiveFixture(t *testing.T) (string, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	root := t.TempDir()
	payload := []byte("portable evidence")
	name := "artifacts/disk.adf"
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o640); err != nil {
		t.Fatal(err)
	}
	manifest, err := Build("test", time.Date(2026, 9, 8, 4, 0, 0, 0, time.UTC), "", []Entry{validEntry(name, KindArtifact, payload)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "case.aaa-evidence.zip")
	if err := CreateArchive(manifest, root, archive); err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return archive, privateKey, publicKey
}

func TestSignAndVerifyArchive(t *testing.T) {
	archive, privateKey, publicKey := buildSignedArchiveFixture(t)
	sig, err := SignArchive(archive, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Schema != SignatureSchema || sig.Algorithm != SignatureAlgorithm {
		t.Fatalf("signature=%+v", sig)
	}
	keyID, err := KeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if sig.SignerKeyID != keyID {
		t.Fatalf("signer=%s want=%s", sig.SignerKeyID, keyID)
	}
	data, err := sig.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSignatureStrict(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedArchive(archive, decoded, publicKey); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySignedArchiveRejectsWrongKeyAndTampering(t *testing.T) {
	archive, privateKey, publicKey := buildSignedArchiveFixture(t)
	sig, err := SignArchive(archive, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	wrongSeed := make([]byte, ed25519.SeedSize)
	wrongSeed[0] = 99
	wrongPublic := ed25519.NewKeyFromSeed(wrongSeed).Public().(ed25519.PublicKey)
	if _, err := VerifySignedArchive(archive, sig, wrongPublic); err == nil {
		t.Fatal("signature verified with wrong trusted key")
	}

	f, err := os.OpenFile(archive, os.O_WRONLY|os.O_APPEND, 0)
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
	if _, err := VerifySignedArchive(archive, sig, publicKey); err == nil {
		t.Fatal("tampered archive verified")
	}
}

func TestDecodeSignatureStrictRejectsUnknownAndTrailingData(t *testing.T) {
	archive, privateKey, _ := buildSignedArchiveFixture(t)
	sig, err := SignArchive(archive, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	data, err := sig.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	unknown := strings.Replace(string(data), "\n}", ",\n  \"surprise\": true\n}", 1)
	if _, err := DecodeSignatureStrict([]byte(unknown)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := DecodeSignatureStrict(append(data, []byte("{}")...)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}

func TestKeyFilesUseStrictLowercaseHexLineFormat(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	privateData := []byte(hex.EncodeToString(privateKey) + "\n")
	publicData := []byte(hex.EncodeToString(publicKey) + "\n")
	parsedPrivate, err := ParsePrivateKeyHexFile(privateData)
	if err != nil {
		t.Fatal(err)
	}
	if !parsedPrivate.Equal(privateKey) {
		t.Fatal("private key changed during parse")
	}
	parsedPublic, keyID, err := ParsePublicKeyHexFile(publicData)
	if err != nil {
		t.Fatal(err)
	}
	if !parsedPublic.Equal(publicKey) || keyID == "" {
		t.Fatal("public key parse failed")
	}
	if _, err := ParsePrivateKeyHexFile([]byte(strings.ToUpper(hex.EncodeToString(privateKey)) + "\n")); err == nil {
		t.Fatal("uppercase private key accepted")
	}
	if _, _, err := ParsePublicKeyHexFile([]byte(hex.EncodeToString(publicKey))); err == nil {
		t.Fatal("public key without newline accepted")
	}
}
