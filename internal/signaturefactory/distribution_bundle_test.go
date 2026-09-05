package signaturefactory

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyDistributionBundleSuccess(t *testing.T) {
	root, manifest, trusted := writeDistributionBundleFixture(t)
	verified, identity, err := VerifyDistributionBundle(root, trusted)
	if err != nil {
		t.Fatalf("verify bundle: %v", err)
	}
	wantIdentity, err := manifest.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	if identity != wantIdentity || verified.Version != manifest.Version {
		t.Fatalf("unexpected verification result identity=%q manifest=%+v", identity, verified)
	}
}

func TestVerifyDistributionBundleRejectsChangedMissingAndWrongSizePayload(t *testing.T) {
	t.Run("changed payload", func(t *testing.T) {
		root, _, trusted := writeDistributionBundleFixture(t)
		path := filepath.Join(root, "aaa", "bootblocks.json")
		if err := os.WriteFile(path, []byte("tampered payload\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		if _, _, err := VerifyDistributionBundle(root, trusted); err == nil || !strings.Contains(err.Error(), "mismatch") {
			t.Fatalf("expected changed payload failure, got %v", err)
		}
	})

	t.Run("missing payload", func(t *testing.T) {
		root, _, trusted := writeDistributionBundleFixture(t)
		if err := os.Remove(filepath.Join(root, "clamav", "aaa.hsb")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := VerifyDistributionBundle(root, trusted); err == nil {
			t.Fatal("expected missing payload failure")
		}
	})

	t.Run("wrong declared size", func(t *testing.T) {
		root, manifest, trusted := writeDistributionBundleFixture(t)
		manifest.Payloads[0].Size++
		resignDistributionBundleManifest(t, root, &manifest, trustedFixturePrivateKey(t, root))
		if _, _, err := VerifyDistributionBundle(root, trusted); err == nil || !strings.Contains(err.Error(), "size mismatch") {
			t.Fatalf("expected size mismatch failure, got %v", err)
		}
	})
}

func TestVerifyDistributionBundleRejectsNonCanonicalManifestAndSignatureFile(t *testing.T) {
	t.Run("non canonical manifest", func(t *testing.T) {
		root, manifest, trusted := writeDistributionBundleFixture(t)
		manifest.Payloads[0], manifest.Payloads[1] = manifest.Payloads[1], manifest.Payloads[0]
		encoded, err := manifest.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		// Preserve valid JSON and semantics while making bytes non-canonical.
		nonCanonical := append([]byte(" \n"), encoded...)
		if err := os.WriteFile(filepath.Join(root, DistributionManifestFilename), nonCanonical, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, _, err := VerifyDistributionBundle(root, trusted); err == nil || !strings.Contains(err.Error(), "not canonical") {
			t.Fatalf("expected non-canonical failure, got %v", err)
		}
	})

	t.Run("signature missing newline", func(t *testing.T) {
		root, _, trusted := writeDistributionBundleFixture(t)
		path := filepath.Join(root, DistributionSignatureFilename)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data[:len(data)-1], 0o640); err != nil {
			t.Fatal(err)
		}
		if _, _, err := VerifyDistributionBundle(root, trusted); err == nil || !strings.Contains(err.Error(), "manifest.sig") {
			t.Fatalf("expected strict signature file failure, got %v", err)
		}
	})
}

func TestVerifyDistributionBundleRejectsSymlinkPayloadPath(t *testing.T) {
	root, _, trusted := writeDistributionBundleFixture(t)
	outside := t.TempDir()
	if err := os.RemoveAll(filepath.Join(root, "aaa")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "aaa")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, _, err := VerifyDistributionBundle(root, trusted); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected symlink traversal failure, got %v", err)
	}
}

func writeDistributionBundleFixture(t *testing.T) (string, DistributionManifest, *TrustedDistributionKeys) {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"aaa", "clamav"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	aaaPayload := []byte("bootblock database\n")
	clamavPayload := []byte("hash:0:AAA.Test\n")
	if err := os.WriteFile(filepath.Join(root, "aaa", "bootblocks.json"), aaaPayload, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "clamav", "aaa.hsb"), clamavPayload, 0o640); err != nil {
		t.Fatal(err)
	}

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
	setPayloadFixtureMetadata(t, &manifest, DistributionTargetAAABootblocks, aaaPayload)
	setPayloadFixtureMetadata(t, &manifest, DistributionTargetClamAVHashes, clamavPayload)
	resignDistributionBundleManifest(t, root, &manifest, privateKey)

	trusted, err := NewTrustedDistributionKeys(hex.EncodeToString(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	// The private key is test-only and kept outside the logical bundle files.
	if err := os.WriteFile(filepath.Join(root, ".fixture-private-key"), []byte(hex.EncodeToString(privateKey)), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, manifest, trusted
}

func setPayloadFixtureMetadata(t *testing.T, manifest *DistributionManifest, target DistributionTarget, data []byte) {
	t.Helper()
	sum := sha256.Sum256(data)
	for i := range manifest.Payloads {
		if manifest.Payloads[i].Target == target {
			manifest.Payloads[i].SHA256 = hex.EncodeToString(sum[:])
			manifest.Payloads[i].Size = int64(len(data))
			return
		}
	}
	t.Fatalf("fixture target %q not found", target)
}

func resignDistributionBundleManifest(t *testing.T, root string, manifest *DistributionManifest, privateKey ed25519.PrivateKey) {
	t.Helper()
	canonical, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignDistributionManifest(*manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, DistributionManifestFilename), canonical, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, DistributionSignatureFilename), []byte(signature+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
}

func trustedFixturePrivateKey(t *testing.T, root string) ed25519.PrivateKey {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, ".fixture-private-key"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := hex.DecodeString(string(data))
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.PrivateKey(decoded)
}
