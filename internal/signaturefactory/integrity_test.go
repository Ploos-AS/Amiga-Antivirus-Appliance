package signaturefactory

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyFileSHA256AcceptsUnchangedFile(t *testing.T) {
	path, expected := writeIntegrityTarget(t, []byte("unchanged payload"))
	if err := VerifyFileSHA256(path, expected); err != nil {
		t.Fatalf("verify unchanged file: %v", err)
	}
}

func TestVerifyFileSHA256FailsClosedWhenFileChanges(t *testing.T) {
	path, expected := writeIntegrityTarget(t, []byte("original payload"))
	if err := os.WriteFile(path, []byte("changed payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFileSHA256(path, expected); err == nil || !strings.Contains(err.Error(), "input changed during scan") {
		t.Fatalf("expected changed-input error, got %v", err)
	}
}

func TestVerifyFileSHA256RejectsInvalidExpectedHash(t *testing.T) {
	path, _ := writeIntegrityTarget(t, []byte("payload"))
	if err := VerifyFileSHA256(path, "not-a-sha256"); err == nil {
		t.Fatal("expected invalid SHA-256 to fail closed")
	}
}

func TestVerifyFileSHA256RejectsNonRegularTarget(t *testing.T) {
	expected := strings.Repeat("0", 64)
	if err := VerifyFileSHA256(t.TempDir(), expected); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected regular-file error, got %v", err)
	}
}

func writeIntegrityTarget(t *testing.T, payload []byte) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	return path, hex.EncodeToString(sum[:])
}
