package signaturefactory

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// VerifyFileSHA256 re-reads a regular file and verifies that its current
// contents still match the SHA-256 observed by the native AAA scan. It is
// intended as a fail-closed TOCTOU guard after an external scanner has run.
func VerifyFileSHA256(path, expected string) error {
	expected = strings.ToLower(strings.TrimSpace(expected))
	if len(expected) != sha256.Size*2 {
		return errors.New("expected SHA-256 must contain exactly 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return fmt.Errorf("expected SHA-256 is invalid: %w", err)
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open file for integrity verification: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat file for integrity verification: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("integrity verification target is not a regular file")
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("hash file for integrity verification: %w", err)
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != expected {
		return fmt.Errorf("input changed during scan: SHA-256 was %s, now %s", expected, actual)
	}
	return nil
}
