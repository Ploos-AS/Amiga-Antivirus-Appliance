package signaturefactory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	DistributionManifestFilename  = "manifest.json"
	DistributionSignatureFilename = "manifest.sig"
	maxDistributionManifestBytes  = 1 << 20
)

// VerifyDistributionBundle verifies the canonical manifest, its Ed25519
// signature, and every declared payload before returning success.
func VerifyDistributionBundle(root string, trusted *TrustedDistributionKeys) (DistributionManifest, string, error) {
	if root == "" {
		return DistributionManifest{}, "", errors.New("distribution bundle root is required")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return DistributionManifest{}, "", fmt.Errorf("stat distribution bundle root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return DistributionManifest{}, "", errors.New("distribution bundle root must be a real directory")
	}

	manifestBytes, err := readDistributionMetadataFile(root, DistributionManifestFilename, maxDistributionManifestBytes)
	if err != nil {
		return DistributionManifest{}, "", err
	}
	manifest, err := DecodeDistributionManifestStrict(manifestBytes)
	if err != nil {
		return DistributionManifest{}, "", err
	}
	canonical, err := manifest.CanonicalBytes()
	if err != nil {
		return DistributionManifest{}, "", err
	}
	if !bytes.Equal(manifestBytes, canonical) {
		return DistributionManifest{}, "", errors.New("distribution manifest is not canonical")
	}

	signatureBytes, err := readDistributionMetadataFile(root, DistributionSignatureFilename, DistributionSignatureHexLength+1)
	if err != nil {
		return DistributionManifest{}, "", err
	}
	signature, err := decodeDistributionSignatureFile(signatureBytes)
	if err != nil {
		return DistributionManifest{}, "", err
	}
	if err := VerifyDistributionManifestSignature(manifest, signature, trusted); err != nil {
		return DistributionManifest{}, "", err
	}

	for _, payload := range manifest.Payloads {
		if err := verifyDistributionPayload(root, payload); err != nil {
			return DistributionManifest{}, "", err
		}
	}
	identity, err := manifest.SHA256()
	if err != nil {
		return DistributionManifest{}, "", err
	}
	return manifest, identity, nil
}

func decodeDistributionSignatureFile(data []byte) (string, error) {
	if len(data) != DistributionSignatureHexLength+1 || data[len(data)-1] != '\n' {
		return "", errors.New("manifest.sig must contain exactly one lowercase hexadecimal Ed25519 signature followed by newline")
	}
	signature := string(data[:len(data)-1])
	if strings.ContainsAny(signature, "\r\n") {
		return "", errors.New("manifest.sig contains unexpected line breaks")
	}
	return signature, nil
}

func readDistributionMetadataFile(root, name string, maxBytes int) ([]byte, error) {
	fullPath, err := secureDistributionPath(root, name)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("open distribution %s: %w", name, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat distribution %s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("distribution %s must be a regular file", name)
	}
	if info.Size() > int64(maxBytes) {
		return nil, fmt.Errorf("distribution %s exceeds size limit", name)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("read distribution %s: %w", name, err)
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("distribution %s exceeds size limit", name)
	}
	return data, nil
}

func verifyDistributionPayload(root string, payload DistributionPayload) error {
	if err := payload.Validate(); err != nil {
		return err
	}
	fullPath, err := secureDistributionPath(root, payload.Path)
	if err != nil {
		return fmt.Errorf("payload %q: %w", payload.Path, err)
	}
	file, err := os.Open(fullPath)
	if err != nil {
		return fmt.Errorf("open payload %q: %w", payload.Path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat payload %q: %w", payload.Path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("payload %q must be a regular file", payload.Path)
	}
	if info.Size() != payload.Size {
		return fmt.Errorf("payload %q size mismatch: got %d want %d", payload.Path, info.Size(), payload.Size)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("hash payload %q: %w", payload.Path, err)
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if actual != payload.SHA256 {
		return fmt.Errorf("payload %q sha256 mismatch: got %s want %s", payload.Path, actual, payload.SHA256)
	}
	return nil
}

func secureDistributionPath(root, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) || strings.Contains(relative, "\\") {
		return "", errors.New("distribution path must be a relative slash-separated path")
	}
	parts := strings.Split(relative, "/")
	current := root
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("distribution path contains unsafe segment")
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("distribution path traverses a symbolic link")
		}
	}
	return current, nil
}
