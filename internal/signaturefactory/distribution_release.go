package signaturefactory

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const UnsignedDistributionSignerKeyID = "0000000000000000000000000000000000000000000000000000000000000000"

// BuildDistributionBundle copies the already-generated public signature
// databases into a new unsigned release bundle and writes a canonical manifest.
// Signing remains a separate explicit operation.
func BuildDistributionBundle(storeRoot, outputRoot, version string, createdAt time.Time) (DistributionManifest, error) {
	if storeRoot == "" {
		return DistributionManifest{}, errors.New("signature store root is required")
	}
	if outputRoot == "" {
		return DistributionManifest{}, errors.New("distribution bundle output is required")
	}
	if _, err := ParseReleaseVersion(version); err != nil {
		return DistributionManifest{}, err
	}
	if createdAt.IsZero() {
		return DistributionManifest{}, errors.New("distribution created_at is required")
	}
	createdAt = createdAt.UTC()

	sourceRoot := filepath.Join(storeRoot, "generated")
	if err := requireRealDirectory(sourceRoot); err != nil {
		return DistributionManifest{}, fmt.Errorf("generated signature root: %w", err)
	}
	if _, err := os.Lstat(outputRoot); err == nil {
		return DistributionManifest{}, errors.New("distribution bundle output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return DistributionManifest{}, fmt.Errorf("stat distribution bundle output: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outputRoot), 0o750); err != nil {
		return DistributionManifest{}, fmt.Errorf("create distribution bundle parent: %w", err)
	}
	if err := os.Mkdir(outputRoot, 0o750); err != nil {
		return DistributionManifest{}, fmt.Errorf("create distribution bundle output: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(outputRoot)
		}
	}()

	payloads := []DistributionPayload{
		{Target: DistributionTargetAAABootblocks, Path: "aaa/bootblocks.json"},
		{Target: DistributionTargetClamAVHashes, Path: "clamav/aaa.hsb"},
	}
	for i := range payloads {
		if err := copyDistributionFile(sourceRoot, outputRoot, payloads[i].Path); err != nil {
			return DistributionManifest{}, err
		}
		digest, size, err := distributionFileIdentity(outputRoot, payloads[i].Path)
		if err != nil {
			return DistributionManifest{}, err
		}
		payloads[i].SHA256 = digest
		payloads[i].Size = size
	}

	manifest := DistributionManifest{
		Schema:      DistributionSchemaVersion,
		Version:     version,
		CreatedAt:   createdAt,
		SignerKeyID: UnsignedDistributionSignerKeyID,
		Payloads:    payloads,
	}
	canonical, err := manifest.CanonicalBytes()
	if err != nil {
		return DistributionManifest{}, err
	}
	if err := os.WriteFile(filepath.Join(outputRoot, DistributionManifestFilename), canonical, 0o640); err != nil {
		return DistributionManifest{}, fmt.Errorf("write distribution manifest: %w", err)
	}
	complete = true
	return manifest, nil
}

// SignDistributionBundle binds the manifest to the supplied private key and
// writes manifest.sig. It does not generate, store, or retain private keys.
func SignDistributionBundle(root string, privateKey ed25519.PrivateKey) (DistributionManifest, string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return DistributionManifest{}, "", errors.New("invalid Ed25519 private key length")
	}
	if err := requireRealDirectory(root); err != nil {
		return DistributionManifest{}, "", err
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
	for _, payload := range manifest.Payloads {
		if err := verifyDistributionPayload(root, payload); err != nil {
			return DistributionManifest{}, "", err
		}
	}

	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return DistributionManifest{}, "", errors.New("derive Ed25519 public key")
	}
	keyID, err := DistributionKeyID(publicKey)
	if err != nil {
		return DistributionManifest{}, "", err
	}
	manifest.SignerKeyID = keyID
	canonical, err = manifest.CanonicalBytes()
	if err != nil {
		return DistributionManifest{}, "", err
	}
	signature, err := SignDistributionManifest(manifest, privateKey)
	if err != nil {
		return DistributionManifest{}, "", err
	}
	if err := writeDistributionFileAtomic(root, DistributionManifestFilename, canonical, 0o640); err != nil {
		return DistributionManifest{}, "", err
	}
	if err := writeDistributionFileAtomic(root, DistributionSignatureFilename, []byte(signature+"\n"), 0o640); err != nil {
		return DistributionManifest{}, "", err
	}
	identity, err := manifest.SHA256()
	if err != nil {
		return DistributionManifest{}, "", err
	}
	return manifest, identity, nil
}

func ParseDistributionPrivateKeyHexFile(data []byte) (ed25519.PrivateKey, error) {
	value, err := decodeSingleLowerHexLine(data, ed25519.PrivateKeySize*2, "Ed25519 private key")
	if err != nil {
		return nil, err
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, errors.New("Ed25519 private key must be lowercase hexadecimal")
	}
	return ed25519.PrivateKey(decoded), nil
}

func ParseDistributionPublicKeyHexFile(data []byte) (string, error) {
	return decodeSingleLowerHexLine(data, DistributionPublicKeyHexLength, "Ed25519 public key")
}

func decodeSingleLowerHexLine(data []byte, hexLength int, label string) (string, error) {
	if len(data) != hexLength+1 || data[len(data)-1] != '\n' {
		return "", fmt.Errorf("%s file must contain exactly one lowercase hexadecimal value followed by newline", label)
	}
	value := string(data[:len(data)-1])
	if strings.ToLower(value) != value || strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("%s file must contain lowercase hexadecimal", label)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", fmt.Errorf("%s file must contain lowercase hexadecimal", label)
	}
	return value, nil
}

func distributionFileIdentity(root, relative string) (string, int64, error) {
	fullPath, err := secureDistributionPath(root, relative)
	if err != nil {
		return "", 0, err
	}
	file, err := os.Open(fullPath)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() {
		return "", 0, errors.New("distribution payload must be a regular file")
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), info.Size(), nil
}

func requireRealDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("path must be a real directory")
	}
	return nil
}

func writeDistributionFileAtomic(root, name string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(root, "."+name+"-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		_ = tmp.Close()
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, filepath.Join(root, name)); err != nil {
		return err
	}
	keep = true
	return syncDirectory(root)
}
