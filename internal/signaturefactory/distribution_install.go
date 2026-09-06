package signaturefactory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	DistributionInstallStateSchema = 1
	DistributionStateFilename       = "current.json"
)

type DistributionInstallState struct {
	Schema         int    `json:"schema"`
	Version        string `json:"version"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

func (s DistributionInstallState) Validate() error {
	if s.Schema != DistributionInstallStateSchema {
		return fmt.Errorf("unsupported distribution install state schema %d", s.Schema)
	}
	if _, err := ParseReleaseVersion(s.Version); err != nil {
		return err
	}
	if !validSHA256(s.ManifestSHA256) {
		return errors.New("distribution install state manifest_sha256 must be a lowercase sha256")
	}
	return nil
}

func (s DistributionInstallState) CanonicalBytes() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("encode distribution install state: %w", err)
	}
	return append(encoded, '\n'), nil
}

func DecodeDistributionInstallStateStrict(data []byte) (DistributionInstallState, error) {
	var state DistributionInstallState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return DistributionInstallState{}, fmt.Errorf("decode distribution install state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return DistributionInstallState{}, errors.New("decode distribution install state: trailing data")
		}
		return DistributionInstallState{}, fmt.Errorf("decode distribution install state trailing data: %w", err)
	}
	if err := state.Validate(); err != nil {
		return DistributionInstallState{}, err
	}
	canonical, err := state.CanonicalBytes()
	if err != nil {
		return DistributionInstallState{}, err
	}
	if !bytes.Equal(data, canonical) {
		return DistributionInstallState{}, errors.New("distribution install state is not canonical")
	}
	return state, nil
}

// InstallDistributionBundle verifies bundleRoot before making any persistent
// state change. A release is copied into distributions/<version>, verified
// again from its staged copy, and only then activated by atomically replacing
// current.json.
func InstallDistributionBundle(bundleRoot, storeRoot string, trusted *TrustedDistributionKeys) (DistributionInstallState, error) {
	manifest, identity, err := VerifyDistributionBundle(bundleRoot, trusted)
	if err != nil {
		return DistributionInstallState{}, err
	}
	incomingVersion, err := ParseReleaseVersion(manifest.Version)
	if err != nil {
		return DistributionInstallState{}, err
	}
	if storeRoot == "" {
		return DistributionInstallState{}, errors.New("distribution store root is required")
	}
	if err := ensureRealDirectory(storeRoot); err != nil {
		return DistributionInstallState{}, err
	}
	distributionsRoot := filepath.Join(storeRoot, "distributions")
	if err := ensureRealDirectory(distributionsRoot); err != nil {
		return DistributionInstallState{}, err
	}

	state := DistributionInstallState{
		Schema:         DistributionInstallStateSchema,
		Version:        manifest.Version,
		ManifestSHA256: identity,
	}
	currentPath := filepath.Join(storeRoot, DistributionStateFilename)
	current, haveCurrent, err := readDistributionInstallState(currentPath)
	if err != nil {
		return DistributionInstallState{}, err
	}
	if haveCurrent {
		currentVersion, err := ParseReleaseVersion(current.Version)
		if err != nil {
			return DistributionInstallState{}, err
		}
		switch incomingVersion.Compare(currentVersion) {
		case -1:
			return DistributionInstallState{}, fmt.Errorf("distribution downgrade from %s to %s is not allowed", current.Version, manifest.Version)
		case 0:
			if current.ManifestSHA256 != identity {
				return DistributionInstallState{}, fmt.Errorf("distribution version %s is already active with different manifest identity", manifest.Version)
			}
			installedRoot := filepath.Join(distributionsRoot, manifest.Version)
			installedManifest, installedIdentity, err := VerifyDistributionBundle(installedRoot, trusted)
			if err != nil {
				return DistributionInstallState{}, fmt.Errorf("verify active distribution %s: %w", manifest.Version, err)
			}
			if installedManifest.Version != manifest.Version || installedIdentity != identity {
				return DistributionInstallState{}, fmt.Errorf("active distribution %s does not match current state", manifest.Version)
			}
			return current, nil
		}
	}

	finalRoot := filepath.Join(distributionsRoot, manifest.Version)
	if info, err := os.Lstat(finalRoot); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return DistributionInstallState{}, fmt.Errorf("distribution version path %s is not a real directory", manifest.Version)
		}
		installedManifest, installedIdentity, err := VerifyDistributionBundle(finalRoot, trusted)
		if err != nil {
			return DistributionInstallState{}, fmt.Errorf("verify existing distribution %s: %w", manifest.Version, err)
		}
		if installedManifest.Version != manifest.Version || installedIdentity != identity {
			return DistributionInstallState{}, fmt.Errorf("distribution version %s already exists with different manifest identity", manifest.Version)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return DistributionInstallState{}, fmt.Errorf("stat distribution version %s: %w", manifest.Version, err)
	} else {
		if err := stageDistributionBundle(bundleRoot, distributionsRoot, manifest, trusted, identity); err != nil {
			return DistributionInstallState{}, err
		}
	}

	if err := writeDistributionInstallStateAtomic(currentPath, state); err != nil {
		return DistributionInstallState{}, err
	}
	return state, nil
}

func ensureRealDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o750); err != nil {
			return fmt.Errorf("create distribution directory %q: %w", path, err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("stat distribution directory %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("distribution directory %q must be a real directory", path)
	}
	return nil
}

func readDistributionInstallState(path string) (DistributionInstallState, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return DistributionInstallState{}, false, nil
	}
	if err != nil {
		return DistributionInstallState{}, false, fmt.Errorf("read distribution install state: %w", err)
	}
	state, err := DecodeDistributionInstallStateStrict(data)
	if err != nil {
		return DistributionInstallState{}, false, err
	}
	return state, true, nil
}

func stageDistributionBundle(sourceRoot, distributionsRoot string, manifest DistributionManifest, trusted *TrustedDistributionKeys, identity string) error {
	stageRoot, err := os.MkdirTemp(distributionsRoot, ".staging-"+manifest.Version+"-")
	if err != nil {
		return fmt.Errorf("create distribution staging directory: %w", err)
	}
	keepStage := false
	defer func() {
		if !keepStage {
			_ = os.RemoveAll(stageRoot)
		}
	}()

	files := []string{DistributionManifestFilename, DistributionSignatureFilename}
	for _, payload := range manifest.Payloads {
		files = append(files, payload.Path)
	}
	for _, relative := range files {
		if err := copyDistributionFile(sourceRoot, stageRoot, relative); err != nil {
			return err
		}
	}
	stagedManifest, stagedIdentity, err := VerifyDistributionBundle(stageRoot, trusted)
	if err != nil {
		return fmt.Errorf("verify staged distribution: %w", err)
	}
	if stagedManifest.Version != manifest.Version || stagedIdentity != identity {
		return errors.New("staged distribution identity changed during install")
	}
	if err := syncDirectory(stageRoot); err != nil {
		return err
	}

	finalRoot := filepath.Join(distributionsRoot, manifest.Version)
	if err := os.Rename(stageRoot, finalRoot); err != nil {
		return fmt.Errorf("activate staged distribution directory: %w", err)
	}
	keepStage = true
	return syncDirectory(distributionsRoot)
}

func copyDistributionFile(sourceRoot, targetRoot, relative string) error {
	sourcePath, err := secureDistributionPath(sourceRoot, relative)
	if err != nil {
		return fmt.Errorf("resolve source distribution path %q: %w", relative, err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("open source distribution file %q: %w", relative, err)
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return fmt.Errorf("stat source distribution file %q: %w", relative, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("source distribution file %q must be regular", relative)
	}

	targetPath := filepath.Join(targetRoot, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o750); err != nil {
		return fmt.Errorf("create target distribution directory: %w", err)
	}
	target, err := os.OpenFile(targetPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("create target distribution file %q: %w", relative, err)
	}
	ok := false
	defer func() {
		_ = target.Close()
		if !ok {
			_ = os.Remove(targetPath)
		}
	}()
	if _, err := io.Copy(target, source); err != nil {
		return fmt.Errorf("copy distribution file %q: %w", relative, err)
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("sync distribution file %q: %w", relative, err)
	}
	if err := target.Close(); err != nil {
		return fmt.Errorf("close distribution file %q: %w", relative, err)
	}
	ok = true
	return nil
}

func writeDistributionInstallStateAtomic(path string, state DistributionInstallState) error {
	data, err := state.CanonicalBytes()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".current-*.json")
	if err != nil {
		return fmt.Errorf("create temporary distribution install state: %w", err)
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		_ = tmp.Close()
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o640); err != nil {
		return fmt.Errorf("chmod temporary distribution install state: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temporary distribution install state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary distribution install state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary distribution install state: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("activate distribution install state: %w", err)
	}
	keep = true
	return syncDirectory(dir)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync %q: %w", path, err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync directory %q: %w", path, err)
	}
	return nil
}
