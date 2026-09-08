package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidencebundle"
)

const (
	defaultEvidenceTrustStateRoot = "/data/aaa/state/evidence-trust"
	trustUpdateStateFilename      = "trust-update-state.json"
	maxTrustUpdateStateBytes      = 4096
)

func runTrustUpdateInstall(args []string, stdout, stderr io.Writer) error {
	fs := newTrustUpdateInstallFlagSet(stderr)
	rootPublicPath := fs.String("root-public-key", "", "independently pinned root Ed25519 public key file")
	stateRoot := fs.String("state-root", defaultEvidenceTrustStateRoot, "persistent evidence trust state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 || *rootPublicPath == "" {
		return errors.New("requires --root-public-key <file> [--state-root <dir>] <trust-store.json> <update.json>")
	}

	rootKeyData, err := readSmallRegularFile(*rootPublicPath, maxEvidenceKeyFileBytes, "pinned root public key")
	if err != nil {
		return err
	}
	rootPublic, rootID, err := evidencebundle.ParsePublicKeyHexFile(rootKeyData)
	if err != nil {
		return err
	}

	current, err := loadInstalledTrustState(*stateRoot)
	if err != nil {
		return err
	}
	if current != nil && current.RootKeyID != rootID {
		return fmt.Errorf("pinned root key id %s does not match installed state root key id %s", rootID, current.RootKeyID)
	}
	currentSequence := uint64(0)
	if current != nil {
		currentSequence = current.Sequence
	}

	storeData, err := readSmallRegularFile(fs.Arg(0), maxEvidenceTrustStoreBytes, "evidence trust store")
	if err != nil {
		return err
	}
	updateData, err := readSmallRegularFile(fs.Arg(1), maxEvidenceTrustUpdateBytes, "trust update")
	if err != nil {
		return err
	}
	update, err := evidencebundle.DecodeTrustUpdateStrict(updateData)
	if err != nil {
		return err
	}
	store, err := evidencebundle.VerifyTrustStoreUpdate(storeData, update, rootPublic, currentSequence)
	if err != nil {
		return err
	}

	installed, err := installVerifiedTrustStore(*stateRoot, storeData, update)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "installed trust update sequence=%d previous=%d keys=%d root-key-id=%s trust-store=%s\n", installed.Sequence, currentSequence, len(store.Keys), rootID, filepath.Join(*stateRoot, installed.TrustStoreFile))
	return nil
}

func runTrustUpdateStatus(args []string, stdout, stderr io.Writer) error {
	fs := newTrustUpdateStatusFlagSet(stderr)
	stateRoot := fs.String("state-root", defaultEvidenceTrustStateRoot, "persistent evidence trust state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("status takes no positional arguments")
	}
	state, err := loadInstalledTrustState(*stateRoot)
	if err != nil {
		return err
	}
	if state == nil {
		fmt.Fprintf(stdout, "no installed evidence trust state in %s\n", *stateRoot)
		return nil
	}
	fmt.Fprintf(stdout, "evidence trust state sequence=%d root-key-id=%s trust-store-sha256=%s trust-store=%s\n", state.Sequence, state.RootKeyID, state.TrustStoreSHA256, filepath.Join(*stateRoot, state.TrustStoreFile))
	return nil
}

func newTrustUpdateInstallFlagSet(stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("trust-update install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func newTrustUpdateStatusFlagSet(stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("trust-update status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func loadInstalledTrustState(root string) (*evidencebundle.TrustUpdateState, error) {
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("trust state root must be a real directory")
	}
	statePath := filepath.Join(root, trustUpdateStateFilename)
	data, err := readSmallRegularFile(statePath, maxTrustUpdateStateBytes, "trust update state")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	state, err := evidencebundle.DecodeTrustUpdateStateStrict(data)
	if err != nil {
		return nil, err
	}
	storePath := filepath.Join(root, state.TrustStoreFile)
	storeData, err := readSmallRegularFile(storePath, maxEvidenceTrustStoreBytes, "installed evidence trust store")
	if err != nil {
		return nil, fmt.Errorf("installed state is incomplete: %w", err)
	}
	sum := sha256.Sum256(storeData)
	if hex.EncodeToString(sum[:]) != state.TrustStoreSHA256 {
		return nil, errors.New("installed trust store SHA-256 does not match state")
	}
	if _, err := evidencebundle.DecodeTrustStoreStrict(storeData); err != nil {
		return nil, fmt.Errorf("installed trust store is invalid: %w", err)
	}
	return &state, nil
}

func installVerifiedTrustStore(root string, storeData []byte, update evidencebundle.TrustUpdate) (evidencebundle.TrustUpdateState, error) {
	if _, err := evidencebundle.DecodeTrustStoreStrict(storeData); err != nil {
		return evidencebundle.TrustUpdateState{}, err
	}
	if err := update.Validate(); err != nil {
		return evidencebundle.TrustUpdateState{}, err
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return evidencebundle.TrustUpdateState{}, err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return evidencebundle.TrustUpdateState{}, err
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return evidencebundle.TrustUpdateState{}, errors.New("trust state root must be a real directory")
	}

	storeFile, err := evidencebundle.TrustStoreFilename(update.Sequence)
	if err != nil {
		return evidencebundle.TrustUpdateState{}, err
	}
	storePath := filepath.Join(root, storeFile)
	if err := writeImmutableOrConfirm(storePath, storeData, 0o640); err != nil {
		return evidencebundle.TrustUpdateState{}, err
	}
	if err := syncDirectory(root); err != nil {
		return evidencebundle.TrustUpdateState{}, err
	}

	state := evidencebundle.TrustUpdateState{
		Schema:            evidencebundle.TrustUpdateStateSchema,
		Sequence:          update.Sequence,
		TrustStoreSHA256: update.TrustStoreSHA256,
		TrustStoreFile:   storeFile,
		RootKeyID:         update.RootKeyID,
	}
	stateData, err := state.MarshalDeterministic()
	if err != nil {
		return evidencebundle.TrustUpdateState{}, err
	}
	if err := atomicReplaceFile(filepath.Join(root, trustUpdateStateFilename), stateData, 0o640); err != nil {
		return evidencebundle.TrustUpdateState{}, err
	}
	if err := syncDirectory(root); err != nil {
		return evidencebundle.TrustUpdateState{}, err
	}
	return state, nil
}

func writeImmutableOrConfirm(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err == nil {
		remove := true
		defer func() {
			_ = f.Close()
			if remove {
				_ = os.Remove(path)
			}
		}()
		if _, err := f.Write(data); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		remove = false
		return nil
	}
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	existing, err := readSmallRegularFile(path, maxEvidenceTrustStoreBytes, "existing immutable trust store")
	if err != nil {
		return err
	}
	if !bytes.Equal(existing, data) {
		return errors.New("immutable trust store path already exists with different bytes")
	}
	return nil
}

func atomicReplaceFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".trust-update-state-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	remove := true
	defer func() {
		_ = tmp.Close()
		if remove {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
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
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	remove = false
	return nil
}

func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
