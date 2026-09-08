package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidencebundle"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidenceledger"
)

const (
	defaultCheckpointTrustStateRoot = "/data/aaa/state/checkpoint-trust"
	checkpointTrustStateFilename    = "checkpoint-trust-update-state.json"
	maxCheckpointTrustStoreBytes    = 1 << 20
	maxCheckpointTrustUpdateBytes   = 4096
	maxCheckpointTrustStateBytes    = 4096
)

func runEvidenceLedgerCheckpointTrustUpdate(args []string, stdout, stderr io.Writer) error {
	if len(args) < 1 {
		return errors.New("checkpoint trust-update requires a subcommand: sign, verify, install or status")
	}
	switch args[0] {
	case "sign":
		return runCheckpointTrustUpdateSign(args[1:], stdout, stderr)
	case "verify":
		return runCheckpointTrustUpdateVerify(args[1:], stdout, stderr)
	case "install":
		return runCheckpointTrustUpdateInstall(args[1:], stdout, stderr)
	case "status":
		return runCheckpointTrustUpdateStatus(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown checkpoint trust-update subcommand: %s", args[0])
	}
}

func runCheckpointTrustUpdateSign(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("evidence ledger checkpoint trust-update sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rootPrivatePath := fs.String("root-private-key", "", "checkpoint trust root Ed25519 private key")
	sequence := fs.Uint64("sequence", 0, "monotonic checkpoint trust update sequence")
	output := fs.String("output", "", "new checkpoint trust update document")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *rootPrivatePath == "" || *sequence == 0 || *output == "" {
		return errors.New("requires --root-private-key <file> --sequence <n> --output <update.json> <checkpoint-trust-store.json>")
	}
	storeData, err := readSmallRegularFile(fs.Arg(0), maxCheckpointTrustStoreBytes, "checkpoint trust store")
	if err != nil {
		return err
	}
	keyData, err := readSmallRegularFile(*rootPrivatePath, maxEvidenceKeyFileBytes, "checkpoint trust root private key")
	if err != nil {
		return err
	}
	privateKey, err := evidencebundle.ParsePrivateKeyHexFile(keyData)
	if err != nil {
		return err
	}
	update, err := evidenceledger.SignCheckpointTrustStore(storeData, *sequence, privateKey)
	if err != nil {
		return err
	}
	data, err := update.MarshalDeterministic()
	if err != nil {
		return err
	}
	if err := writeNewFile(*output, data, 0o640); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "signed checkpoint trust update sequence=%d root-key-id=%s trust-store-sha256=%s update=%s\n", update.Sequence, update.RootKeyID, update.TrustStoreSHA256, *output)
	return nil
}

func runCheckpointTrustUpdateVerify(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("evidence ledger checkpoint trust-update verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rootPublicPath := fs.String("root-public-key", "", "pinned checkpoint trust root Ed25519 public key")
	currentSequence := fs.Uint64("current-sequence", 0, "currently installed checkpoint trust sequence")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 || *rootPublicPath == "" {
		return errors.New("requires --root-public-key <file> [--current-sequence <n>] <checkpoint-trust-store.json> <update.json>")
	}
	rootData, err := readSmallRegularFile(*rootPublicPath, maxEvidenceKeyFileBytes, "checkpoint trust root public key")
	if err != nil {
		return err
	}
	rootPublic, rootID, err := evidencebundle.ParsePublicKeyHexFile(rootData)
	if err != nil {
		return err
	}
	storeData, err := readSmallRegularFile(fs.Arg(0), maxCheckpointTrustStoreBytes, "checkpoint trust store")
	if err != nil {
		return err
	}
	updateData, err := readSmallRegularFile(fs.Arg(1), maxCheckpointTrustUpdateBytes, "checkpoint trust update")
	if err != nil {
		return err
	}
	update, err := evidenceledger.DecodeCheckpointTrustUpdateStrict(updateData)
	if err != nil {
		return err
	}
	store, err := evidenceledger.VerifyCheckpointTrustStoreUpdate(storeData, update, rootPublic, *currentSequence)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "verified checkpoint trust update sequence=%d previous=%d keys=%d root-key-id=%s\n", update.Sequence, *currentSequence, len(store.Keys), rootID)
	return nil
}

func runCheckpointTrustUpdateInstall(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("evidence ledger checkpoint trust-update install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rootPublicPath := fs.String("root-public-key", "", "pinned checkpoint trust root Ed25519 public key")
	stateRoot := fs.String("state-root", defaultCheckpointTrustStateRoot, "persistent checkpoint trust state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 || *rootPublicPath == "" {
		return errors.New("requires --root-public-key <file> [--state-root <dir>] <checkpoint-trust-store.json> <update.json>")
	}
	rootData, err := readSmallRegularFile(*rootPublicPath, maxEvidenceKeyFileBytes, "checkpoint trust root public key")
	if err != nil {
		return err
	}
	rootPublic, rootID, err := evidencebundle.ParsePublicKeyHexFile(rootData)
	if err != nil {
		return err
	}
	current, err := loadCheckpointTrustState(*stateRoot)
	if err != nil {
		return err
	}
	if current != nil && current.RootKeyID != rootID {
		return fmt.Errorf("pinned checkpoint trust root key id %s does not match installed state root key id %s", rootID, current.RootKeyID)
	}
	currentSequence := uint64(0)
	if current != nil {
		currentSequence = current.Sequence
	}
	storeData, err := readSmallRegularFile(fs.Arg(0), maxCheckpointTrustStoreBytes, "checkpoint trust store")
	if err != nil {
		return err
	}
	updateData, err := readSmallRegularFile(fs.Arg(1), maxCheckpointTrustUpdateBytes, "checkpoint trust update")
	if err != nil {
		return err
	}
	update, err := evidenceledger.DecodeCheckpointTrustUpdateStrict(updateData)
	if err != nil {
		return err
	}
	store, err := evidenceledger.VerifyCheckpointTrustStoreUpdate(storeData, update, rootPublic, currentSequence)
	if err != nil {
		return err
	}
	installed, err := installCheckpointTrustStore(*stateRoot, storeData, update)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "installed checkpoint trust update sequence=%d previous=%d keys=%d root-key-id=%s trust-store=%s\n", installed.Sequence, currentSequence, len(store.Keys), rootID, filepath.Join(*stateRoot, installed.TrustStoreFile))
	return nil
}

func runCheckpointTrustUpdateStatus(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("evidence ledger checkpoint trust-update status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateRoot := fs.String("state-root", defaultCheckpointTrustStateRoot, "persistent checkpoint trust state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("checkpoint trust-update status takes no positional arguments")
	}
	state, err := loadCheckpointTrustState(*stateRoot)
	if err != nil {
		return err
	}
	if state == nil {
		fmt.Fprintf(stdout, "no installed checkpoint trust state in %s\n", *stateRoot)
		return nil
	}
	fmt.Fprintf(stdout, "checkpoint trust state sequence=%d root-key-id=%s trust-store-sha256=%s trust-store=%s\n", state.Sequence, state.RootKeyID, state.TrustStoreSHA256, filepath.Join(*stateRoot, state.TrustStoreFile))
	return nil
}

func loadCheckpointTrustState(root string) (*evidenceledger.CheckpointTrustUpdateState, error) {
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("checkpoint trust state root must be a real directory")
	}
	stateData, err := readSmallRegularFile(filepath.Join(root, checkpointTrustStateFilename), maxCheckpointTrustStateBytes, "checkpoint trust update state")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	state, err := evidenceledger.DecodeCheckpointTrustUpdateStateStrict(stateData)
	if err != nil {
		return nil, err
	}
	storeData, err := readSmallRegularFile(filepath.Join(root, state.TrustStoreFile), maxCheckpointTrustStoreBytes, "installed checkpoint trust store")
	if err != nil {
		return nil, fmt.Errorf("installed checkpoint trust state is incomplete: %w", err)
	}
	sum := sha256.Sum256(storeData)
	if hex.EncodeToString(sum[:]) != state.TrustStoreSHA256 {
		return nil, errors.New("installed checkpoint trust store SHA-256 does not match state")
	}
	if _, err := evidenceledger.DecodeCheckpointTrustStoreStrict(storeData); err != nil {
		return nil, fmt.Errorf("installed checkpoint trust store is invalid: %w", err)
	}
	return &state, nil
}

func installCheckpointTrustStore(root string, storeData []byte, update evidenceledger.CheckpointTrustUpdate) (evidenceledger.CheckpointTrustUpdateState, error) {
	if _, err := evidenceledger.DecodeCheckpointTrustStoreStrict(storeData); err != nil {
		return evidenceledger.CheckpointTrustUpdateState{}, err
	}
	if err := update.Validate(); err != nil {
		return evidenceledger.CheckpointTrustUpdateState{}, err
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return evidenceledger.CheckpointTrustUpdateState{}, err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return evidenceledger.CheckpointTrustUpdateState{}, err
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return evidenceledger.CheckpointTrustUpdateState{}, errors.New("checkpoint trust state root must be a real directory")
	}
	storeFile, err := evidenceledger.CheckpointTrustStoreFilename(update.Sequence)
	if err != nil {
		return evidenceledger.CheckpointTrustUpdateState{}, err
	}
	if err := writeImmutableOrConfirm(filepath.Join(root, storeFile), storeData, 0o640); err != nil {
		return evidenceledger.CheckpointTrustUpdateState{}, err
	}
	if err := syncDirectory(root); err != nil {
		return evidenceledger.CheckpointTrustUpdateState{}, err
	}
	state := evidenceledger.CheckpointTrustUpdateState{
		Schema:           evidenceledger.CheckpointTrustUpdateStateSchema,
		Sequence:         update.Sequence,
		TrustStoreSHA256: update.TrustStoreSHA256,
		TrustStoreFile:   storeFile,
		RootKeyID:        update.RootKeyID,
	}
	stateData, err := state.MarshalDeterministic()
	if err != nil {
		return evidenceledger.CheckpointTrustUpdateState{}, err
	}
	if err := atomicReplaceFile(filepath.Join(root, checkpointTrustStateFilename), stateData, 0o640); err != nil {
		return evidenceledger.CheckpointTrustUpdateState{}, err
	}
	if err := syncDirectory(root); err != nil {
		return evidenceledger.CheckpointTrustUpdateState{}, err
	}
	return state, nil
}
