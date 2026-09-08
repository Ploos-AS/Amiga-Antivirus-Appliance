package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidencebundle"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidenceledger"
)

const maxLedgerCheckpointBytes = 4096

func runEvidenceLedgerCheckpoint(args []string, stdout, stderr io.Writer) error {
	if len(args) < 1 {
		return errors.New("ledger checkpoint requires a subcommand: sign or verify")
	}
	switch args[0] {
	case "sign":
		return runEvidenceLedgerCheckpointSign(args[1:], stdout, stderr)
	case "verify":
		return runEvidenceLedgerCheckpointVerify(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown ledger checkpoint subcommand: %s", args[0])
	}
}

func runEvidenceLedgerCheckpointSign(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("evidence ledger checkpoint sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ledgerPath := fs.String("ledger", defaultEvidenceLedgerPath, "evidence ledger path")
	privateKeyPath := fs.String("private-key", "", "lowercase hex Ed25519 private key file")
	output := fs.String("output", "", "new detached checkpoint path (default: LEDGER.checkpoint.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *privateKeyPath == "" {
		return errors.New("requires --private-key <file>")
	}
	keyData, err := readSmallRegularFile(*privateKeyPath, maxEvidenceKeyFileBytes, "checkpoint private key")
	if err != nil {
		return err
	}
	privateKey, err := evidencebundle.ParsePrivateKeyHexFile(keyData)
	if err != nil {
		return err
	}
	ledger, err := readEvidenceLedgerBytes(*ledgerPath)
	if err != nil {
		return err
	}
	checkpoint, err := evidenceledger.BuildCheckpoint(ledger, privateKey)
	if err != nil {
		return err
	}
	data, err := checkpoint.MarshalDeterministic()
	if err != nil {
		return err
	}
	checkpointPath := *output
	if checkpointPath == "" {
		checkpointPath = *ledgerPath + ".checkpoint.json"
	}
	if err := writeNewFile(checkpointPath, data, 0o640); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "signed evidence ledger checkpoint %s sequence=%d tail-sha256=%s signer-key-id=%s\n", checkpointPath, checkpoint.Sequence, checkpoint.TailLineSHA256, checkpoint.SignerKeyID)
	return nil
}

func runEvidenceLedgerCheckpointVerify(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("evidence ledger checkpoint verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ledgerPath := fs.String("ledger", defaultEvidenceLedgerPath, "evidence ledger path")
	trustedKeyPath := fs.String("trusted-key", "", "lowercase hex trusted Ed25519 public key file")
	checkpointPath := fs.String("checkpoint", "", "checkpoint path (default: LEDGER.checkpoint.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *trustedKeyPath == "" {
		return errors.New("requires --trusted-key <file>")
	}
	keyData, err := readSmallRegularFile(*trustedKeyPath, maxEvidenceKeyFileBytes, "checkpoint trusted public key")
	if err != nil {
		return err
	}
	publicKey, trustedKeyID, err := evidencebundle.ParsePublicKeyHexFile(keyData)
	if err != nil {
		return err
	}
	path := *checkpointPath
	if path == "" {
		path = *ledgerPath + ".checkpoint.json"
	}
	checkpointData, err := readSmallRegularFile(path, maxLedgerCheckpointBytes, "ledger checkpoint")
	if err != nil {
		return err
	}
	checkpoint, err := evidenceledger.DecodeCheckpointStrict(checkpointData)
	if err != nil {
		return err
	}
	ledger, err := readEvidenceLedgerBytes(*ledgerPath)
	if err != nil {
		return err
	}
	if err := evidenceledger.VerifyLedgerAgainstCheckpoint(ledger, checkpoint, publicKey); err != nil {
		return err
	}
	verification, err := evidenceledger.Verify(ledger)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "verified evidence ledger checkpoint %s checkpoint-sequence=%d ledger-tail-sequence=%d signer-key-id=%s\n", path, checkpoint.Sequence, verification.TailSequence, trustedKeyID)
	return nil
}

func readEvidenceLedgerBytes(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		return nil, err
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()

	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return nil, errors.New("ledger must remain the same regular file while opened")
	}
	if opened.Size() > maxEvidenceLedgerBytes {
		return nil, errors.New("ledger exceeds 64 MiB limit")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxEvidenceLedgerBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxEvidenceLedgerBytes {
		return nil, errors.New("ledger exceeds 64 MiB limit")
	}
	finished, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != opened.Size() || finished.Size() != opened.Size() || !finished.ModTime().Equal(opened.ModTime()) {
		return nil, errors.New("ledger changed while reading")
	}
	if _, err := evidenceledger.Verify(data); err != nil {
		return nil, err
	}
	return data, nil
}
