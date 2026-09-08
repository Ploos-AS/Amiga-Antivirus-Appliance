package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidenceledger"
)

const (
	defaultEvidenceLedgerPath = "/data/aaa/state/evidence-ledger.jsonl"
	maxEvidenceLedgerBytes    = 64 << 20
)

func runEvidenceLedger(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	if len(args) < 1 {
		return errors.New("ledger requires a subcommand: append, verify, status or checkpoint")
	}
	switch args[0] {
	case "append":
		return runEvidenceLedgerAppend(args[1:], stdout, stderr, now)
	case "verify":
		return runEvidenceLedgerVerify(args[1:], stdout, stderr)
	case "status":
		return runEvidenceLedgerStatus(args[1:], stdout, stderr)
	case "checkpoint":
		return runEvidenceLedgerCheckpoint(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown ledger subcommand: %s", args[0])
	}
}

func runEvidenceLedgerAppend(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("evidence ledger append", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ledgerPath := fs.String("ledger", defaultEvidenceLedgerPath, "append-only evidence ledger path")
	event := fs.String("event", "", "ledger event type")
	objectKind := fs.String("object-kind", "", "ledger object kind")
	objectPath := fs.String("object", "", "regular file whose exact SHA-256 is recorded")
	note := fs.String("note", "", "operator metadata note")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *event == "" || *objectKind == "" || *objectPath == "" {
		return errors.New("requires --event <type> --object-kind <kind> --object <file>")
	}

	objectSHA, _, err := hashRegularFile(*objectPath)
	if err != nil {
		return fmt.Errorf("ledger object: %w", err)
	}
	if err := appendEvidenceLedgerRecord(*ledgerPath, evidenceledger.Event(*event), evidenceledger.ObjectKind(*objectKind), objectSHA, *note, now().UTC()); err != nil {
		return err
	}
	verification, err := readAndVerifyEvidenceLedger(*ledgerPath)
	if err != nil {
		return fmt.Errorf("post-append verification failed: %w", err)
	}
	fmt.Fprintf(stdout, "appended evidence ledger %s sequence=%d event=%s object-kind=%s object-sha256=%s tail-sha256=%s\n", *ledgerPath, verification.TailSequence, *event, *objectKind, objectSHA, verification.TailLineSHA256)
	return nil
}

func runEvidenceLedgerVerify(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("evidence ledger verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ledgerPath := fs.String("ledger", defaultEvidenceLedgerPath, "evidence ledger path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("ledger verify takes no positional arguments")
	}
	verification, err := readAndVerifyEvidenceLedger(*ledgerPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "verified evidence ledger %s records=%d tail-sequence=%d tail-sha256=%s\n", *ledgerPath, verification.Records, verification.TailSequence, verification.TailLineSHA256)
	return nil
}

func runEvidenceLedgerStatus(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("evidence ledger status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ledgerPath := fs.String("ledger", defaultEvidenceLedgerPath, "evidence ledger path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("ledger status takes no positional arguments")
	}
	if _, err := os.Lstat(*ledgerPath); errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(stdout, "no evidence ledger at %s\n", *ledgerPath)
		return nil
	} else if err != nil {
		return err
	}
	verification, err := readAndVerifyEvidenceLedger(*ledgerPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "evidence ledger %s records=%d tail-sequence=%d tail-sha256=%s tail-record-sha256=%s\n", *ledgerPath, verification.Records, verification.TailSequence, verification.TailLineSHA256, verification.TailRecordSHA256)
	return nil
}

func appendEvidenceLedgerRecord(path string, event evidenceledger.Event, objectKind evidenceledger.ObjectKind, objectSHA, note string, recordedAt time.Time) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()

	opened, err := f.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return errors.New("ledger path must remain the same regular file while opened")
	}
	if opened.Size() > maxEvidenceLedgerBytes {
		return errors.New("ledger exceeds 64 MiB limit")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxEvidenceLedgerBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxEvidenceLedgerBytes {
		return errors.New("ledger exceeds 64 MiB limit")
	}
	verification, err := evidenceledger.Verify(data)
	if err != nil {
		return fmt.Errorf("existing ledger is invalid: %w", err)
	}

	var previousLine []byte
	if len(data) > 0 {
		previousStart := bytes.LastIndexByte(data[:len(data)-1], '\n') + 1
		previousLine = append([]byte(nil), data[previousStart:]...)
	}
	record, err := evidenceledger.BuildRecord(verification.TailSequence+1, recordedAt, event, objectKind, objectSHA, previousLine, note)
	if err != nil {
		return err
	}
	line, err := record.MarshalDeterministic()
	if err != nil {
		return err
	}
	if int64(len(data)+len(line)) > maxEvidenceLedgerBytes {
		return errors.New("ledger append would exceed 64 MiB limit")
	}

	beforeWrite, err := f.Stat()
	if err != nil {
		return err
	}
	current, err = os.Lstat(path)
	if err != nil {
		return err
	}
	if !current.Mode().IsRegular() || !os.SameFile(beforeWrite, current) || beforeWrite.Size() != int64(len(data)) {
		return errors.New("ledger changed while append was prepared")
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return nil
}

func readAndVerifyEvidenceLedger(path string) (evidenceledger.Verification, error) {
	f, err := os.Open(path)
	if err != nil {
		return evidenceledger.Verification{}, err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		return evidenceledger.Verification{}, err
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()

	opened, err := f.Stat()
	if err != nil {
		return evidenceledger.Verification{}, err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return evidenceledger.Verification{}, err
	}
	if !opened.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return evidenceledger.Verification{}, errors.New("ledger must remain the same regular file while opened")
	}
	if opened.Size() > maxEvidenceLedgerBytes {
		return evidenceledger.Verification{}, errors.New("ledger exceeds 64 MiB limit")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxEvidenceLedgerBytes+1))
	if err != nil {
		return evidenceledger.Verification{}, err
	}
	if len(data) > maxEvidenceLedgerBytes {
		return evidenceledger.Verification{}, errors.New("ledger exceeds 64 MiB limit")
	}
	finished, err := f.Stat()
	if err != nil {
		return evidenceledger.Verification{}, err
	}
	if finished.Size() != opened.Size() || !finished.ModTime().Equal(opened.ModTime()) || int64(len(data)) != opened.Size() {
		return evidenceledger.Verification{}, errors.New("ledger changed while reading")
	}
	return evidenceledger.Verify(data)
}
