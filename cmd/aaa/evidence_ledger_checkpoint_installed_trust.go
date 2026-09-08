package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidenceledger"
)

func runEvidenceLedgerCheckpointVerifyInstalled(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("evidence ledger checkpoint verify-installed", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ledgerPath := fs.String("ledger", defaultEvidenceLedgerPath, "evidence ledger path")
	stateRoot := fs.String("state-root", defaultCheckpointTrustStateRoot, "authenticated checkpoint trust state directory")
	checkpointPath := fs.String("checkpoint", "", "checkpoint path (default: LEDGER.checkpoint.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("evidence ledger checkpoint verify-installed takes no positional arguments")
	}

	state, err := loadCheckpointTrustState(*stateRoot)
	if err != nil {
		return err
	}
	if state == nil {
		return fmt.Errorf("no authenticated checkpoint trust state installed in %s", *stateRoot)
	}
	storeData, err := readSmallRegularFile(filepath.Join(*stateRoot, state.TrustStoreFile), maxCheckpointTrustStoreBytes, "installed checkpoint trust store")
	if err != nil {
		return err
	}
	store, err := evidenceledger.DecodeCheckpointTrustStoreStrict(storeData)
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
	key, err := evidenceledger.VerifyLedgerAgainstCheckpointTrustStore(ledger, checkpoint, store, now().UTC())
	if err != nil {
		return err
	}
	verification, err := evidenceledger.Verify(ledger)
	if err != nil {
		return err
	}
	label := key.Label
	if label == "" {
		label = "-"
	}
	fmt.Fprintf(stdout, "verified evidence ledger checkpoint with installed trust %s checkpoint-sequence=%d ledger-tail-sequence=%d trust-sequence=%d signer-key-id=%s signer-label=%s\n", path, checkpoint.Sequence, verification.TailSequence, state.Sequence, key.KeyID, label)
	return nil
}
