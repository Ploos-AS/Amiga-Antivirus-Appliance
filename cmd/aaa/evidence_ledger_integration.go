package main

import (
	"fmt"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidenceledger"
)

func recordLedgerBundleCreated(ledgerPath, objectPath string, now time.Time) error {
	return recordIntegratedLedger(ledgerPath, evidenceledger.EventBundleCreated, evidenceledger.ObjectEvidenceBundle, objectPath, now)
}

func recordLedgerBundleVerified(ledgerPath, objectPath string, now time.Time) error {
	return recordIntegratedLedger(ledgerPath, evidenceledger.EventBundleVerified, evidenceledger.ObjectEvidenceBundle, objectPath, now)
}

func recordLedgerBundleSigned(ledgerPath, signaturePath string, now time.Time) error {
	return recordIntegratedLedger(ledgerPath, evidenceledger.EventBundleSigned, evidenceledger.ObjectEvidenceSignature, signaturePath, now)
}

func recordLedgerTrustStoreInstalled(ledgerPath, trustStorePath string, now time.Time) error {
	return recordIntegratedLedger(ledgerPath, evidenceledger.EventTrustStoreInstalled, evidenceledger.ObjectEvidenceTrustStore, trustStorePath, now)
}

func recordIntegratedLedger(ledgerPath string, event evidenceledger.Event, objectKind evidenceledger.ObjectKind, objectPath string, recordedAt time.Time) error {
	if ledgerPath == "" {
		return nil
	}
	objectSHA, _, err := hashRegularFile(objectPath)
	if err != nil {
		return fmt.Errorf("ledger object: %w", err)
	}
	if err := appendEvidenceLedgerRecord(ledgerPath, event, objectKind, objectSHA, "", recordedAt.UTC()); err != nil {
		return fmt.Errorf("ledger append: %w", err)
	}
	return nil
}
