package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidenceledger"
)

func TestEvidenceLedgerAppendVerifyStatus(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "ledger.jsonl")
	object := filepath.Join(dir, "bundle.zip")
	if err := os.WriteFile(object, []byte("bundle-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Date(2026, 9, 8, 10, 30, 0, 0, time.UTC) }

	var stdout, stderr bytes.Buffer
	args := []string{"append", "--ledger", ledger, "--event", "bundle-created", "--object-kind", "evidence-bundle", "--object", object, "--note", "case A"}
	if err := runEvidenceLedger(args, &stdout, &stderr, now); err != nil {
		t.Fatal(err)
	}
	firstBytes, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := evidenceledger.Verify(firstBytes)
	if err != nil {
		t.Fatal(err)
	}
	if verification.Records != 1 || verification.TailSequence != 1 {
		t.Fatalf("unexpected first verification: %+v", verification)
	}
	sum := sha256.Sum256([]byte("bundle-bytes"))
	if !bytes.Contains(firstBytes, []byte(hex.EncodeToString(sum[:]))) {
		t.Fatal("ledger does not contain exact object SHA-256")
	}

	stdout.Reset()
	if err := runEvidenceLedger([]string{"append", "--ledger", ledger, "--event", "bundle-verified", "--object-kind", "evidence-bundle", "--object", object}, &stdout, &stderr, now); err != nil {
		t.Fatal(err)
	}
	secondBytes, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(secondBytes, firstBytes) {
		t.Fatal("second append rewrote existing ledger prefix")
	}
	verification, err = evidenceledger.Verify(secondBytes)
	if err != nil {
		t.Fatal(err)
	}
	if verification.Records != 2 || verification.TailSequence != 2 {
		t.Fatalf("unexpected second verification: %+v", verification)
	}

	stdout.Reset()
	if err := runEvidenceLedger([]string{"verify", "--ledger", ledger}, &stdout, &stderr, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "records=2") {
		t.Fatalf("verify output = %q", stdout.String())
	}
	stdout.Reset()
	if err := runEvidenceLedger([]string{"status", "--ledger", ledger}, &stdout, &stderr, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "tail-sequence=2") || !strings.Contains(stdout.String(), "tail-record-sha256=") {
		t.Fatalf("status output = %q", stdout.String())
	}
}

func TestEvidenceLedgerAppendRejectsInvalidExistingLedger(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "ledger.jsonl")
	object := filepath.Join(dir, "object")
	if err := os.WriteFile(object, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ledger, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(ledger)
	err := runEvidenceLedger([]string{"append", "--ledger", ledger, "--event", "bundle-created", "--object-kind", "evidence-bundle", "--object", object}, &bytes.Buffer{}, &bytes.Buffer{}, time.Now)
	if err == nil || !strings.Contains(err.Error(), "existing ledger is invalid") {
		t.Fatalf("expected invalid-ledger rejection, got %v", err)
	}
	after, _ := os.ReadFile(ledger)
	if !bytes.Equal(before, after) {
		t.Fatal("invalid ledger was modified")
	}
}

func TestEvidenceLedgerRejectsSymlinkObjectAndLedger(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("symlink behavior differs on Windows")
	}
	dir := t.TempDir()
	object := filepath.Join(dir, "object")
	objectLink := filepath.Join(dir, "object-link")
	if err := os.WriteFile(object, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(object, objectLink); err != nil {
		t.Fatal(err)
	}
	ledger := filepath.Join(dir, "ledger.jsonl")
	err := runEvidenceLedger([]string{"append", "--ledger", ledger, "--event", "bundle-created", "--object-kind", "evidence-bundle", "--object", objectLink}, &bytes.Buffer{}, &bytes.Buffer{}, time.Now)
	if err == nil {
		t.Fatal("expected symlink object rejection")
	}

	realLedger := filepath.Join(dir, "real-ledger.jsonl")
	if err := os.WriteFile(realLedger, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ledgerLink := filepath.Join(dir, "ledger-link.jsonl")
	if err := os.Symlink(realLedger, ledgerLink); err != nil {
		t.Fatal(err)
	}
	err = runEvidenceLedger([]string{"append", "--ledger", ledgerLink, "--event", "bundle-created", "--object-kind", "evidence-bundle", "--object", object}, &bytes.Buffer{}, &bytes.Buffer{}, time.Now)
	if err == nil || !strings.Contains(err.Error(), "same regular file") {
		t.Fatalf("expected symlink ledger rejection, got %v", err)
	}
}

func TestEvidenceLedgerStatusMissingAndInvalidValues(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "missing.jsonl")
	var stdout bytes.Buffer
	if err := runEvidenceLedger([]string{"status", "--ledger", ledger}, &stdout, &bytes.Buffer{}, time.Now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "no evidence ledger") {
		t.Fatalf("status output = %q", stdout.String())
	}
	object := filepath.Join(dir, "object")
	if err := os.WriteFile(object, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runEvidenceLedger([]string{"append", "--ledger", ledger, "--event", "unknown", "--object-kind", "evidence-bundle", "--object", object}, &bytes.Buffer{}, &bytes.Buffer{}, time.Now)
	if err == nil || !strings.Contains(err.Error(), "unsupported ledger event") {
		t.Fatalf("expected invalid event rejection, got %v", err)
	}
}
