package acquisition

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGreaseweazleReadADF(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "gw")
	script := `#!/bin/sh
set -eu
if [ "$1" = "--version" ]; then
  echo "gw 1.23"
  exit 0
fi
[ "$1" = "read" ]
printf 'fake gw acquisition log\n'
for last do :; done
printf 'ADF-FIXTURE' > "$last"
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "capture.adf")
	result, err := (Greaseweazle{Executable: fake, Device: "/dev/ttyACM0", Timeout: time.Second}).ReadADF(context.Background(), out)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("ADF-FIXTURE"))
	if result.Evidence.OutputSHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("sha=%s", result.Evidence.OutputSHA256)
	}
	if result.Evidence.OutputSize != int64(len("ADF-FIXTURE")) {
		t.Fatalf("size=%d", result.Evidence.OutputSize)
	}
	if result.Evidence.ToolVersion != "gw 1.23" {
		t.Fatalf("version=%q", result.Evidence.ToolVersion)
	}
	if result.Evidence.Device != "/dev/ttyACM0" {
		t.Fatalf("device=%q", result.Evidence.Device)
	}
	joined := strings.Join(result.Evidence.Command, " ")
	if !strings.Contains(joined, "read --format amiga.amigados --device /dev/ttyACM0") {
		t.Fatalf("command=%q", joined)
	}
	if !strings.Contains(result.RawLog, "fake gw acquisition log") {
		t.Fatalf("log=%q", result.RawLog)
	}
	if err := result.Evidence.Validate(); err != nil {
		t.Fatalf("evidence: %v", err)
	}
}

func TestGreaseweazleRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "existing.adf")
	if err := os.WriteFile(out, []byte("keep"), 0o640); err != nil {
		t.Fatal(err)
	}
	_, err := (Greaseweazle{Executable: filepath.Join(dir, "missing-gw")}).ReadADF(context.Background(), out)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("err=%v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep" {
		t.Fatalf("existing output changed: %q", data)
	}
}

func TestGreaseweazleFailureRemovesPartialOutput(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "gw")
	script := `#!/bin/sh
set -eu
if [ "$1" = "--version" ]; then
  echo "gw 1.23"
  exit 0
fi
for last do :; done
printf 'partial' > "$last"
echo 'read failed' >&2
exit 2
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "failed.adf")
	_, err := (Greaseweazle{Executable: fake, Timeout: time.Second}).ReadADF(context.Background(), out)
	if err == nil || !strings.Contains(err.Error(), "acquisition failed") {
		t.Fatalf("err=%v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("partial output remains: %v", statErr)
	}
}

func TestEvidenceValidationRejectsBadHash(t *testing.T) {
	now := time.Now().UTC()
	e := Evidence{
		Method:       "physical-floppy",
		Tool:         "greaseweazle",
		ToolVersion:  "gw 1.23",
		Format:       "adf",
		OutputName:   "disk.adf",
		OutputSHA256: "bad",
		OutputSize:   1,
		Command:      []string{"gw", "read"},
		StartedAt:    now,
		FinishedAt:   now,
	}
	if err := e.Validate(); err == nil {
		t.Fatal("expected invalid hash error")
	}
}
