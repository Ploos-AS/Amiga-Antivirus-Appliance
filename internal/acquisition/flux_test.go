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

func TestGreaseweazleReadSCPUsesRawFlux(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "gw")
	script := `#!/bin/sh
set -eu
if [ "$1" = "--version" ]; then
  echo "gw 1.23"
  exit 0
fi
[ "$1" = "read" ]
printf 'fake raw flux log\n'
for last do :; done
printf 'SCP-RAW-FLUX' > "$last"
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "capture.scp")
	result, err := (Greaseweazle{Executable: fake, Device: "/dev/ttyACM0", Timeout: time.Second}).ReadSCP(context.Background(), out)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("SCP-RAW-FLUX"))
	if result.Evidence.OutputSHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("sha=%s", result.Evidence.OutputSHA256)
	}
	if result.Evidence.Format != "scp-raw-flux" {
		t.Fatalf("format=%q", result.Evidence.Format)
	}
	joined := strings.Join(result.Evidence.Command, " ")
	if !strings.Contains(joined, "read --raw --format amiga.amigados") {
		t.Fatalf("command=%q", joined)
	}
	if !strings.Contains(result.RawLog, "fake raw flux log") {
		t.Fatalf("log=%q", result.RawLog)
	}
}

func TestGreaseweazleReadSCPRequiresSCPExtension(t *testing.T) {
	_, err := (Greaseweazle{}).ReadSCP(context.Background(), filepath.Join(t.TempDir(), "capture.adf"))
	if err == nil || !strings.Contains(err.Error(), "must use .scp") {
		t.Fatalf("err=%v", err)
	}
}

func TestGreaseweazleFluxFailureRemovesPartialOutput(t *testing.T) {
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
exit 2
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "failed.scp")
	_, err := (Greaseweazle{Executable: fake, Timeout: time.Second}).ReadSCP(context.Background(), out)
	if err == nil || !strings.Contains(err.Error(), "flux acquisition failed") {
		t.Fatalf("err=%v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("partial output remains: %v", statErr)
	}
}
