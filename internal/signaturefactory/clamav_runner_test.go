package signaturefactory

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunClamAVWithExecutableInfected(t *testing.T) {
	target := writeClamAVTarget(t)
	executable := writeFakeClamAV(t, `
if [ "$1" = "--version" ]; then
  echo "ClamAV 1.4.2/27777/Fri Sep  5 00:00:00 2026"
  exit 0
fi
echo "$5: Win.Test.EICAR_HDB-1 FOUND"
exit 1
`)

	result, err := runClamAVWithExecutable(target, executable, time.Second)
	if err != nil {
		t.Fatalf("run ClamAV: %v", err)
	}
	if result.Verdict != "infected" {
		t.Fatalf("verdict = %q, want infected", result.Verdict)
	}
	if result.DetectionName != "Win.Test.EICAR_HDB-1" {
		t.Fatalf("detection = %q", result.DetectionName)
	}
	if result.EngineVersion != "1.4.2" || result.SignatureDBVersion != "27777" {
		t.Fatalf("unexpected provenance: %#v", result)
	}
	if result.Evidence == nil {
		t.Fatal("expected normalized evidence")
	}
	if result.Evidence.CorrelationKey != "clamav-db:27777" {
		t.Fatalf("correlation key = %q", result.Evidence.CorrelationKey)
	}
}

func TestRunClamAVWithExecutableClean(t *testing.T) {
	target := writeClamAVTarget(t)
	executable := writeFakeClamAV(t, `
if [ "$1" = "--version" ]; then
  echo "ClamAV 1.4.2/27777/Fri Sep  5 00:00:00 2026"
  exit 0
fi
echo "$5: OK"
exit 0
`)

	result, err := runClamAVWithExecutable(target, executable, time.Second)
	if err != nil {
		t.Fatalf("run ClamAV: %v", err)
	}
	if result.Verdict != "clean" {
		t.Fatalf("verdict = %q, want clean", result.Verdict)
	}
	if result.Evidence != nil || result.DetectionName != "" {
		t.Fatalf("clean scan produced detection evidence: %#v", result)
	}
}

func TestRunClamAVWithExecutableFailsClosedOnScannerError(t *testing.T) {
	target := writeClamAVTarget(t)
	executable := writeFakeClamAV(t, `
if [ "$1" = "--version" ]; then
  echo "ClamAV 1.4.2/27777/Fri Sep  5 00:00:00 2026"
  exit 0
fi
echo "permission denied" >&2
exit 2
`)

	_, err := runClamAVWithExecutable(target, executable, time.Second)
	if err == nil || !strings.Contains(err.Error(), "exit code 2") {
		t.Fatalf("expected scanner error, got %v", err)
	}
}

func TestRunClamAVWithExecutableTimesOut(t *testing.T) {
	target := writeClamAVTarget(t)
	executable := writeFakeClamAV(t, `
if [ "$1" = "--version" ]; then
  echo "ClamAV 1.4.2/27777/Fri Sep  5 00:00:00 2026"
  exit 0
fi
sleep 1
echo "$5: OK"
`)

	_, err := runClamAVWithExecutable(target, executable, 50*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("expected timeout, got %v", err)
	}
}

func TestRunClamAVWithExecutableRejectsNonRegularTarget(t *testing.T) {
	executable := writeFakeClamAV(t, "exit 0")
	_, err := runClamAVWithExecutable(t.TempDir(), executable, time.Second)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected regular-file validation error, got %v", err)
	}
}

func TestParseClamAVScanOutputRequiresResultLine(t *testing.T) {
	_, _, _, err := parseClamAVScanOutput("LibClamAV Warning: synthetic warning\n")
	if err == nil {
		t.Fatal("expected output without OK/FOUND to fail closed")
	}
}

func writeClamAVTarget(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(path, []byte("synthetic test payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFakeClamAV(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-clamscan")
	content := "#!/bin/sh\nset -eu\n" + body
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestClamAVCappedBuffer(t *testing.T) {
	buffer := &clamAVCappedBuffer{limit: 4}
	if _, err := buffer.Write([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	if _, err := buffer.Write([]byte("e")); err == nil {
		t.Fatal("expected cap error")
	}
	if !buffer.exceeded {
		t.Fatal("expected exceeded flag")
	}
	if !errors.Is(errors.New("x"), nil) {
		// keep the errors import exercised without coupling the test to messages
	}
}
