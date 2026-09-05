package archive

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDecodeDMSWithExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake decoder is Unix-only")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "xdms")
	script := "#!/bin/sh\nprintf 'DOS\\001synthetic-adf'\n"
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}

	expanded, analysis, err := decodeDMSWithExecutable([]byte("DMS!synthetic"), fake)
	if err != nil {
		t.Fatal(err)
	}
	if string(expanded) != "DOS\x01synthetic-adf" {
		t.Fatalf("unexpected expanded data %q", expanded)
	}
	if analysis.Format != "dms" || analysis.ExpandedSize != int64(len(expanded)) || len(analysis.Members) != 1 {
		t.Fatalf("unexpected DMS analysis: %+v", analysis)
	}
	if analysis.Members[0].Format != "adf" || len(analysis.Members[0].SHA256) != 64 {
		t.Fatalf("unexpected DMS member: %+v", analysis.Members[0])
	}
}

func TestDecodeDMSRejectsInvalidMagic(t *testing.T) {
	if _, _, err := decodeDMSWithExecutable([]byte("not-dms"), "xdms"); err == nil {
		t.Fatal("expected invalid DMS error")
	}
}

func TestDecodeDMSReportsMissingExecutable(t *testing.T) {
	if _, _, err := decodeDMSWithExecutable([]byte("DMS!synthetic"), filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected missing decoder error")
	}
}
