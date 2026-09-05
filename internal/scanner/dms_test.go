package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/adf"
)

func TestScanDMSFeedsExpandedADFThroughPipeline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake xDMS helper is Unix-only")
	}

	dir := t.TempDir()
	fake := filepath.Join(dir, "xdms")
	script := `#!/bin/sh
python3 -c 'import sys,struct
b=bytearray(901120)
b[0:4]=b"DOS\x01"
b[8:12]=struct.pack(">I",880)
sys.stdout.buffer.write(b)'
`
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AAA_XDMS", fake)

	path := filepath.Join(dir, "disk.dms")
	if err := os.WriteFile(path, []byte("DMS!synthetic"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != "dms" || got.Archive == nil || got.ADF == nil || got.Filesystem == nil {
		t.Fatalf("missing DMS pipeline analysis: %+v", got)
	}
	if got.Archive.Format != "dms" || got.Archive.ExpandedSize != adf.DDSize || len(got.Archive.Members) != 1 {
		t.Fatalf("unexpected DMS archive analysis: %+v", got.Archive)
	}
	if got.ADF.Filesystem != "FFS" || got.ADF.RootBlock != 880 {
		t.Fatalf("unexpected expanded DMS ADF analysis: %+v", got.ADF)
	}
}

func TestScanDMSFailsClosedWithoutDecoder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.dms")
	if err := os.WriteFile(path, []byte("DMS!synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AAA_XDMS", filepath.Join(t.TempDir(), "missing-xdms"))
	if _, err := ScanFile(path); err == nil {
		t.Fatal("expected DMS scan to fail without decoder")
	}
}
