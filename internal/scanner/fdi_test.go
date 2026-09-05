package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDetectFormatFDICandidate(t *testing.T) {
	if got := DetectFormat("disk.fdi", []byte("synthetic-fdi"), 13); got != "fdi" {
		t.Fatalf("got %q", got)
	}
}

func TestScanFDIFeedsDerivedADFThroughPipeline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake decoder is Unix-only")
	}

	dir := t.TempDir()
	derived := testADFImage()
	derivedPath := filepath.Join(dir, "derived.adf")
	if err := os.WriteFile(derivedPath, derived, 0600); err != nil {
		t.Fatal(err)
	}

	helper := filepath.Join(dir, "fdi-helper")
	header := fmt.Sprintf(`{"schema":1,"format":"fdi","decoder":"fake-fdi","decoder_version":"1.0","platform":"amiga","tracks":160,"derived_size":%d,"lossless_for_sector_scan":true}`, len(derived))
	script := "#!/bin/sh\nprintf '%s\\n' '" + header + "'\ncat \"$AAA_TEST_DERIVED\"\n"
	if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("AAA_TEST_DERIVED", derivedPath)
	t.Setenv("AAA_FDI_HELPER", helper)

	inputPath := filepath.Join(dir, "disk.fdi")
	if err := os.WriteFile(inputPath, []byte("synthetic-fdi-candidate"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := ScanFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != "fdi" || got.PreservationImage == nil {
		t.Fatalf("missing FDI preservation analysis: %+v", got)
	}
	if got.PreservationImage.Decoder != "fake-fdi" || got.PreservationImage.DerivedSectorImage == nil {
		t.Fatalf("unexpected preservation metadata: %+v", got.PreservationImage)
	}
	if got.PreservationImage.DerivedSectorImage.Size != int64(len(derived)) || len(got.PreservationImage.DerivedSectorImage.SHA256) != 64 {
		t.Fatalf("unexpected derived image metadata: %+v", got.PreservationImage.DerivedSectorImage)
	}
	if got.ADF == nil || got.Filesystem == nil {
		t.Fatalf("derived ADF did not reach native scanner pipeline: %+v", got)
	}
	if got.ADF.Filesystem != "FFS" || got.ADF.RootBlock != 880 || !got.ADF.ChecksumValid {
		t.Fatalf("unexpected derived ADF analysis: %+v", got.ADF)
	}
}

func TestScanFDIRequiresHelper(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "disk.fdi")
	if err := os.WriteFile(inputPath, []byte("synthetic-fdi-candidate"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AAA_FDI_HELPER", "")
	if _, err := ScanFile(inputPath); err == nil {
		t.Fatal("expected missing FDI helper to fail closed")
	}
}
