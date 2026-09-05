package preservation

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDecodeIPFWithExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake decoder is Unix-only")
	}
	dir := t.TempDir()
	derivedPath := filepath.Join(dir, "derived.adf")
	derived := []byte("DOS\x01synthetic-sector-view")
	if err := os.WriteFile(derivedPath, derived, 0600); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(dir, "ipf-helper")
	script := "#!/bin/sh\nprintf '%s\\n' '{\"schema\":1,\"format\":\"ipf\",\"decoder\":\"fake-caps\",\"decoder_version\":\"1.0\",\"platform\":\"amiga\",\"tracks\":160,\"derived_size\":25,\"lossless_for_sector_scan\":true}'\ncat \"$AAA_TEST_DERIVED\"\n"
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AAA_TEST_DERIVED", derivedPath)

	got, analysis, err := decodeIPFWithExecutable([]byte("synthetic-ipf"), fake, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(derived) {
		t.Fatalf("unexpected derived data %q", got)
	}
	if analysis.Format != "ipf" || analysis.Decoder != "fake-caps" || analysis.DecoderVersion != "1.0" || analysis.Platform != "amiga" || analysis.Tracks != 160 {
		t.Fatalf("unexpected analysis: %+v", analysis)
	}
	if analysis.DerivedSectorImage == nil || analysis.DerivedSectorImage.Size != int64(len(derived)) || len(analysis.DerivedSectorImage.SHA256) != 64 || !analysis.DerivedSectorImage.LosslessForSectorScan {
		t.Fatalf("unexpected derived metadata: %+v", analysis.DerivedSectorImage)
	}
}

func TestDecodeIPFRejectsFormatMismatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake decoder is Unix-only")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "ipf-helper")
	script := "#!/bin/sh\nprintf '%s\\n' '{\"schema\":1,\"format\":\"not-ipf\",\"decoder\":\"fake\",\"derived_size\":0,\"lossless_for_sector_scan\":false}'\n"
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeIPFWithExecutable([]byte("candidate"), fake, time.Second); err == nil || !strings.Contains(err.Error(), "did not confirm IPF") {
		t.Fatalf("expected format confirmation failure, got %v", err)
	}
}

func TestDecodeIPFRejectsDerivedSizeMismatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake decoder is Unix-only")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "ipf-helper")
	script := "#!/bin/sh\nprintf '%s\\nabc' '{\"schema\":1,\"format\":\"ipf\",\"decoder\":\"fake\",\"derived_size\":4,\"lossless_for_sector_scan\":true}'\n"
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeIPFWithExecutable([]byte("candidate"), fake, time.Second); err == nil || !strings.Contains(err.Error(), "derived-size mismatch") {
		t.Fatalf("expected size mismatch failure, got %v", err)
	}
}

func TestDecodeIPFTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake decoder is Unix-only")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "ipf-helper")
	script := "#!/bin/sh\nsleep 1\n"
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeIPFWithExecutable([]byte("candidate"), fake, 20*time.Millisecond); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("expected timeout failure, got %v", err)
	}
}

func TestDecodeIPFRequiresConfiguredHelper(t *testing.T) {
	t.Setenv("AAA_IPF_HELPER", "")
	if _, _, err := DecodeIPF([]byte("candidate")); err == nil || !strings.Contains(err.Error(), "AAA_IPF_HELPER") {
		t.Fatalf("expected missing helper failure, got %v", err)
	}
}
