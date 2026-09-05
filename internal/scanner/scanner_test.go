package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectFormatADF(t *testing.T) {
	head := []byte{'D', 'O', 'S', 1}
	if got := DetectFormat("disk.adf", head, 901120); got != "adf" {
		t.Fatalf("got %q", got)
	}
}

func TestDetectFormatDMS(t *testing.T) {
	if got := DetectFormat("disk.dms", []byte("DMS!rest"), 100); got != "dms" {
		t.Fatalf("got %q", got)
	}
}

func TestDetectFormatADZ(t *testing.T) {
	if got := DetectFormat("disk.adz", []byte{0x1f, 0x8b, 0x08}, 100); got != "adz" {
		t.Fatalf("got %q", got)
	}
}

func TestDetectFormatLHA(t *testing.T) {
	head := []byte{0x20, 0x00, '-', 'l', 'h', '5', '-'}
	if got := DetectFormat("archive.lha", head, 100); got != "lha" {
		t.Fatalf("got %q", got)
	}
}

func TestDetectFormatHunk(t *testing.T) {
	head := []byte{0x00, 0x00, 0x03, 0xf3}
	if got := DetectFormat("program", head, 4); got != "amiga-hunk-executable" {
		t.Fatalf("got %q", got)
	}
}

func TestScanFileHashesAndClassifies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(path, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("unexpected hash %s", got.SHA256)
	}
	if got.Size != 3 || got.Format != "unknown" || got.Verdict != "unknown" {
		t.Fatalf("unexpected result: %+v", got)
	}
}
