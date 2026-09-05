package scanner

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/adf"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/signatures"
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

func TestScanFileIncludesADFAnalysis(t *testing.T) {
	image := testADFImage()
	path := filepath.Join(t.TempDir(), "disk.adf")
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != "adf" || got.ADF == nil {
		t.Fatalf("missing ADF analysis: %+v", got)
	}
	if got.ADF.Filesystem != "FFS" || !got.ADF.ChecksumValid || got.ADF.RootBlock != 880 || len(got.ADF.BootblockSHA256) != 64 {
		t.Fatalf("unexpected ADF analysis: %+v", got.ADF)
	}
	if got.Verdict != "unknown" {
		t.Fatalf("unknown bootblock must remain unknown: %q", got.Verdict)
	}
}

func TestScanADZFeedsExpandedADFThroughPipeline(t *testing.T) {
	image := testADFImage()
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(image); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "disk.adz")
	if err := os.WriteFile(path, compressed.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != "adz" || got.Archive == nil || got.ADF == nil || got.Filesystem == nil {
		t.Fatalf("missing ADZ pipeline analysis: %+v", got)
	}
	if got.Archive.ExpandedSize != adf.DDSize || len(got.Archive.Members) != 1 {
		t.Fatalf("unexpected archive analysis: %+v", got.Archive)
	}
	if got.ADF.Filesystem != "FFS" || got.ADF.RootBlock != 880 || !got.ADF.ChecksumValid {
		t.Fatalf("unexpected expanded ADF analysis: %+v", got.ADF)
	}
}

func TestScanADZRejectsNonADFExpansion(t *testing.T) {
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write([]byte("not an ADF")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "bad.adz")
	if err := os.WriteFile(path, compressed.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ScanFile(path); err == nil {
		t.Fatal("expected non-ADF ADZ payload to fail")
	}
}

func TestScanZIPEnumeratesAndClassifiesMembers(t *testing.T) {
	var compressed bytes.Buffer
	zw := zip.NewWriter(&compressed)
	w, err := zw.Create("disk.adf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(testADFImage()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "bundle.zip")
	if err := os.WriteFile(path, compressed.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != "zip" || got.Archive == nil || len(got.Archive.Members) != 1 {
		t.Fatalf("missing ZIP analysis: %+v", got)
	}
	if got.Archive.Members[0].Name != "disk.adf" || got.Archive.Members[0].Format != "adf" || len(got.Archive.Members[0].SHA256) != 64 {
		t.Fatalf("unexpected ZIP member: %+v", got.Archive.Members[0])
	}
}

func TestMaliciousBootblockSetsInfected(t *testing.T) {
	hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	db := &signatures.Database{Schema: 1, Entries: []signatures.Entry{{
		SHA256: hash, Status: signatures.StatusKnownMalicious, Name: "Test Virus", Source: "unit-test",
	}}}
	result := Result{Verdict: "unknown", ADF: &adf.Analysis{BootblockSHA256: hash}}
	applyBootblockDatabase(&result, db)
	if result.Verdict != "infected" || result.Detection != "bootblock:Test Virus" || result.BootblockMatch == nil {
		t.Fatalf("unexpected malicious classification: %+v", result)
	}
}

func TestKnownCleanBootblockDoesNotMarkDiskClean(t *testing.T) {
	hash := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	db := &signatures.Database{Schema: 1, Entries: []signatures.Entry{{
		SHA256: hash, Status: signatures.StatusKnownClean, Name: "Known clean bootblock", Source: "unit-test",
	}}}
	result := Result{Verdict: "unknown", ADF: &adf.Analysis{BootblockSHA256: hash}}
	applyBootblockDatabase(&result, db)
	if result.Verdict != "unknown" || result.Detection != "" || result.BootblockMatch == nil || result.BootblockMatch.Status != signatures.StatusKnownClean {
		t.Fatalf("known-clean bootblock must not imply clean disk: %+v", result)
	}
}

func testADFImage() []byte {
	image := make([]byte, adf.DDSize)
	copy(image[:3], []byte("DOS"))
	image[3] = 1
	binary.BigEndian.PutUint32(image[8:12], 880)
	image[12] = 0x4e
	image[13] = 0xf9
	binary.BigEndian.PutUint32(image[4:8], adf.CalculateBootblockChecksum(image[:adf.BootBlockSize]))
	return image
}
