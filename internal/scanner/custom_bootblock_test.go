package scanner

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/adf"
)

func TestDetectFormatUsesRawADFGeometryWithoutDOSHeader(t *testing.T) {
	head := []byte("VIRUSBOOT")
	if got := DetectFormat("disk.adf", head, adf.DDSize); got != "adf" {
		t.Fatalf("standard DD geometry must remain scannable as ADF, got %q", got)
	}
}

func TestScanCustomBootblockHashesBeforeFilesystemRecognition(t *testing.T) {
	image := make([]byte, adf.DDSize)
	copy(image[:4], []byte("NOPE"))
	binary.BigEndian.PutUint32(image[8:12], 880)
	image[12] = 0x4e
	image[13] = 0xf9
	binary.BigEndian.PutUint32(image[4:8], adf.CalculateBootblockChecksum(image[:adf.BootBlockSize]))

	path := filepath.Join(t.TempDir(), "custom.adf")
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != "adf" || got.ADF == nil {
		t.Fatalf("custom bootblock did not reach ADF analysis: %+v", got)
	}
	if got.ADF.DOSHeaderRecognized {
		t.Fatalf("custom header incorrectly recognized as DOS: %+v", got.ADF)
	}
	if len(got.ADF.BootblockSHA256) != 64 {
		t.Fatalf("bootblock hash missing: %+v", got.ADF)
	}
	if got.Filesystem != nil {
		t.Fatalf("filesystem traversal must stay disabled without recognized DOS header: %+v", got.Filesystem)
	}
}
