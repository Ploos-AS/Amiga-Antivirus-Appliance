package adf

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func makeADF(size int, dos uint8, root uint32, bootable bool) []byte {
	image := make([]byte, size)
	copy(image[:3], []byte("DOS"))
	image[3] = dos
	binary.BigEndian.PutUint32(image[8:12], root)
	if bootable {
		image[12] = 0x4e
		image[13] = 0xf9
	}
	binary.BigEndian.PutUint32(image[4:8], CalculateBootblockChecksum(image[:BootBlockSize]))
	return image
}

func TestAnalyzeDDFFSBootable(t *testing.T) {
	image := makeADF(DDSize, 1, 880, true)
	got, err := Analyze(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatal(err)
	}
	if got.DiskType != "dd" || got.Blocks != 1760 {
		t.Fatalf("unexpected geometry: %+v", got)
	}
	if !got.DOSHeaderRecognized || got.Filesystem != "FFS" || got.DOSVersion != 1 {
		t.Fatalf("unexpected filesystem: %+v", got)
	}
	if !got.Bootable || !got.ChecksumValid || !got.RootBlockPlausible {
		t.Fatalf("unexpected bootblock analysis: %+v", got)
	}
	if got.StoredChecksum != got.CalculatedChecksum {
		t.Fatalf("checksum mismatch: stored=%08x calculated=%08x", got.StoredChecksum, got.CalculatedChecksum)
	}
}

func TestAnalyzeHDNonBootable(t *testing.T) {
	image := makeADF(HDSize, 0, 1760, false)
	got, err := Analyze(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatal(err)
	}
	if got.DiskType != "hd" || got.Blocks != 3520 || got.ExpectedRootBlock != 1760 {
		t.Fatalf("unexpected geometry: %+v", got)
	}
	if got.Bootable {
		t.Fatal("zero boot code reported as bootable")
	}
}

func TestAnalyzeDetectsBadChecksum(t *testing.T) {
	image := makeADF(DDSize, 1, 880, true)
	image[100] ^= 0xff
	got, err := Analyze(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatal(err)
	}
	if got.ChecksumValid {
		t.Fatal("corrupted bootblock checksum reported valid")
	}
}

func TestAnalyzeRejectsUnsupportedGeometry(t *testing.T) {
	image := make([]byte, 4096)
	copy(image, []byte{'D', 'O', 'S', 1})
	if _, err := Analyze(bytes.NewReader(image), int64(len(image))); err == nil {
		t.Fatal("expected unsupported ADF size error")
	}
}

func TestAnalyzePreservesCustomBootblockWithoutDOSHeader(t *testing.T) {
	image := make([]byte, DDSize)
	copy(image[:4], []byte("NOPE"))
	binary.BigEndian.PutUint32(image[8:12], 880)
	image[12] = 0x4e
	image[13] = 0xf9
	binary.BigEndian.PutUint32(image[4:8], CalculateBootblockChecksum(image[:BootBlockSize]))

	got, err := Analyze(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatal(err)
	}
	if got.DOSHeaderRecognized {
		t.Fatalf("custom bootblock incorrectly recognized as DOS: %+v", got)
	}
	if got.Filesystem != "" || got.DOSVersion != 0 {
		t.Fatalf("custom bootblock must not invent filesystem metadata: %+v", got)
	}
	if len(got.BootblockSHA256) != 64 || !got.Bootable || !got.ChecksumValid {
		t.Fatalf("custom bootblock analysis incomplete: %+v", got)
	}
}
