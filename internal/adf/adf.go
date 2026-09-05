package adf

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

const (
	BootBlockSize = 1024
	DDSize        = 901120
	HDSize        = 1802240
)

type Analysis struct {
	DiskType            string `json:"disk_type"`
	Blocks              int64  `json:"blocks"`
	DOSHeaderRecognized bool   `json:"dos_header_recognized"`
	DOSVersion          uint8  `json:"dos_version,omitempty"`
	Filesystem          string `json:"filesystem,omitempty"`
	Bootable            bool   `json:"bootable"`
	BootblockSHA256     string `json:"bootblock_sha256"`
	StoredChecksum      uint32 `json:"stored_checksum"`
	CalculatedChecksum  uint32 `json:"calculated_checksum"`
	ChecksumValid       bool   `json:"checksum_valid"`
	RootBlock           uint32 `json:"root_block"`
	ExpectedRootBlock   uint32 `json:"expected_root_block"`
	RootBlockPlausible  bool   `json:"root_block_plausible"`
}

func AnalyzeFile(path string) (*Analysis, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", path)
	}
	return Analyze(f, info.Size())
}

func Analyze(r io.Reader, size int64) (*Analysis, error) {
	diskType, blocks, expectedRoot, err := geometry(size)
	if err != nil {
		return nil, err
	}

	boot := make([]byte, BootBlockSize)
	if _, err := io.ReadFull(r, boot); err != nil {
		return nil, fmt.Errorf("read bootblock: %w", err)
	}

	dosHeaderRecognized := string(boot[:3]) == "DOS" && boot[3] <= 7
	stored := binary.BigEndian.Uint32(boot[4:8])
	root := binary.BigEndian.Uint32(boot[8:12])
	calculated := CalculateBootblockChecksum(boot)
	bootHash := sha256.Sum256(boot)

	analysis := &Analysis{
		DiskType:            diskType,
		Blocks:              blocks,
		DOSHeaderRecognized: dosHeaderRecognized,
		Bootable:            hasBootCode(boot[12:]),
		BootblockSHA256:     hex.EncodeToString(bootHash[:]),
		StoredChecksum:      stored,
		CalculatedChecksum:  calculated,
		ChecksumValid:       stored == calculated,
		RootBlock:           root,
		ExpectedRootBlock:   expectedRoot,
		RootBlockPlausible:  root == 0 || root == expectedRoot,
	}
	if dosHeaderRecognized {
		analysis.DOSVersion = boot[3]
		analysis.Filesystem = filesystemName(boot[3])
	}
	return analysis, nil
}

// CalculateBootblockChecksum returns the checksum value that belongs in bytes
// 4..7 of a 1024-byte Amiga boot block. The stored checksum field is treated
// as zero and the 32-bit big-endian words are added with end-around carry.
func CalculateBootblockChecksum(boot []byte) uint32 {
	if len(boot) < BootBlockSize {
		return 0
	}
	var sum uint32
	for off := 0; off < BootBlockSize; off += 4 {
		var word uint32
		if off != 4 {
			word = binary.BigEndian.Uint32(boot[off : off+4])
		}
		old := sum
		sum += word
		if sum < old {
			sum++
		}
	}
	return ^sum
}

func geometry(size int64) (string, int64, uint32, error) {
	switch size {
	case DDSize:
		return "dd", DDSize / 512, 880, nil
	case HDSize:
		return "hd", HDSize / 512, 1760, nil
	default:
		return "", 0, 0, fmt.Errorf("unsupported ADF size: %d", size)
	}
}

func filesystemName(v uint8) string {
	switch v {
	case 0:
		return "OFS"
	case 1:
		return "FFS"
	case 2:
		return "OFS+INTL"
	case 3:
		return "FFS+INTL"
	case 4:
		return "OFS+DIRCACHE"
	case 5:
		return "FFS+DIRCACHE"
	case 6:
		return "OFS+LONGNAME"
	case 7:
		return "FFS+LONGNAME"
	default:
		return "unknown"
	}
}

func hasBootCode(code []byte) bool {
	for _, b := range code {
		if b != 0 {
			return true
		}
	}
	return false
}
