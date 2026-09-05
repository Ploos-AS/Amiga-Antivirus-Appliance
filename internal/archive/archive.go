package archive

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

const MaxExpandedSize int64 = 32 * 1024 * 1024

type Member struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Format string `json:"format,omitempty"`
}

type Analysis struct {
	Format       string   `json:"format"`
	ExpandedSize int64    `json:"expanded_size"`
	Members      []Member `json:"members,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

// DecodeADZ expands one gzip-wrapped ADF entirely in memory. The caller owns
// format validation of the resulting bytes. A hard expansion limit protects
// the appliance from decompression bombs.
func DecodeADZ(data []byte) ([]byte, *Analysis, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, nil, fmt.Errorf("open ADZ gzip stream: %w", err)
	}
	defer zr.Close()

	limited := io.LimitReader(zr, MaxExpandedSize+1)
	expanded, err := io.ReadAll(limited)
	if err != nil {
		return nil, nil, fmt.Errorf("expand ADZ: %w", err)
	}
	if int64(len(expanded)) > MaxExpandedSize {
		return nil, nil, fmt.Errorf("expanded ADZ exceeds %d-byte safety limit", MaxExpandedSize)
	}

	sum := sha256.Sum256(expanded)
	analysis := &Analysis{
		Format:       "adz",
		ExpandedSize: int64(len(expanded)),
		Members: []Member{{
			Name:   "disk.adf",
			Size:   int64(len(expanded)),
			SHA256: hex.EncodeToString(sum[:]),
			Format: "adf",
		}},
	}
	return expanded, analysis, nil
}
