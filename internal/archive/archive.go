package archive

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	MaxExpandedSize int64 = 32 * 1024 * 1024
	MaxMembers            = 1024
)

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

type ExpandedMember struct {
	Name string
	Data []byte
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

// DecodeZIP expands regular ZIP members into memory with strict member-count
// and aggregate expansion limits. Directory entries are ignored. No paths are
// created on the host filesystem, so member names cannot cause path traversal.
func DecodeZIP(data []byte) ([]ExpandedMember, *Analysis, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, nil, fmt.Errorf("open ZIP: %w", err)
	}
	if len(zr.File) > MaxMembers {
		return nil, nil, fmt.Errorf("ZIP contains %d entries, exceeds %d-entry safety limit", len(zr.File), MaxMembers)
	}

	analysis := &Analysis{Format: "zip"}
	expanded := make([]ExpandedMember, 0, len(zr.File))
	var total int64
	for _, file := range zr.File {
		if file.FileInfo().IsDir() {
			continue
		}
		if file.Flags&0x1 != 0 {
			return nil, nil, fmt.Errorf("encrypted ZIP member is unsupported: %s", file.Name)
		}

		rc, err := file.Open()
		if err != nil {
			return nil, nil, fmt.Errorf("open ZIP member %q: %w", file.Name, err)
		}
		remaining := MaxExpandedSize - total
		if remaining < 0 {
			rc.Close()
			return nil, nil, fmt.Errorf("expanded ZIP exceeds %d-byte safety limit", MaxExpandedSize)
		}
		memberData, readErr := io.ReadAll(io.LimitReader(rc, remaining+1))
		closeErr := rc.Close()
		if readErr != nil {
			return nil, nil, fmt.Errorf("expand ZIP member %q: %w", file.Name, readErr)
		}
		if closeErr != nil {
			return nil, nil, fmt.Errorf("close ZIP member %q: %w", file.Name, closeErr)
		}
		if int64(len(memberData)) > remaining {
			return nil, nil, fmt.Errorf("expanded ZIP exceeds %d-byte safety limit", MaxExpandedSize)
		}

		total += int64(len(memberData))
		sum := sha256.Sum256(memberData)
		analysis.Members = append(analysis.Members, Member{
			Name:   file.Name,
			Size:   int64(len(memberData)),
			SHA256: hex.EncodeToString(sum[:]),
		})
		expanded = append(expanded, ExpandedMember{Name: file.Name, Data: memberData})
	}
	analysis.ExpandedSize = total
	return expanded, analysis, nil
}
