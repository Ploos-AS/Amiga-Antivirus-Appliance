package archive

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/koron-go/lha"
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

func DecodeADZ(data []byte) ([]byte, *Analysis, error) {
	return DecodeADZLimited(data, MaxExpandedSize)
}

// DecodeADZLimited expands one gzip-wrapped ADF entirely in memory. The caller
// supplies the remaining expansion budget so nested scans can share a global
// resource ceiling rather than resetting limits for every archive layer.
func DecodeADZLimited(data []byte, maxExpanded int64) ([]byte, *Analysis, error) {
	if maxExpanded <= 0 || maxExpanded > MaxExpandedSize {
		return nil, nil, fmt.Errorf("invalid ADZ expansion limit: %d", maxExpanded)
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, nil, fmt.Errorf("open ADZ gzip stream: %w", err)
	}
	defer zr.Close()

	limited := io.LimitReader(zr, maxExpanded+1)
	expanded, err := io.ReadAll(limited)
	if err != nil {
		return nil, nil, fmt.Errorf("expand ADZ: %w", err)
	}
	if int64(len(expanded)) > maxExpanded {
		return nil, nil, fmt.Errorf("expanded ADZ exceeds %d-byte safety limit", maxExpanded)
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

func DecodeZIP(data []byte) ([]ExpandedMember, *Analysis, error) {
	return DecodeZIPLimited(data, MaxExpandedSize, MaxMembers)
}

// DecodeZIPLimited expands regular ZIP members into memory with caller-supplied
// remaining byte/member budgets. Directory entries still count toward the
// archive entry ceiling even though they do not become scanner members.
func DecodeZIPLimited(data []byte, maxExpanded int64, maxMembers int) ([]ExpandedMember, *Analysis, error) {
	if maxExpanded <= 0 || maxExpanded > MaxExpandedSize {
		return nil, nil, fmt.Errorf("invalid ZIP expansion limit: %d", maxExpanded)
	}
	if maxMembers <= 0 || maxMembers > MaxMembers {
		return nil, nil, fmt.Errorf("invalid ZIP member limit: %d", maxMembers)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, nil, fmt.Errorf("open ZIP: %w", err)
	}
	if len(zr.File) > maxMembers {
		return nil, nil, fmt.Errorf("ZIP contains %d entries, exceeds %d-entry safety limit", len(zr.File), maxMembers)
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
		remaining := maxExpanded - total
		memberData, readErr := io.ReadAll(io.LimitReader(rc, remaining+1))
		closeErr := rc.Close()
		if readErr != nil {
			return nil, nil, fmt.Errorf("expand ZIP member %q: %w", file.Name, readErr)
		}
		if closeErr != nil {
			return nil, nil, fmt.Errorf("close ZIP member %q: %w", file.Name, closeErr)
		}
		if int64(len(memberData)) > remaining {
			return nil, nil, fmt.Errorf("expanded ZIP exceeds %d-byte safety limit", maxExpanded)
		}

		total += int64(len(memberData))
		appendMember(analysis, &expanded, file.Name, memberData)
	}
	analysis.ExpandedSize = total
	return expanded, analysis, nil
}

func DecodeLHA(data []byte) ([]ExpandedMember, *Analysis, error) {
	return DecodeLHALimited(data, MaxExpandedSize, MaxMembers)
}

// DecodeLHALimited expands supported LHA/LZH members entirely in memory using
// caller-supplied remaining byte/member budgets. The selected reader supports
// the common -lh0-, -lh4-, -lh5-, -lh6- and -lh7- methods. Unsupported methods
// fail closed. Directory headers count toward the entry ceiling.
func DecodeLHALimited(data []byte, maxExpanded int64, maxMembers int) ([]ExpandedMember, *Analysis, error) {
	if maxExpanded <= 0 || maxExpanded > MaxExpandedSize {
		return nil, nil, fmt.Errorf("invalid LHA expansion limit: %d", maxExpanded)
	}
	if maxMembers <= 0 || maxMembers > MaxMembers {
		return nil, nil, fmt.Errorf("invalid LHA member limit: %d", maxMembers)
	}
	if !looksLikeLHA(data) {
		return nil, nil, fmt.Errorf("not a recognized LHA/LZH stream")
	}

	r := lha.NewReader(bytes.NewReader(data))
	analysis := &Analysis{Format: "lha"}
	expanded := make([]ExpandedMember, 0)
	var total int64
	entries := 0

	for {
		h, err := r.NextHeader()
		if err != nil {
			return nil, nil, fmt.Errorf("read LHA header: %w", err)
		}
		if h == nil {
			break
		}
		entries++
		if entries > maxMembers {
			return nil, nil, fmt.Errorf("LHA exceeds %d-entry safety limit", maxMembers)
		}
		if h.Method == "-lhd-" {
			continue
		}
		if h.OriginalSize > uint64(maxExpanded) || int64(h.OriginalSize) > maxExpanded-total {
			return nil, nil, fmt.Errorf("expanded LHA exceeds %d-byte safety limit", maxExpanded)
		}

		var buf bytes.Buffer
		buf.Grow(int(h.OriginalSize))
		n, err := r.Decode(&buf)
		if err != nil {
			return nil, nil, fmt.Errorf("decode LHA member %q (%s): %w", lhaMemberName(h), h.Method, err)
		}
		if n < 0 || int64(n) != int64(buf.Len()) || int64(buf.Len()) != int64(h.OriginalSize) {
			return nil, nil, fmt.Errorf("LHA member %q decoded size mismatch", lhaMemberName(h))
		}
		memberData := append([]byte(nil), buf.Bytes()...)
		total += int64(len(memberData))
		appendMember(analysis, &expanded, lhaMemberName(h), memberData)
	}

	if len(expanded) == 0 {
		return nil, nil, fmt.Errorf("LHA contains no decodable file members")
	}
	analysis.ExpandedSize = total
	return expanded, analysis, nil
}

func looksLikeLHA(data []byte) bool {
	if len(data) < 21 {
		return false
	}
	method := string(data[2:7])
	switch method {
	case "-lh0-", "-lh4-", "-lh5-", "-lh6-", "-lh7-", "-lhd-":
		return data[20] <= 3
	default:
		return false
	}
}

func lhaMemberName(h *lha.Header) string {
	if h == nil {
		return ""
	}
	if h.Dir == "" {
		return h.Name
	}
	return h.Dir + h.Name
}

func appendMember(analysis *Analysis, expanded *[]ExpandedMember, name string, data []byte) {
	sum := sha256.Sum256(data)
	analysis.Members = append(analysis.Members, Member{
		Name:   name,
		Size:   int64(len(data)),
		SHA256: hex.EncodeToString(sum[:]),
	})
	*expanded = append(*expanded, ExpandedMember{Name: name, Data: data})
}
