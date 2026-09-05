package archive

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	lzxToolTimeout = 15 * time.Second
	maxLSAROutput  = 4 * 1024 * 1024
)

type lsarListing struct {
	FormatName string      `json:"lsarFormatName"`
	Contents   []lsarEntry `json:"lsarContents"`
}

type lsarEntry struct {
	Name        string `json:"XADFileName"`
	Size        int64  `json:"XADFileSize"`
	IsDirectory bool   `json:"XADIsDirectory"`
}

// DecodeLZX expands an Amiga LZX archive through Debian's unar/lsar tools.
// The submitted archive is stored only in a private temporary file because
// the tools require a seekable archive path. Member payloads are never written
// to host filesystem paths: each member is requested separately with unar's
// stdout output mode and retained only in memory.
func DecodeLZX(data []byte) ([]ExpandedMember, *Analysis, error) {
	return DecodeLZXLimited(data, MaxExpandedSize, MaxMembers)
}

// DecodeLZXLimited applies caller-supplied remaining byte/member budgets so a
// nested scan shares the same global resource ceilings as ZIP and LHA.
func DecodeLZXLimited(data []byte, maxExpanded int64, maxMembers int) ([]ExpandedMember, *Analysis, error) {
	if maxExpanded <= 0 || maxExpanded > MaxExpandedSize {
		return nil, nil, fmt.Errorf("invalid LZX expansion limit: %d", maxExpanded)
	}
	if maxMembers <= 0 || maxMembers > MaxMembers {
		return nil, nil, fmt.Errorf("invalid LZX member limit: %d", maxMembers)
	}
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("empty LZX input")
	}

	lsarPath := os.Getenv("AAA_LSAR")
	if lsarPath == "" {
		lsarPath = "lsar"
	}
	unarPath := os.Getenv("AAA_UNAR")
	if unarPath == "" {
		unarPath = "unar"
	}

	tmp, err := os.CreateTemp("", "aaa-lzx-*.lzx")
	if err != nil {
		return nil, nil, fmt.Errorf("create LZX staging file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return nil, nil, fmt.Errorf("secure LZX staging file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return nil, nil, fmt.Errorf("write LZX staging file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, nil, fmt.Errorf("close LZX staging file: %w", err)
	}

	listing, err := inspectLZX(lsarPath, tmpName)
	if err != nil {
		return nil, nil, err
	}
	if !strings.Contains(strings.ToLower(listing.FormatName), "lzx") {
		return nil, nil, fmt.Errorf("lsar did not recognize Amiga LZX archive: %q", listing.FormatName)
	}
	if len(listing.Contents) > maxMembers {
		return nil, nil, fmt.Errorf("LZX contains %d entries, exceeds %d-entry safety limit", len(listing.Contents), maxMembers)
	}

	analysis := &Analysis{Format: "lzx"}
	expanded := make([]ExpandedMember, 0, len(listing.Contents))
	var total int64
	for _, entry := range listing.Contents {
		if entry.IsDirectory {
			continue
		}
		if entry.Name == "" {
			return nil, nil, fmt.Errorf("LZX member has empty name")
		}
		if entry.Size < 0 || entry.Size > maxExpanded-total {
			return nil, nil, fmt.Errorf("expanded LZX exceeds %d-byte safety limit", maxExpanded)
		}
		memberData, err := extractLZXMember(unarPath, tmpName, entry.Name, maxExpanded-total)
		if err != nil {
			return nil, nil, err
		}
		if int64(len(memberData)) != entry.Size {
			return nil, nil, fmt.Errorf("LZX member %q decoded size mismatch: got %d, expected %d", entry.Name, len(memberData), entry.Size)
		}
		total += int64(len(memberData))
		appendMember(analysis, &expanded, entry.Name, memberData)
	}
	if len(expanded) == 0 {
		return nil, nil, fmt.Errorf("LZX contains no decodable file members")
	}
	analysis.ExpandedSize = total
	return expanded, analysis, nil
}

func inspectLZX(executable, archivePath string) (*lsarListing, error) {
	ctx, cancel := context.WithTimeout(context.Background(), lzxToolTimeout)
	defer cancel()
	stdout := &cappedBuffer{limit: maxLSAROutput}
	stderr := &cappedBuffer{limit: maxToolStderr}
	cmd := exec.CommandContext(ctx, executable, "-j", "-nr", "--", archivePath)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("lsar inspection exceeded %s timeout", lzxToolTimeout)
		}
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("lsar inspection failed: %w: %s", err, stderr.String())
		}
		return nil, fmt.Errorf("lsar inspection failed: %w", err)
	}
	if stdout.exceeded {
		return nil, fmt.Errorf("lsar metadata exceeds %d-byte safety limit", maxLSAROutput)
	}
	var listing lsarListing
	if err := json.Unmarshal(stdout.Bytes(), &listing); err != nil {
		return nil, fmt.Errorf("parse lsar JSON: %w", err)
	}
	return &listing, nil
}

func extractLZXMember(executable, archivePath, memberName string, maxExpanded int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), lzxToolTimeout)
	defer cancel()
	stdout := &cappedBuffer{limit: maxExpanded}
	stderr := &cappedBuffer{limit: maxToolStderr}
	cmd := exec.CommandContext(ctx, executable, "-o", "-", "--", archivePath, memberName)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("unar extraction of %q exceeded %s timeout", memberName, lzxToolTimeout)
		}
		if stdout.exceeded {
			return nil, fmt.Errorf("expanded LZX exceeds %d-byte safety limit", maxExpanded)
		}
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("unar extraction of %q failed: %w: %s", memberName, err, stderr.String())
		}
		return nil, fmt.Errorf("unar extraction of %q failed: %w", memberName, err)
	}
	if stdout.exceeded {
		return nil, fmt.Errorf("expanded LZX exceeds %d-byte safety limit", maxExpanded)
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

var _ = bytes.MinRead
