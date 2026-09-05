package scanner

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/adf"
	archivepkg "github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/archive"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/hunk"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/signatures"
)

type Result struct {
	Path           string                  `json:"path"`
	Name           string                  `json:"name"`
	Size           int64                   `json:"size"`
	SHA256         string                  `json:"sha256"`
	Format         string                  `json:"format"`
	Verdict        string                  `json:"verdict"`
	Detection      string                  `json:"detection,omitempty"`
	Archive        *archivepkg.Analysis    `json:"archive,omitempty"`
	ADF            *adf.Analysis           `json:"adf,omitempty"`
	Filesystem     *adf.FilesystemAnalysis `json:"filesystem,omitempty"`
	Hunk           *hunk.Analysis          `json:"hunk,omitempty"`
	BootblockMatch *signatures.Match       `json:"bootblock_match,omitempty"`
}

func ScanFile(path string) (Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return Result{}, err
	}
	if !info.Mode().IsRegular() {
		return Result{}, fmt.Errorf("not a regular file: %s", path)
	}

	h := sha256.New()
	head := make([]byte, 4096)
	n, readErr := io.ReadFull(f, head)
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		return Result{}, readErr
	}
	head = head[:n]

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return Result{}, err
	}
	if _, err := io.Copy(h, f); err != nil {
		return Result{}, err
	}

	format := DetectFormat(path, head, info.Size())
	result := Result{
		Path:    path,
		Name:    filepath.Base(path),
		Size:    info.Size(),
		SHA256:  hex.EncodeToString(h.Sum(nil)),
		Format:  format,
		Verdict: "unknown",
	}

	switch format {
	case "adf":
		if err := analyzeADFPath(&result, path); err != nil {
			return Result{}, err
		}
	case "adz":
		data, err := os.ReadFile(path)
		if err != nil {
			return Result{}, fmt.Errorf("read ADZ: %w", err)
		}
		expanded, archiveAnalysis, err := archivepkg.DecodeADZ(data)
		if err != nil {
			return Result{}, fmt.Errorf("decode ADZ: %w", err)
		}
		result.Archive = archiveAnalysis
		if err := analyzeADFBytes(&result, expanded); err != nil {
			return Result{}, fmt.Errorf("analyze expanded ADZ ADF: %w", err)
		}
	case "zip":
		data, err := os.ReadFile(path)
		if err != nil {
			return Result{}, fmt.Errorf("read ZIP: %w", err)
		}
		members, archiveAnalysis, err := archivepkg.DecodeZIP(data)
		if err != nil {
			return Result{}, fmt.Errorf("decode ZIP: %w", err)
		}
		for i, member := range members {
			memberHead := member.Data
			if len(memberHead) > 4096 {
				memberHead = memberHead[:4096]
			}
			archiveAnalysis.Members[i].Format = DetectFormat(member.Name, memberHead, int64(len(member.Data)))
		}
		result.Archive = archiveAnalysis
	case "amiga-hunk-executable":
		data, err := os.ReadFile(path)
		if err != nil {
			return Result{}, fmt.Errorf("read Hunk executable: %w", err)
		}
		result.Hunk = hunk.Analyze(data)
	}

	return result, nil
}

func analyzeADFPath(result *Result, path string) error {
	analysis, err := adf.AnalyzeFile(path)
	if err != nil {
		return fmt.Errorf("analyze ADF: %w", err)
	}
	result.ADF = analysis

	filesystem, err := adf.AnalyzeFilesystem(path)
	if err != nil {
		return fmt.Errorf("analyze ADF filesystem: %w", err)
	}
	result.Filesystem = filesystem
	return applyBundledBootblockDatabase(result)
}

func analyzeADFBytes(result *Result, image []byte) error {
	analysis, err := adf.Analyze(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		return err
	}
	result.ADF = analysis

	filesystem, err := adf.AnalyzeFilesystemBytes(image)
	if err != nil {
		return fmt.Errorf("analyze ADF filesystem: %w", err)
	}
	result.Filesystem = filesystem
	return applyBundledBootblockDatabase(result)
}

func applyBundledBootblockDatabase(result *Result) error {
	db, err := signatures.LoadBundled()
	if err != nil {
		return fmt.Errorf("load bootblock signatures: %w", err)
	}
	applyBootblockDatabase(result, db)
	return nil
}

func applyBootblockDatabase(result *Result, db *signatures.Database) {
	if result == nil || result.ADF == nil || db == nil {
		return
	}
	match := db.Lookup(result.ADF.BootblockSHA256)
	result.BootblockMatch = match
	if match != nil && match.Status == signatures.StatusKnownMalicious {
		result.Verdict = "infected"
		result.Detection = "bootblock:" + match.Name
	}
}

func DetectFormat(path string, head []byte, size int64) string {
	if len(head) >= 4 && string(head[:3]) == "DOS" && head[3] <= 7 {
		if size == adf.DDSize || size == adf.HDSize {
			return "adf"
		}
		return "amiga-filesystem-image"
	}
	if len(head) >= 4 && string(head[:4]) == "DMS!" {
		return "dms"
	}
	if len(head) >= 4 && head[0] == 'P' && head[1] == 'K' && (head[2] == 3 || head[2] == 5 || head[2] == 7) {
		return "zip"
	}
	if len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b {
		if strings.EqualFold(filepath.Ext(path), ".adz") {
			return "adz"
		}
		return "gzip"
	}
	if len(head) >= 7 && head[2] == '-' && head[3] == 'l' && head[4] == 'h' && head[6] == '-' {
		return "lha"
	}
	if len(head) >= 4 && binary.BigEndian.Uint32(head[:4]) == hunk.HUNK_HEADER {
		return "amiga-hunk-executable"
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".adf":
		return "adf-unrecognized"
	case ".adz":
		return "adz-unrecognized"
	case ".dms":
		return "dms-unrecognized"
	case ".lha", ".lzh":
		return "lha-unrecognized"
	case ".lzx":
		return "lzx-unrecognized"
	case ".hdf":
		return "hdf"
	}
	return "unknown"
}
