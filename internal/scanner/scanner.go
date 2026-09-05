package scanner

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Result struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Format    string `json:"format"`
	Verdict   string `json:"verdict"`
	Detection string `json:"detection,omitempty"`
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
	return Result{
		Path:    path,
		Name:    filepath.Base(path),
		Size:    info.Size(),
		SHA256:  hex.EncodeToString(h.Sum(nil)),
		Format:  format,
		Verdict: "unknown",
	}, nil
}

func DetectFormat(path string, head []byte, size int64) string {
	if len(head) >= 4 && string(head[:3]) == "DOS" && head[3] <= 7 {
		if size == 901120 || size == 1802240 {
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
	if len(head) >= 4 && binary.BigEndian.Uint32(head[:4]) == 0x000003f3 {
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
