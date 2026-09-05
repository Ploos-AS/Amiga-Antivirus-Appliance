package signaturefactory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type nativeBootblockEntry struct {
	SHA256 string `json:"sha256"`
	Status string `json:"status"`
	Name   string `json:"name"`
	Source string `json:"source"`
	Notes  string `json:"notes,omitempty"`
}

type nativeBootblockDatabase struct {
	Schema  int                    `json:"schema"`
	Entries []nativeBootblockEntry `json:"entries"`
}

// ListPromoted returns all strictly validated promoted records in deterministic
// candidate-ID order. Any malformed promoted record fails the whole operation.
func (s *Store) ListPromoted() ([]Candidate, error) {
	if s == nil {
		return nil, errors.New("nil signature store")
	}
	if err := s.Init(); err != nil {
		return nil, err
	}

	base := filepath.Join(s.Root, "promoted")
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil, fmt.Errorf("list promoted candidates: %w", err)
	}

	promoted := make([]Candidate, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := entry.Name()[:len(entry.Name())-len(".json")]
		if !candidateIDPattern.MatchString(id) {
			return nil, fmt.Errorf("promoted record has invalid filename %q", entry.Name())
		}
		data, err := os.ReadFile(filepath.Join(base, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read promoted candidate %q: %w", id, err)
		}
		candidate, err := DecodeCandidateStrict(data)
		if err != nil {
			return nil, fmt.Errorf("decode promoted candidate %q: %w", id, err)
		}
		if candidate.Status != StatusPromoted {
			return nil, fmt.Errorf("promoted record %q has status %q", id, candidate.Status)
		}
		if candidate.ID != id {
			return nil, fmt.Errorf("promoted record %q id does not match filename", id)
		}
		promoted = append(promoted, candidate)
	}

	sort.Slice(promoted, func(i, j int) bool { return promoted[i].ID < promoted[j].ID })
	return promoted, nil
}

// ExportNativeBootblocks builds the native AAA bootblock database exclusively
// from promoted exact bootblock candidates. Other promoted candidate kinds are
// intentionally ignored until a native consumer exists for them.
func (s *Store) ExportNativeBootblocks() (string, int, error) {
	promoted, err := s.ListPromoted()
	if err != nil {
		return "", 0, err
	}

	entries := make([]nativeBootblockEntry, 0, len(promoted))
	seen := make(map[string]string)
	for _, candidate := range promoted {
		if candidate.Kind != KindBootblockSHA256 {
			continue
		}
		if previous, ok := seen[candidate.BootblockSHA256]; ok {
			return "", 0, fmt.Errorf("duplicate promoted bootblock sha256 %s in %s and %s", candidate.BootblockSHA256, previous, candidate.ID)
		}
		seen[candidate.BootblockSHA256] = candidate.ID

		notes := ""
		if candidate.DetectionName != candidate.MalwareName {
			notes = "Detection: " + candidate.DetectionName
		}
		entries = append(entries, nativeBootblockEntry{
			SHA256: candidate.BootblockSHA256,
			Status: "known-malicious",
			Name:   candidate.MalwareName,
			Source: "signature-factory:" + candidate.ID,
			Notes:  notes,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].SHA256 == entries[j].SHA256 {
			return entries[i].Source < entries[j].Source
		}
		return entries[i].SHA256 < entries[j].SHA256
	})

	database := nativeBootblockDatabase{Schema: 1, Entries: entries}
	encoded, err := json.MarshalIndent(database, "", "  ")
	if err != nil {
		return "", 0, fmt.Errorf("encode native bootblock database: %w", err)
	}
	encoded = append(encoded, '\n')

	path := filepath.Join(s.Root, "generated", "aaa", "bootblocks.json")
	if err := writeGeneratedFile(filepath.Dir(path), path, encoded); err != nil {
		return "", 0, err
	}
	return path, len(entries), nil
}

// ExportClamAVHashes builds a ClamAV SHA-256 hash database (.hsb) exclusively
// from promoted exact file candidates attributed to ClamAV. Each output line is
// HashString:FileSize:MalwareName and output ordering is deterministic.
func (s *Store) ExportClamAVHashes() (string, int, error) {
	promoted, err := s.ListPromoted()
	if err != nil {
		return "", 0, err
	}

	type line struct {
		sha256 string
		text   string
		id     string
	}
	lines := make([]line, 0, len(promoted))
	seen := make(map[string]string)
	for _, candidate := range promoted {
		if candidate.Kind != KindFileSHA256 || candidate.SourceEngine != ClamAVEngineName {
			continue
		}
		name := strings.TrimSpace(candidate.DetectionName)
		if name == "" {
			name = strings.TrimSpace(candidate.MalwareName)
		}
		if err := validateClamAVSignatureName(name); err != nil {
			return "", 0, fmt.Errorf("candidate %s: %w", candidate.ID, err)
		}
		if previous, ok := seen[candidate.SampleSHA256]; ok {
			return "", 0, fmt.Errorf("duplicate promoted ClamAV sha256 %s in %s and %s", candidate.SampleSHA256, previous, candidate.ID)
		}
		seen[candidate.SampleSHA256] = candidate.ID
		lines = append(lines, line{
			sha256: candidate.SampleSHA256,
			text:   fmt.Sprintf("%s:%d:%s", candidate.SampleSHA256, candidate.SampleSize, name),
			id:     candidate.ID,
		})
	}

	sort.Slice(lines, func(i, j int) bool {
		if lines[i].sha256 == lines[j].sha256 {
			return lines[i].id < lines[j].id
		}
		return lines[i].sha256 < lines[j].sha256
	})

	var encoded bytes.Buffer
	for _, item := range lines {
		encoded.WriteString(item.text)
		encoded.WriteByte('\n')
	}

	path := filepath.Join(s.Root, "generated", "clamav", "aaa.hsb")
	if err := writeGeneratedFile(filepath.Dir(path), path, encoded.Bytes()); err != nil {
		return "", 0, err
	}
	return path, len(lines), nil
}

func validateClamAVSignatureName(name string) error {
	if name == "" {
		return errors.New("ClamAV signature name is required")
	}
	if strings.ContainsRune(name, ':') {
		return errors.New("ClamAV signature name contains ':'")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return errors.New("ClamAV signature name contains control characters")
		}
	}
	return nil
}

func writeGeneratedFile(dir, path string, encoded []byte) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create generated signature directory: %w", err)
	}
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, encoded) {
		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read generated signature file: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".generated-*.tmp")
	if err != nil {
		return fmt.Errorf("create generated signature temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return fmt.Errorf("set generated signature permissions: %w", err)
	}
	if _, err := tmp.Write(encoded); err != nil {
		tmp.Close()
		return fmt.Errorf("write generated signature temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync generated signature temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close generated signature temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("commit generated signature file: %w", err)
	}
	return nil
}
