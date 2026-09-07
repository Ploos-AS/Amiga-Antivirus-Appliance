// Package evidencebundle implements the portable AAA evidence-manifest contract.
package evidencebundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const Schema = "aaa-evidence-bundle-v1"

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Kind is a controlled category of evidence referenced by a portable manifest.
type Kind string

const (
	KindArtifact            Kind = "artifact"
	KindScanReport          Kind = "scan-report"
	KindEngineEvidence      Kind = "engine-evidence"
	KindAcquisitionEvidence Kind = "acquisition-evidence"
	KindRepeatability       Kind = "repeatability"
	KindAcquisitionSession  Kind = "acquisition-session"
	KindRawFlux             Kind = "raw-flux"
	KindSignatureEvidence   Kind = "signature-evidence"
)

// Entry binds one portable relative name to its exact bytes.
type Entry struct {
	Name   string `json:"name"`
	Kind   Kind   `json:"kind"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Relationship records an explicit semantic relationship between two entries.
// Type is descriptive only and must never be inferred by bundle verification.
type Relationship struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}

// Manifest is the portable evidence boundary introduced by M13.
type Manifest struct {
	Schema        string         `json:"schema"`
	CreatedAt     time.Time      `json:"created_at"`
	AAAVersion    string         `json:"aaa_version"`
	Note          string         `json:"note,omitempty"`
	Entries       []Entry        `json:"entries"`
	Relationships []Relationship `json:"relationships,omitempty"`
}

// Build constructs a validated manifest and canonicalizes entry and relationship ordering.
func Build(aaaVersion string, createdAt time.Time, note string, entries []Entry, relationships []Relationship) (Manifest, error) {
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	m := Manifest{
		Schema:        Schema,
		CreatedAt:     createdAt.UTC(),
		AAAVersion:    aaaVersion,
		Note:          note,
		Entries:       append([]Entry(nil), entries...),
		Relationships: append([]Relationship(nil), relationships...),
	}
	canonicalize(&m)
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// Validate enforces the portable manifest contract without touching the filesystem.
func (m Manifest) Validate() error {
	if m.Schema != Schema {
		return fmt.Errorf("unsupported evidence bundle schema %q", m.Schema)
	}
	if m.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	if strings.TrimSpace(m.AAAVersion) == "" {
		return errors.New("aaa_version is required")
	}
	if len(m.Entries) == 0 {
		return errors.New("at least one evidence entry is required")
	}

	seen := make(map[string]struct{}, len(m.Entries))
	for i, entry := range m.Entries {
		if err := entry.Validate(); err != nil {
			return fmt.Errorf("entry %d: %w", i+1, err)
		}
		if _, ok := seen[entry.Name]; ok {
			return fmt.Errorf("duplicate evidence entry name %q", entry.Name)
		}
		seen[entry.Name] = struct{}{}
	}

	for i, rel := range m.Relationships {
		if strings.TrimSpace(rel.Type) == "" {
			return fmt.Errorf("relationship %d: type is required", i+1)
		}
		if _, ok := seen[rel.From]; !ok {
			return fmt.Errorf("relationship %d: unknown from entry %q", i+1, rel.From)
		}
		if _, ok := seen[rel.To]; !ok {
			return fmt.Errorf("relationship %d: unknown to entry %q", i+1, rel.To)
		}
		if rel.From == rel.To {
			return fmt.Errorf("relationship %d: self relationship is not allowed", i+1)
		}
	}
	return nil
}

// Validate enforces the portable identity of one evidence entry.
func (e Entry) Validate() error {
	if err := validatePortableName(e.Name); err != nil {
		return err
	}
	if !e.Kind.Valid() {
		return fmt.Errorf("unsupported evidence kind %q", e.Kind)
	}
	if !sha256Pattern.MatchString(e.SHA256) {
		return errors.New("invalid SHA-256")
	}
	if e.Size < 0 {
		return errors.New("size must not be negative")
	}
	return nil
}

func (k Kind) Valid() bool {
	switch k {
	case KindArtifact, KindScanReport, KindEngineEvidence, KindAcquisitionEvidence, KindRepeatability, KindAcquisitionSession, KindRawFlux, KindSignatureEvidence:
		return true
	default:
		return false
	}
}

// MarshalDeterministic validates and serializes a canonical copy of the manifest.
// A trailing newline is included so the returned bytes can be written directly as the canonical manifest file.
func (m Manifest) MarshalDeterministic() ([]byte, error) {
	copy := Manifest{
		Schema:        m.Schema,
		CreatedAt:     m.CreatedAt.UTC(),
		AAAVersion:    m.AAAVersion,
		Note:          m.Note,
		Entries:       append([]Entry(nil), m.Entries...),
		Relationships: append([]Relationship(nil), m.Relationships...),
	}
	canonicalize(&copy)
	if err := copy.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(copy, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// VerifyFiles validates the manifest and verifies each referenced file under root.
// It never follows a manifest name outside root and never executes file content.
func (m Manifest) VerifyFiles(root string) error {
	if err := m.Validate(); err != nil {
		return err
	}
	for _, entry := range m.Entries {
		path := filepath.Join(root, filepath.FromSlash(entry.Name))
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("verify %q: %w", entry.Name, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("verify %q: entry is not a regular file", entry.Name)
		}
		if info.Size() != entry.Size {
			return fmt.Errorf("verify %q: size mismatch", entry.Name)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("verify %q: %w", entry.Name, err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != entry.SHA256 {
			return fmt.Errorf("verify %q: SHA-256 mismatch", entry.Name)
		}
	}
	return nil
}

func validatePortableName(name string) error {
	if name == "" || strings.TrimSpace(name) != name {
		return errors.New("evidence name is required without surrounding whitespace")
	}
	if strings.Contains(name, "\\") {
		return errors.New("evidence name must use forward slashes")
	}
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return errors.New("absolute evidence paths are forbidden")
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(name)))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != name {
		return errors.New("evidence name must be a normalized safe relative path")
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("evidence name contains an unsafe path component")
		}
	}
	return nil
}

func canonicalize(m *Manifest) {
	sort.Slice(m.Entries, func(i, j int) bool {
		if m.Entries[i].Name == m.Entries[j].Name {
			return m.Entries[i].Kind < m.Entries[j].Kind
		}
		return m.Entries[i].Name < m.Entries[j].Name
	})
	sort.Slice(m.Relationships, func(i, j int) bool {
		if m.Relationships[i].From != m.Relationships[j].From {
			return m.Relationships[i].From < m.Relationships[j].From
		}
		if m.Relationships[i].To != m.Relationships[j].To {
			return m.Relationships[i].To < m.Relationships[j].To
		}
		return m.Relationships[i].Type < m.Relationships[j].Type
	})
}
