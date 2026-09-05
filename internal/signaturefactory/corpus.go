package signaturefactory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const CorpusSchemaVersion = 1

type CorpusClass string

const (
	CorpusClassClean   CorpusClass = "clean"
	CorpusClassMalware CorpusClass = "malware"
)

type CorpusEntry struct {
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	Format     string `json:"format,omitempty"`
	Provenance string `json:"provenance,omitempty"`
}

type CorpusManifest struct {
	Schema    int           `json:"schema"`
	Class     CorpusClass   `json:"class"`
	ID        string        `json:"id"`
	CreatedAt time.Time     `json:"created_at"`
	Entries   []CorpusEntry `json:"entries"`
}

type CorpusValidationResult struct {
	Schema                int       `json:"schema"`
	CandidateID           string    `json:"candidate_id"`
	PatternSHA256         string    `json:"pattern_sha256"`
	CleanManifestSHA256   string    `json:"clean_manifest_sha256"`
	MalwareManifestSHA256 string    `json:"malware_manifest_sha256"`
	CleanSampleCount      int       `json:"clean_sample_count"`
	CleanMatchCount       int       `json:"clean_match_count"`
	MalwareSampleCount    int       `json:"malware_sample_count"`
	MalwareMatchCount     int       `json:"malware_match_count"`
	CleanMatches          []string  `json:"clean_matches,omitempty"`
	MalwareMatches        []string  `json:"malware_matches,omitempty"`
	ValidatedAt           time.Time `json:"validated_at"`
}

func (m CorpusManifest) Validate() error {
	if m.Schema != CorpusSchemaVersion {
		return fmt.Errorf("unsupported corpus schema %d", m.Schema)
	}
	if m.Class != CorpusClassClean && m.Class != CorpusClassMalware {
		return fmt.Errorf("invalid corpus class %q", m.Class)
	}
	if strings.TrimSpace(m.ID) == "" {
		return errors.New("corpus id is required")
	}
	if m.CreatedAt.IsZero() {
		return errors.New("corpus created_at is required")
	}
	if len(m.Entries) == 0 {
		return errors.New("corpus entries are required")
	}
	seen := make(map[string]struct{}, len(m.Entries))
	for i, entry := range m.Entries {
		if !validSHA256(entry.SHA256) {
			return fmt.Errorf("corpus entry %d has invalid sha256", i)
		}
		if entry.Size < 0 {
			return fmt.Errorf("corpus entry %d has negative size", i)
		}
		if _, ok := seen[entry.SHA256]; ok {
			return fmt.Errorf("duplicate corpus sha256 %s", entry.SHA256)
		}
		seen[entry.SHA256] = struct{}{}
	}
	return nil
}

func (m CorpusManifest) CanonicalBytes() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	canonical := m
	canonical.CreatedAt = canonical.CreatedAt.UTC()
	canonical.Entries = append([]CorpusEntry(nil), m.Entries...)
	sort.Slice(canonical.Entries, func(i, j int) bool {
		if canonical.Entries[i].SHA256 == canonical.Entries[j].SHA256 {
			return canonical.Entries[i].Size < canonical.Entries[j].Size
		}
		return canonical.Entries[i].SHA256 < canonical.Entries[j].SHA256
	})
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("encode corpus manifest: %w", err)
	}
	return append(encoded, '\n'), nil
}

func (m CorpusManifest) SHA256() (string, error) {
	encoded, err := m.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func DecodeCorpusManifestStrict(data []byte) (CorpusManifest, error) {
	var manifest CorpusManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return CorpusManifest{}, fmt.Errorf("decode corpus manifest: %w", err)
	}
	if decoder.More() {
		return CorpusManifest{}, errors.New("decode corpus manifest: trailing data")
	}
	if err := manifest.Validate(); err != nil {
		return CorpusManifest{}, err
	}
	return manifest, nil
}

func (r CorpusValidationResult) Validate() error {
	if r.Schema != CorpusSchemaVersion {
		return fmt.Errorf("unsupported corpus validation schema %d", r.Schema)
	}
	if !candidateIDPattern.MatchString(r.CandidateID) {
		return errors.New("invalid candidate id")
	}
	if !validSHA256(r.PatternSHA256) || !validSHA256(r.CleanManifestSHA256) || !validSHA256(r.MalwareManifestSHA256) {
		return errors.New("validation result requires valid lowercase sha256 identities")
	}
	if r.CleanSampleCount < 0 || r.CleanMatchCount < 0 || r.MalwareSampleCount < 0 || r.MalwareMatchCount < 0 {
		return errors.New("validation counts cannot be negative")
	}
	if r.CleanMatchCount != len(r.CleanMatches) || r.MalwareMatchCount != len(r.MalwareMatches) {
		return errors.New("validation match counts do not match match lists")
	}
	if r.CleanMatchCount > r.CleanSampleCount || r.MalwareMatchCount > r.MalwareSampleCount {
		return errors.New("validation match count exceeds sample count")
	}
	if r.ValidatedAt.IsZero() {
		return errors.New("validated_at is required")
	}
	if err := validateSortedUniqueHashes(r.CleanMatches); err != nil {
		return fmt.Errorf("clean matches: %w", err)
	}
	if err := validateSortedUniqueHashes(r.MalwareMatches); err != nil {
		return fmt.Errorf("malware matches: %w", err)
	}
	return nil
}

func (r CorpusValidationResult) PassingPatternGate() bool {
	return r.Validate() == nil && r.CleanMatchCount == 0 && r.MalwareMatchCount > 0
}

func validateSortedUniqueHashes(values []string) error {
	for i, value := range values {
		if !validSHA256(value) {
			return fmt.Errorf("invalid sha256 at index %d", i)
		}
		if i > 0 && values[i-1] >= value {
			return errors.New("hashes must be strictly sorted and unique")
		}
	}
	return nil
}
