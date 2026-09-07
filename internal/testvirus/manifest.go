package testvirus

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Manifest describes a qualification-only corpus of synthetic antivirus test files.
type Manifest struct {
	Schema  int      `json:"schema"`
	Corpus  string   `json:"corpus"`
	Samples []Sample `json:"samples"`
}

// Sample is one synthetic test sample. Synthetic must always be true so this
// corpus cannot be mistaken for real malware evidence by later tooling.
type Sample struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	SHA256             string   `json:"sha256"`
	Synthetic          bool     `json:"synthetic"`
	Source              string   `json:"source"`
	ExpectedDetections []string `json:"expected_detections,omitempty"`
	Notes               string   `json:"notes,omitempty"`
}

func Decode(r io.Reader) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, err
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func (m Manifest) Validate() error {
	if m.Schema != 1 {
		return fmt.Errorf("unsupported schema %d", m.Schema)
	}
	if strings.TrimSpace(m.Corpus) == "" {
		return errors.New("corpus is required")
	}
	seen := make(map[string]struct{}, len(m.Samples))
	for i, sample := range m.Samples {
		if err := sample.validate(); err != nil {
			return fmt.Errorf("sample %d: %w", i, err)
		}
		if _, ok := seen[sample.ID]; ok {
			return fmt.Errorf("sample %d: duplicate id %q", i, sample.ID)
		}
		seen[sample.ID] = struct{}{}
	}
	return nil
}

func (s Sample) validate() error {
	if strings.TrimSpace(s.ID) == "" {
		return errors.New("id is required")
	}
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("name is required")
	}
	if !s.Synthetic {
		return errors.New("synthetic must be true for test-virus corpus samples")
	}
	if strings.TrimSpace(s.Source) == "" {
		return errors.New("source is required")
	}
	if len(s.SHA256) != 64 {
		return errors.New("sha256 must be 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(s.SHA256); err != nil {
		return errors.New("sha256 must be hexadecimal")
	}
	return nil
}
