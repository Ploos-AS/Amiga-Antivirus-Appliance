package support

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Kind identifies independently versioned support data used by historical
// Amiga antivirus engines.
type Kind string

const (
	KindXVS              Kind = "xvs-library"
	KindVirusZBootblocks Kind = "virusz-iii-bootblocks"
)

// Component records the exact identity of one support artifact. Third-party
// binaries are user supplied; AAA records identity and provenance only.
type Component struct {
	Kind    Kind   `json:"kind"`
	Name    string `json:"name"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Source  string `json:"source,omitempty"`
}

// Validate rejects incomplete or ambiguous provenance records.
func (c Component) Validate() error {
	switch c.Kind {
	case KindXVS, KindVirusZBootblocks:
	default:
		return fmt.Errorf("unsupported support component kind %q", c.Kind)
	}
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("component name is required")
	}
	if strings.TrimSpace(c.Version) == "" {
		return errors.New("component version is required")
	}
	if len(c.SHA256) != 64 {
		return errors.New("component SHA-256 must contain 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(c.SHA256); err != nil {
		return fmt.Errorf("invalid component SHA-256: %w", err)
	}
	return nil
}

// IdentifyFile hashes a user-supplied support artifact and returns a validated
// provenance record. It does not copy or redistribute the artifact.
func IdentifyFile(kind Kind, name, version, source, path string) (Component, error) {
	f, err := os.Open(path)
	if err != nil {
		return Component{}, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return Component{}, err
	}
	c := Component{
		Kind:    kind,
		Name:    name,
		Version: version,
		SHA256:  hex.EncodeToString(h.Sum(nil)),
		Source:  source,
	}
	if err := c.Validate(); err != nil {
		return Component{}, err
	}
	return c, nil
}

// EngineProvenance binds an engine run to the independently versioned support
// artifacts that influenced its interpretation.
type EngineProvenance struct {
	EngineID      string      `json:"engine_id"`
	EngineVersion string      `json:"engine_version"`
	Components    []Component `json:"components,omitempty"`
}

// Validate requires unique component kinds and complete component identities.
func (p EngineProvenance) Validate() error {
	if strings.TrimSpace(p.EngineID) == "" {
		return errors.New("engine id is required")
	}
	if strings.TrimSpace(p.EngineVersion) == "" {
		return errors.New("engine version is required")
	}
	seen := make(map[Kind]struct{}, len(p.Components))
	for _, c := range p.Components {
		if err := c.Validate(); err != nil {
			return err
		}
		if _, ok := seen[c.Kind]; ok {
			return fmt.Errorf("duplicate support component kind %q", c.Kind)
		}
		seen[c.Kind] = struct{}{}
	}
	return nil
}
