package signatures

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

//go:embed bootblocks.json
var bundledFS embed.FS

const (
	StatusKnownClean     = "known-clean"
	StatusKnownMalicious = "known-malicious"
)

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Entry struct {
	SHA256 string `json:"sha256"`
	Status string `json:"status"`
	Name   string `json:"name"`
	Family string `json:"family,omitempty"`
	Source string `json:"source"`
	Notes  string `json:"notes,omitempty"`
}

type Database struct {
	Schema  int     `json:"schema"`
	Entries []Entry `json:"entries"`
}

type Match struct {
	Status string `json:"status"`
	Name   string `json:"name"`
	Family string `json:"family,omitempty"`
	Source string `json:"source"`
	Notes  string `json:"notes,omitempty"`
}

func LoadBundled() (*Database, error) {
	b, err := bundledFS.ReadFile("bootblocks.json")
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

func Parse(b []byte) (*Database, error) {
	var db Database
	if err := json.Unmarshal(b, &db); err != nil {
		return nil, fmt.Errorf("decode bootblock database: %w", err)
	}
	if db.Schema != 1 {
		return nil, fmt.Errorf("unsupported bootblock database schema: %d", db.Schema)
	}
	seen := make(map[string]struct{}, len(db.Entries))
	for i := range db.Entries {
		e := &db.Entries[i]
		e.SHA256 = strings.ToLower(strings.TrimSpace(e.SHA256))
		e.Status = strings.TrimSpace(e.Status)
		e.Name = strings.TrimSpace(e.Name)
		e.Source = strings.TrimSpace(e.Source)
		if !sha256Pattern.MatchString(e.SHA256) {
			return nil, fmt.Errorf("entry %d has invalid sha256", i)
		}
		if e.Status != StatusKnownClean && e.Status != StatusKnownMalicious {
			return nil, fmt.Errorf("entry %d has invalid status %q", i, e.Status)
		}
		if e.Name == "" {
			return nil, fmt.Errorf("entry %d has empty name", i)
		}
		if e.Source == "" {
			return nil, fmt.Errorf("entry %d has empty source", i)
		}
		if _, ok := seen[e.SHA256]; ok {
			return nil, fmt.Errorf("duplicate bootblock sha256 %s", e.SHA256)
		}
		seen[e.SHA256] = struct{}{}
	}
	return &db, nil
}

func (db *Database) Lookup(sha256 string) *Match {
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	for _, e := range db.Entries {
		if e.SHA256 == sha256 {
			return &Match{Status: e.Status, Name: e.Name, Family: e.Family, Source: e.Source, Notes: e.Notes}
		}
	}
	return nil
}
