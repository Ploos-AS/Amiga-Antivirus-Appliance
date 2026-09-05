package signaturefactory

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type Evidence struct {
	Type               string `json:"type"`
	Detail             string `json:"detail"`
	SourceEngine       string `json:"source_engine,omitempty"`
	SourceVersion      string `json:"source_version,omitempty"`
	SignatureDBVersion string `json:"signature_db_version,omitempty"`
	OSProfile          string `json:"os_profile,omitempty"`
	CorrelationKey     string `json:"correlation_key,omitempty"`
}

func (e Evidence) Validate() error {
	if strings.TrimSpace(e.Type) == "" {
		return errors.New("evidence type is required")
	}
	if strings.TrimSpace(e.Detail) == "" {
		return errors.New("evidence detail is required")
	}
	attributed := strings.TrimSpace(e.SourceEngine) != "" ||
		strings.TrimSpace(e.SourceVersion) != "" ||
		strings.TrimSpace(e.SignatureDBVersion) != "" ||
		strings.TrimSpace(e.OSProfile) != "" ||
		strings.TrimSpace(e.CorrelationKey) != ""
	if !attributed {
		return nil
	}
	if strings.TrimSpace(e.SourceEngine) == "" {
		return errors.New("attributed evidence requires source_engine")
	}
	if strings.TrimSpace(e.CorrelationKey) == "" {
		return errors.New("attributed evidence requires correlation_key")
	}
	if strings.ContainsAny(e.CorrelationKey, "\r\n\t") {
		return errors.New("correlation_key contains control whitespace")
	}
	return nil
}

// IndependentEvidenceSources returns the number of independent knowledge sources
// represented by attributed evidence. Multiple scanner frontends that use the same
// underlying database must deliberately use the same correlation key and therefore
// count only once.
func IndependentEvidenceSources(evidence []Evidence) (int, error) {
	keys := make(map[string]struct{})
	for i, item := range evidence {
		if err := item.Validate(); err != nil {
			return 0, fmt.Errorf("evidence %d: %w", i, err)
		}
		key := strings.TrimSpace(item.CorrelationKey)
		if key == "" {
			continue
		}
		keys[key] = struct{}{}
	}
	return len(keys), nil
}

// IndependentCorrelationKeys returns a deterministic sorted list for reports and
// future policy gates.
func IndependentCorrelationKeys(evidence []Evidence) ([]string, error) {
	keys := make(map[string]struct{})
	for i, item := range evidence {
		if err := item.Validate(); err != nil {
			return nil, fmt.Errorf("evidence %d: %w", i, err)
		}
		if key := strings.TrimSpace(item.CorrelationKey); key != "" {
			keys[key] = struct{}{}
		}
	}
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	sort.Strings(result)
	return result, nil
}
