package engineevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Kind identifies the independent analysis implementation that produced evidence.
type Kind string

const (
	KindNative     Kind = "native"
	KindClamAV     Kind = "clamav"
	KindHistorical Kind = "historical-amiga"
)

// Status distinguishes a completed engine verdict from execution/integration failure.
type Status string

const (
	StatusCompleted Status = "completed"
	StatusError     Status = "error"
)

// Component captures independently versioned support data used by an engine.
type Component struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Version string `json:"version"`
	SHA256  string `json:"sha256,omitempty"`
	Source  string `json:"source,omitempty"`
}

// Result is the common engine-attribution envelope exposed through M9 history/API
// and consumed by M10. Specialized native, ClamAV and M8 records may retain
// additional detail elsewhere; this record preserves their comparable identity.
type Result struct {
	Kind              Kind        `json:"kind"`
	EngineID          string      `json:"engine_id"`
	EngineName        string      `json:"engine_name"`
	EngineVersion     string      `json:"engine_version,omitempty"`
	Status            Status      `json:"status"`
	Verdict           string      `json:"verdict"`
	DetectionName     string      `json:"detection_name,omitempty"`
	InputSHA256       string      `json:"input_sha256"`
	DatabaseID        string      `json:"database_id,omitempty"`
	DatabaseVersion   string      `json:"database_version,omitempty"`
	OSProfile         string      `json:"os_profile,omitempty"`
	BinarySHA256      string      `json:"binary_sha256,omitempty"`
	RawEvidenceSHA256 string      `json:"raw_evidence_sha256,omitempty"`
	StartedAt         *time.Time  `json:"started_at,omitempty"`
	FinishedAt        *time.Time  `json:"finished_at,omitempty"`
	Components        []Component `json:"components,omitempty"`
	Error             string      `json:"error,omitempty"`
}

func (r Result) Validate() error {
	if !r.Kind.Valid() {
		return fmt.Errorf("invalid engine kind %q", r.Kind)
	}
	if strings.TrimSpace(r.EngineID) == "" || strings.TrimSpace(r.EngineName) == "" {
		return errors.New("engine id and name are required")
	}
	if r.Status != StatusCompleted && r.Status != StatusError {
		return fmt.Errorf("invalid engine status %q", r.Status)
	}
	if !validSHA256(r.InputSHA256) {
		return errors.New("input SHA-256 must be lowercase SHA-256")
	}
	if r.BinarySHA256 != "" && !validSHA256(r.BinarySHA256) {
		return errors.New("binary SHA-256 must be lowercase SHA-256")
	}
	if r.RawEvidenceSHA256 != "" && !validSHA256(r.RawEvidenceSHA256) {
		return errors.New("raw evidence SHA-256 must be lowercase SHA-256")
	}
	if r.Status == StatusCompleted {
		if strings.TrimSpace(r.EngineVersion) == "" {
			return errors.New("completed engine result requires engine version")
		}
		if strings.TrimSpace(r.Verdict) == "" {
			return errors.New("completed engine result requires verdict")
		}
	} else if strings.TrimSpace(r.Error) == "" {
		return errors.New("error engine result requires error text")
	}
	if r.Verdict == "infected" && strings.TrimSpace(r.DetectionName) == "" {
		return errors.New("infected engine result requires detection name")
	}
	if (r.StartedAt == nil) != (r.FinishedAt == nil) {
		return errors.New("engine timestamps must be both present or both absent")
	}
	if r.StartedAt != nil && r.FinishedAt.Before(*r.StartedAt) {
		return errors.New("engine finish time precedes start time")
	}
	seenComponents := make(map[string]struct{}, len(r.Components))
	for _, component := range r.Components {
		if strings.TrimSpace(component.Kind) == "" || strings.TrimSpace(component.Name) == "" || strings.TrimSpace(component.Version) == "" {
			return errors.New("engine component kind, name and version are required")
		}
		if component.SHA256 != "" && !validSHA256(component.SHA256) {
			return errors.New("engine component SHA-256 must be lowercase SHA-256")
		}
		if _, ok := seenComponents[component.Kind]; ok {
			return fmt.Errorf("duplicate engine component kind %q", component.Kind)
		}
		seenComponents[component.Kind] = struct{}{}
	}
	return nil
}

func (k Kind) Valid() bool {
	switch k {
	case KindNative, KindClamAV, KindHistorical:
		return true
	default:
		return false
	}
}

func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
