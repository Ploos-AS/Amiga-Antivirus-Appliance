package historical

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Verdict is the normalized result of one historical Amiga antivirus engine.
type Verdict string

const (
	VerdictClean      Verdict = "clean"
	VerdictInfected   Verdict = "infected"
	VerdictSuspicious Verdict = "suspicious"
	VerdictUnknown    Verdict = "unknown"
	VerdictError      Verdict = "error"
)

// OSProfile identifies a controlled AmigaOS runtime profile.
type OSProfile string

const (
	OS13  OSProfile = "os13"
	OS204 OSProfile = "os204"
	OS31  OSProfile = "os31"
	OS32  OSProfile = "os32"
)

// Engine describes a historical scanner adapter without redistributing it.
type Engine struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	ExpectedVersion  string      `json:"expected_version"`
	SupportedProfiles []OSProfile `json:"supported_profiles"`
}

// Result is derived evidence. RawLog and its digest preserve the scanner's
// original output while the normalized fields make engines comparable.
type Result struct {
	EngineID              string    `json:"engine_id"`
	EngineName            string    `json:"engine_name"`
	EngineVersion         string    `json:"engine_version"`
	OSProfile             OSProfile `json:"os_profile"`
	ScannerBinarySHA256   string    `json:"scanner_binary_sha256"`
	SignatureDatabaseID   string    `json:"signature_database_id,omitempty"`
	Verdict               Verdict   `json:"verdict"`
	DetectionName         string    `json:"detection_name,omitempty"`
	RawExit                string    `json:"raw_exit"`
	RawLog                 []byte    `json:"raw_log"`
	RawLogSHA256           string    `json:"raw_log_sha256"`
	InputSHA256            string    `json:"input_sha256"`
	DerivedInputSHA256     string    `json:"derived_input_sha256,omitempty"`
	StartedAt              time.Time `json:"started_at"`
	FinishedAt             time.Time `json:"finished_at"`
}

func (p OSProfile) Valid() bool {
	switch p {
	case OS13, OS204, OS31, OS32:
		return true
	default:
		return false
	}
}

func (v Verdict) Valid() bool {
	switch v {
	case VerdictClean, VerdictInfected, VerdictSuspicious, VerdictUnknown, VerdictError:
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

func (e Engine) Validate() error {
	if strings.TrimSpace(e.ID) == "" || strings.TrimSpace(e.Name) == "" || strings.TrimSpace(e.ExpectedVersion) == "" {
		return errors.New("historical engine id, name and expected version are required")
	}
	if len(e.SupportedProfiles) == 0 {
		return errors.New("historical engine requires at least one OS profile")
	}
	seen := make(map[OSProfile]struct{}, len(e.SupportedProfiles))
	for _, profile := range e.SupportedProfiles {
		if !profile.Valid() {
			return fmt.Errorf("invalid OS profile %q", profile)
		}
		if _, ok := seen[profile]; ok {
			return fmt.Errorf("duplicate OS profile %q", profile)
		}
		seen[profile] = struct{}{}
	}
	return nil
}

func (r *Result) SealRawLog() {
	r.RawLogSHA256 = HashBytes(r.RawLog)
}

func (r Result) Validate() error {
	if strings.TrimSpace(r.EngineID) == "" || strings.TrimSpace(r.EngineName) == "" || strings.TrimSpace(r.EngineVersion) == "" {
		return errors.New("historical result engine identity is incomplete")
	}
	if !r.OSProfile.Valid() {
		return fmt.Errorf("invalid OS profile %q", r.OSProfile)
	}
	if !r.Verdict.Valid() {
		return fmt.Errorf("invalid verdict %q", r.Verdict)
	}
	if !validSHA256(r.ScannerBinarySHA256) || !validSHA256(r.InputSHA256) {
		return errors.New("scanner and input SHA-256 values must be lowercase SHA-256")
	}
	if r.DerivedInputSHA256 != "" && !validSHA256(r.DerivedInputSHA256) {
		return errors.New("derived input SHA-256 must be lowercase SHA-256")
	}
	if !validSHA256(r.RawLogSHA256) || r.RawLogSHA256 != HashBytes(r.RawLog) {
		return errors.New("raw log SHA-256 does not match raw log")
	}
	if r.StartedAt.IsZero() || r.FinishedAt.IsZero() || r.FinishedAt.Before(r.StartedAt) {
		return errors.New("invalid historical scanner timestamps")
	}
	if r.Verdict == VerdictInfected && strings.TrimSpace(r.DetectionName) == "" {
		return errors.New("infected result requires a detection name")
	}
	return nil
}

// Registry owns immutable engine metadata and rejects ambiguous engine IDs.
type Registry struct {
	engines map[string]Engine
}

func NewRegistry(engines ...Engine) (*Registry, error) {
	r := &Registry{engines: make(map[string]Engine, len(engines))}
	for _, engine := range engines {
		if err := engine.Validate(); err != nil {
			return nil, err
		}
		if _, exists := r.engines[engine.ID]; exists {
			return nil, fmt.Errorf("duplicate historical engine id %q", engine.ID)
		}
		copyEngine := engine
		copyEngine.SupportedProfiles = append([]OSProfile(nil), engine.SupportedProfiles...)
		r.engines[engine.ID] = copyEngine
	}
	return r, nil
}

func (r *Registry) Engine(id string) (Engine, bool) {
	engine, ok := r.engines[id]
	if !ok {
		return Engine{}, false
	}
	engine.SupportedProfiles = append([]OSProfile(nil), engine.SupportedProfiles...)
	return engine, true
}

func (r *Registry) Engines() []Engine {
	ids := make([]string, 0, len(r.engines))
	for id := range r.engines {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Engine, 0, len(ids))
	for _, id := range ids {
		engine, _ := r.Engine(id)
		out = append(out, engine)
	}
	return out
}
