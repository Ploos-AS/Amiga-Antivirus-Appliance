package acquisition

import (
	"errors"
	"fmt"
	"time"
)

const SessionSchema = "aaa-acquisition-session-v1"

// Session binds preservation and decoded acquisitions that an operator states
// belong to one physical-media handling session. It does not claim that an ADF
// was derived from the SCP capture.
type Session struct {
	Schema        string         `json:"schema"`
	CreatedAt     time.Time      `json:"created_at"`
	Note          string         `json:"note,omitempty"`
	Flux          Evidence       `json:"flux"`
	ADFReads      []Evidence     `json:"adf_reads"`
	Repeatability Repeatability  `json:"repeatability"`
	Relationship  string         `json:"relationship"`
}

// BuildSession validates and binds independently acquired evidence into one
// session-level provenance object.
func BuildSession(flux Evidence, adfReads []Evidence, note string, createdAt time.Time) (Session, error) {
	if err := flux.Validate(); err != nil {
		return Session{}, fmt.Errorf("flux evidence: %w", err)
	}
	if flux.Format != "scp-raw-flux" || flux.Method != "physical-floppy-flux" {
		return Session{}, errors.New("session flux evidence must be raw SCP physical-floppy flux")
	}
	if len(adfReads) == 0 {
		return Session{}, errors.New("session requires at least one ADF acquisition")
	}
	for i, e := range adfReads {
		if err := e.Validate(); err != nil {
			return Session{}, fmt.Errorf("ADF read %d: %w", i+1, err)
		}
		if e.Format != "adf" || e.Method != "physical-floppy" {
			return Session{}, fmt.Errorf("ADF read %d is not a physical-floppy ADF acquisition", i+1)
		}
		if flux.Device != "" && e.Device != "" && flux.Device != e.Device {
			return Session{}, fmt.Errorf("ADF read %d device does not match flux device", i+1)
		}
	}
	repeatability, err := CompareReads(adfReads)
	if err != nil {
		return Session{}, fmt.Errorf("compare ADF reads: %w", err)
	}
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	return Session{
		Schema:        SessionSchema,
		CreatedAt:     createdAt.UTC(),
		Note:          note,
		Flux:          flux,
		ADFReads:      append([]Evidence(nil), adfReads...),
		Repeatability: repeatability,
		Relationship:  "same-operator-session; no SCP-to-ADF derivation asserted",
	}, nil
}
