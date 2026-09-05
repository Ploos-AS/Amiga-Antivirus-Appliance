package signaturefactory

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	SchemaVersion = 1
	CreatedBy     = "aaa-signature-factory"
)

type Status string

type Kind string

type Confidence string

const (
	StatusCandidate Status = "candidate"
	StatusPromoted  Status = "promoted"
	StatusRejected  Status = "rejected"

	KindFileSHA256      Kind = "file-sha256"
	KindBootblockSHA256 Kind = "bootblock-sha256"
	KindPattern         Kind = "pattern"

	ConfidenceSingleEngine Confidence = "single-engine"
	ConfidenceCorroborated Confidence = "corroborated"
	ConfidenceConfirmed    Confidence = "confirmed"
)

var candidateIDPattern = regexp.MustCompile(`^AAA\.Amiga\.[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.[a-f0-9]{16}$`)

type Evidence struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

type Candidate struct {
	Schema             int        `json:"schema"`
	ID                 string     `json:"id"`
	Status             Status     `json:"status"`
	Kind               Kind       `json:"kind"`
	MalwareName        string     `json:"malware_name"`
	SampleSHA256       string     `json:"sample_sha256,omitempty"`
	BootblockSHA256    string     `json:"bootblock_sha256,omitempty"`
	SampleSize         int64      `json:"sample_size,omitempty"`
	Format             string     `json:"format,omitempty"`
	SourceEngine       string     `json:"source_engine"`
	SourceVersion      string     `json:"source_version,omitempty"`
	OSProfile          string     `json:"os_profile,omitempty"`
	SignatureDBVersion string     `json:"signature_db_version,omitempty"`
	DetectionName      string     `json:"detection_name"`
	Confidence         Confidence `json:"confidence"`
	Evidence           []Evidence `json:"evidence,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	CreatedBy          string     `json:"created_by"`
}

type ExactCandidateInput struct {
	Family             string
	Kind               Kind
	MalwareName        string
	SampleSHA256       string
	BootblockSHA256    string
	SampleSize         int64
	Format             string
	SourceEngine       string
	SourceVersion      string
	OSProfile          string
	SignatureDBVersion string
	DetectionName      string
	Confidence         Confidence
	Evidence           []Evidence
	CreatedAt          time.Time
}

func NewExactCandidate(input ExactCandidateInput) (Candidate, error) {
	if input.Kind != KindFileSHA256 && input.Kind != KindBootblockSHA256 {
		return Candidate{}, fmt.Errorf("unsupported exact candidate kind %q", input.Kind)
	}
	if input.CreatedAt.IsZero() {
		return Candidate{}, errors.New("created_at is required")
	}
	if !validFamily(input.Family) {
		return Candidate{}, errors.New("invalid malware family")
	}

	identityHash := input.SampleSHA256
	if input.Kind == KindBootblockSHA256 {
		identityHash = input.BootblockSHA256
	}
	if !validSHA256(identityHash) {
		return Candidate{}, errors.New("candidate identity requires a lowercase SHA-256")
	}

	candidate := Candidate{
		Schema:             SchemaVersion,
		ID:                 "AAA.Amiga." + input.Family + "." + identityHash[:16],
		Status:             StatusCandidate,
		Kind:               input.Kind,
		MalwareName:        input.MalwareName,
		SampleSHA256:       input.SampleSHA256,
		BootblockSHA256:    input.BootblockSHA256,
		SampleSize:         input.SampleSize,
		Format:             input.Format,
		SourceEngine:       input.SourceEngine,
		SourceVersion:      input.SourceVersion,
		OSProfile:          input.OSProfile,
		SignatureDBVersion: input.SignatureDBVersion,
		DetectionName:      input.DetectionName,
		Confidence:         input.Confidence,
		Evidence:           append([]Evidence(nil), input.Evidence...),
		CreatedAt:          input.CreatedAt.UTC(),
		CreatedBy:          CreatedBy,
	}
	if err := candidate.Validate(); err != nil {
		return Candidate{}, err
	}
	return candidate, nil
}

func (c Candidate) Validate() error {
	if c.Schema != SchemaVersion {
		return fmt.Errorf("unsupported candidate schema %d", c.Schema)
	}
	if !candidateIDPattern.MatchString(c.ID) {
		return errors.New("invalid candidate id")
	}
	if c.Status != StatusCandidate && c.Status != StatusPromoted && c.Status != StatusRejected {
		return fmt.Errorf("invalid candidate status %q", c.Status)
	}
	if c.Kind != KindFileSHA256 && c.Kind != KindBootblockSHA256 && c.Kind != KindPattern {
		return fmt.Errorf("invalid candidate kind %q", c.Kind)
	}
	if strings.TrimSpace(c.MalwareName) == "" {
		return errors.New("malware_name is required")
	}
	if strings.TrimSpace(c.SourceEngine) == "" {
		return errors.New("source_engine is required")
	}
	if strings.TrimSpace(c.DetectionName) == "" {
		return errors.New("detection_name is required")
	}
	if c.Confidence != ConfidenceSingleEngine && c.Confidence != ConfidenceCorroborated && c.Confidence != ConfidenceConfirmed {
		return fmt.Errorf("invalid confidence %q", c.Confidence)
	}
	if c.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	if c.CreatedBy != CreatedBy {
		return fmt.Errorf("invalid created_by %q", c.CreatedBy)
	}
	if c.SampleSize < 0 {
		return errors.New("sample_size cannot be negative")
	}
	if c.SampleSHA256 != "" && !validSHA256(c.SampleSHA256) {
		return errors.New("invalid sample_sha256")
	}
	if c.BootblockSHA256 != "" && !validSHA256(c.BootblockSHA256) {
		return errors.New("invalid bootblock_sha256")
	}

	switch c.Kind {
	case KindFileSHA256:
		if !validSHA256(c.SampleSHA256) {
			return errors.New("file-sha256 candidate requires sample_sha256")
		}
	case KindBootblockSHA256:
		if !validSHA256(c.SampleSHA256) || !validSHA256(c.BootblockSHA256) {
			return errors.New("bootblock-sha256 candidate requires sample and bootblock SHA-256")
		}
	case KindPattern:
		return errors.New("pattern candidates are not enabled in M7.0")
	}
	return nil
}

func validFamily(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return value[0] != '.' && value[0] != '-' && value[0] != '_'
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
