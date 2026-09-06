package signaturefactory

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// AmiGuardResearchRecord is a conservative handoff format for Ploos-AS/AmiGuard.
// AAA never promotes an AmiGuard signature automatically: the exported record is
// always research-only and must be independently qualified in the AmiGuard repo.
type AmiGuardResearchRecord struct {
	Schema       int                     `json:"schema"`
	ID           string                  `json:"id"`
	Name         string                  `json:"name"`
	Family       string                  `json:"family"`
	Kind         string                  `json:"kind"`
	Status       string                  `json:"status"`
	Synthetic    bool                    `json:"synthetic"`
	Source       AmiGuardSource          `json:"source"`
	Provenance   AmiGuardProvenance      `json:"provenance"`
	SampleSHA256 *string                 `json:"sample_sha256"`
	Signature    *AmiGuardSignature      `json:"signature"`
	Verifier     string                  `json:"verifier"`
	Cleaner      string                  `json:"cleaner"`
	Research     *AmiGuardResearchDetail `json:"research,omitempty"`
}

type AmiGuardSource struct {
	Type      string `json:"type"`
	Reference string `json:"reference"`
}

type AmiGuardProvenance struct {
	Derivation           string `json:"derivation"`
	VerificationRequired string `json:"verification_required"`
}

type AmiGuardSignature struct {
	Offset int64  `json:"offset"`
	Bytes  string `json:"bytes"`
	Mask   string `json:"mask"`
}

type AmiGuardResearchDetail struct {
	AAAStatus          Status     `json:"aaa_status"`
	AAAKind            Kind       `json:"aaa_kind"`
	AAAConfidence      Confidence `json:"aaa_confidence"`
	SourceEngine       string     `json:"source_engine"`
	SourceVersion      string     `json:"source_version,omitempty"`
	OSProfile          string     `json:"os_profile,omitempty"`
	SignatureDBVersion string     `json:"signature_db_version,omitempty"`
	DetectionName      string     `json:"detection_name"`
	Note               string     `json:"note"`
}

// ExportAmiGuardResearch converts one validated AAA candidate into a deterministic
// AmiGuard research record. Only fixed-offset exact byte patterns can be mapped
// losslessly to AmiGuard's current offset/bytes/mask signature form. Other AAA
// candidate kinds remain useful research handoffs but carry signature=null.
func ExportAmiGuardResearch(candidate Candidate) (AmiGuardResearchRecord, error) {
	if err := candidate.Validate(); err != nil {
		return AmiGuardResearchRecord{}, fmt.Errorf("invalid AAA candidate: %w", err)
	}
	family, suffix, err := candidateFamilyAndSuffix(candidate.ID)
	if err != nil {
		return AmiGuardResearchRecord{}, err
	}

	record := AmiGuardResearchRecord{
		Schema:    1,
		ID:        "aaa." + strings.ToLower(family) + "." + suffix,
		Name:      candidate.MalwareName,
		Family:    family,
		Kind:      "bootblock",
		Status:    "research",
		Synthetic: false,
		Source: AmiGuardSource{
			Type:      "aaa-candidate",
			Reference: candidate.ID,
		},
		Provenance: AmiGuardProvenance{
			Derivation:           "Generated from a validated AAA signature-factory candidate; no automatic AmiGuard promotion is implied.",
			VerificationRequired: "Re-derive and verify the signature independently against legally analyzable clean and infected samples before promotion in AmiGuard.",
		},
		Verifier: "pending-sample-qualification",
		Cleaner:  "none",
		Research: &AmiGuardResearchDetail{
			AAAStatus:          candidate.Status,
			AAAKind:            candidate.Kind,
			AAAConfidence:      candidate.Confidence,
			SourceEngine:       candidate.SourceEngine,
			SourceVersion:      candidate.SourceVersion,
			OSProfile:          candidate.OSProfile,
			SignatureDBVersion: candidate.SignatureDBVersion,
			DetectionName:      candidate.DetectionName,
		},
	}
	if candidate.SampleSHA256 != "" {
		sample := candidate.SampleSHA256
		record.SampleSHA256 = &sample
	}

	switch candidate.Kind {
	case KindPattern:
		if candidate.Pattern == nil {
			return AmiGuardResearchRecord{}, errors.New("AAA pattern candidate has no pattern")
		}
		if candidate.Pattern.Offset == nil {
			record.Research.Note = "AAA pattern is any-offset and cannot be mapped losslessly to AmiGuard's fixed-offset signature; derive an offset/mask before promotion."
			return record, nil
		}
		bytesHex := candidate.Pattern.BytesHex
		record.Signature = &AmiGuardSignature{
			Offset: *candidate.Pattern.Offset,
			Bytes:  bytesHex,
			Mask:   strings.Repeat("ff", len(bytesHex)/2),
		}
		record.Research.Note = "Exact AAA fixed-offset pattern mapped to an all-bits-significant AmiGuard mask; still research-only until AmiGuard qualification."
	case KindBootblockSHA256:
		record.Research.Note = "AAA bootblock SHA-256 candidate has no byte pattern; use its sample/evidence to derive an AmiGuard offset/bytes/mask signature."
	case KindFileSHA256:
		record.Research.Note = "AAA file SHA-256 candidate is not directly representable as an AmiGuard bootblock byte signature."
	default:
		return AmiGuardResearchRecord{}, fmt.Errorf("unsupported AAA candidate kind %q", candidate.Kind)
	}
	return record, nil
}

func MarshalAmiGuardResearch(candidate Candidate) ([]byte, error) {
	record, err := ExportAmiGuardResearch(candidate)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func candidateFamilyAndSuffix(id string) (string, string, error) {
	const prefix = "AAA.Amiga."
	if !strings.HasPrefix(id, prefix) {
		return "", "", errors.New("AAA candidate id has unexpected prefix")
	}
	rest := strings.TrimPrefix(id, prefix)
	lastDot := strings.LastIndexByte(rest, '.')
	if lastDot <= 0 || lastDot == len(rest)-1 {
		return "", "", errors.New("AAA candidate id has no family/suffix boundary")
	}
	return rest[:lastDot], rest[lastDot+1:], nil
}
