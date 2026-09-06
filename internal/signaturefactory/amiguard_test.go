package signaturefactory

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestExportAmiGuardResearchFixedPattern(t *testing.T) {
	offset := int64(64)
	candidate, err := NewPatternCandidate(PatternCandidateInput{
		Family:        "SCA",
		MalwareName:   "SCA",
		SampleSHA256:  strings.Repeat("a", 64),
		SampleSize:    901120,
		Format:        "adf",
		Pattern:       FixedPattern{BytesHex: "414d494755415244", Offset: &offset},
		SourceEngine:  "vtschutz",
		SourceVersion: "3.17",
		OSProfile:     "os13",
		DetectionName: "SCA",
		Confidence:    ConfidenceCorroborated,
		CreatedAt:     time.Date(2026, 9, 6, 19, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := ExportAmiGuardResearch(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != "research" || record.Source.Type != "aaa-candidate" {
		t.Fatalf("unexpected research boundary: %#v", record)
	}
	if record.SampleSHA256 != nil || record.Signature != nil {
		t.Fatal("AmiGuard research records must keep sample_sha256 and signature null")
	}
	proposal := record.Research.ProposedSignature
	if proposal == nil {
		t.Fatal("fixed-offset AAA pattern should be preserved as a research proposal")
	}
	if proposal.Offset != 64 || proposal.Bytes != "414d494755415244" || proposal.Mask != "ffffffffffffffff" {
		t.Fatalf("unexpected proposed signature: %#v", proposal)
	}
	if record.Research.AAASampleSHA256 != candidate.SampleSHA256 {
		t.Fatal("AAA sample provenance lost")
	}
}

func TestExportAmiGuardResearchAnyOffsetStaysResearchOnly(t *testing.T) {
	candidate, err := NewPatternCandidate(PatternCandidateInput{
		Family:        "Fixture",
		MalwareName:   "Fixture",
		SampleSHA256:  strings.Repeat("b", 64),
		Pattern:       FixedPattern{BytesHex: "0011223344556677"},
		SourceEngine:  "fixture",
		SourceVersion: "1",
		DetectionName: "Fixture",
		Confidence:    ConfidenceSingleEngine,
		CreatedAt:     time.Date(2026, 9, 6, 19, 1, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := ExportAmiGuardResearch(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if record.Signature != nil || record.Research.ProposedSignature != nil {
		t.Fatal("any-offset pattern must not be converted to a fixed AmiGuard signature")
	}
	if !strings.Contains(record.Research.Note, "any-offset") {
		t.Fatalf("missing conservative research note: %#v", record.Research)
	}
}

func TestExportAmiGuardResearchBootblockHashDoesNotClaimVerifiedSample(t *testing.T) {
	candidate, err := NewExactCandidate(ExactCandidateInput{
		Family:          "ByteBandit",
		Kind:            KindBootblockSHA256,
		MalwareName:     "Byte Bandit",
		SampleSHA256:    strings.Repeat("c", 64),
		BootblockSHA256: strings.Repeat("d", 64),
		SampleSize:      901120,
		Format:          "adf",
		SourceEngine:    "virusz3",
		SourceVersion:   "1.04ß",
		OSProfile:       "os31",
		DetectionName:   "Byte Bandit",
		Confidence:      ConfidenceConfirmed,
		CreatedAt:       time.Date(2026, 9, 6, 19, 2, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := ExportAmiGuardResearch(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if record.SampleSHA256 != nil || record.Signature != nil {
		t.Fatal("research record must not claim AmiGuard verification")
	}
	if record.Research.AAASampleSHA256 != candidate.SampleSHA256 || record.Research.AAABootblockSHA256 != candidate.BootblockSHA256 {
		t.Fatal("AAA hash provenance lost")
	}
}

func TestMarshalAmiGuardResearchIsStableJSON(t *testing.T) {
	offset := int64(8)
	candidate, err := NewPatternCandidate(PatternCandidateInput{
		Family:        "Fixture",
		MalwareName:   "Fixture",
		SampleSHA256:  strings.Repeat("e", 64),
		Pattern:       FixedPattern{BytesHex: "deadbeefcafebabe", Offset: &offset},
		SourceEngine:  "fixture",
		DetectionName: "Fixture",
		Confidence:    ConfidenceSingleEngine,
		CreatedAt:     time.Date(2026, 9, 6, 19, 3, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := MarshalAmiGuardResearch(candidate)
	if err != nil {
		t.Fatal(err)
	}
	second, err := MarshalAmiGuardResearch(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("AmiGuard research JSON is not deterministic")
	}
	var decoded AmiGuardResearchRecord
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SampleSHA256 != nil || decoded.Signature != nil || decoded.Verifier != "pending-sample-qualification" {
		t.Fatalf("unexpected decoded record: %#v", decoded)
	}
	if decoded.Research == nil || decoded.Research.ProposedSignature == nil {
		t.Fatalf("missing research proposal: %#v", decoded.Research)
	}
}

func TestAmiGuardCompilerResearchContract(t *testing.T) {
	offset := int64(16)
	candidate, err := NewPatternCandidate(PatternCandidateInput{
		Family:        "Contract",
		MalwareName:   "Contract Fixture",
		SampleSHA256:  strings.Repeat("f", 64),
		Pattern:       FixedPattern{BytesHex: "0011223344556677", Offset: &offset},
		SourceEngine:  "fixture",
		DetectionName: "Contract Fixture",
		Confidence:    ConfidenceSingleEngine,
		CreatedAt:     time.Date(2026, 9, 6, 19, 4, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := ExportAmiGuardResearch(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if record.Schema != 1 || record.Kind != "bootblock" || record.Status != "research" || record.Synthetic {
		t.Fatalf("record violates AmiGuard research metadata contract: %#v", record)
	}
	if record.SampleSHA256 != nil {
		t.Fatal("AmiGuard research compiler requires sample_sha256=null")
	}
	if record.Signature != nil {
		t.Fatal("AmiGuard research compiler requires signature=null")
	}
	if record.ID == "" || record.Name == "" || record.Family == "" || record.Verifier == "" || record.Cleaner == "" {
		t.Fatal("AmiGuard required string field missing")
	}
}
