package acquisition

import (
	"strings"
	"testing"
	"time"
)

func validFluxEvidence(hash string) Evidence {
	e := validEvidence(hash)
	e.Method = "physical-floppy-flux"
	e.Format = "scp-raw-flux"
	e.OutputName = "disk.scp"
	e.Device = "gw0"
	return e
}

func TestBuildSessionBindsFluxAndRepeatedADFWithoutDerivationClaim(t *testing.T) {
	flux := validFluxEvidence(strings.Repeat("f", 64))
	a := validEvidence(strings.Repeat("a", 64))
	b := validEvidence(strings.Repeat("a", 64))
	a.Device, b.Device = "gw0", "gw0"
	created := time.Date(2026, 9, 7, 14, 0, 0, 0, time.UTC)

	s, err := BuildSession(flux, []Evidence{a, b}, "label: Workbench disk", created)
	if err != nil {
		t.Fatal(err)
	}
	if s.Schema != SessionSchema || s.CreatedAt != created || s.Note == "" {
		t.Fatalf("session metadata=%+v", s)
	}
	if s.Flux.OutputSHA256 != flux.OutputSHA256 || len(s.ADFReads) != 2 {
		t.Fatalf("session evidence=%+v", s)
	}
	if s.Repeatability.Status != RepeatabilityReproducible {
		t.Fatalf("repeatability=%+v", s.Repeatability)
	}
	if s.Relationship != "same-operator-session; no SCP-to-ADF derivation asserted" {
		t.Fatalf("relationship=%q", s.Relationship)
	}
}

func TestBuildSessionAllowsDivergentADFReads(t *testing.T) {
	flux := validFluxEvidence(strings.Repeat("f", 64))
	a := validEvidence(strings.Repeat("a", 64))
	b := validEvidence(strings.Repeat("b", 64))
	a.Device, b.Device = "gw0", "gw0"

	s, err := BuildSession(flux, []Evidence{a, b}, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if s.Repeatability.Status != RepeatabilityDivergent {
		t.Fatalf("repeatability=%+v", s.Repeatability)
	}
}

func TestBuildSessionRejectsWrongFluxEvidence(t *testing.T) {
	flux := validEvidence(strings.Repeat("f", 64))
	_, err := BuildSession(flux, []Evidence{validEvidence(strings.Repeat("a", 64))}, "", time.Now())
	if err == nil {
		t.Fatal("expected flux validation error")
	}
}

func TestBuildSessionRejectsDeviceMismatch(t *testing.T) {
	flux := validFluxEvidence(strings.Repeat("f", 64))
	adf := validEvidence(strings.Repeat("a", 64))
	adf.Device = "gw1"
	_, err := BuildSession(flux, []Evidence{adf}, "", time.Now())
	if err == nil {
		t.Fatal("expected device mismatch")
	}
}
