package historical

import (
	"strings"
	"testing"
	"time"
)

func TestInitialRegistry(t *testing.T) {
	registry, err := InitialRegistry()
	if err != nil {
		t.Fatal(err)
	}
	engines := registry.Engines()
	if len(engines) != 6 {
		t.Fatalf("engine count=%d want 6", len(engines))
	}
	vt, ok := registry.Engine("vtschutz")
	if !ok {
		t.Fatal("VT-Schutz missing")
	}
	if len(vt.SupportedProfiles) != 1 || vt.SupportedProfiles[0] != OS13 {
		t.Fatalf("VT-Schutz profiles=%v want [os13]", vt.SupportedProfiles)
	}
}

func TestRegistryRejectsDuplicateID(t *testing.T) {
	engine := Engine{ID: "fixture", Name: "Fixture", ExpectedVersion: "1.0", SupportedProfiles: []OSProfile{OS31}}
	if _, err := NewRegistry(engine, engine); err == nil {
		t.Fatal("expected duplicate engine id rejection")
	}
}

func TestEngineRejectsInvalidAndDuplicateProfiles(t *testing.T) {
	for _, profiles := range [][]OSProfile{{"os99"}, {OS31, OS31}} {
		engine := Engine{ID: "fixture", Name: "Fixture", ExpectedVersion: "1.0", SupportedProfiles: profiles}
		if err := engine.Validate(); err == nil {
			t.Fatalf("expected profile rejection for %v", profiles)
		}
	}
}

func TestResultPreservesRawLogEvidence(t *testing.T) {
	start := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	result := Result{
		EngineID:            "fixture",
		EngineName:          "Synthetic Scanner",
		EngineVersion:       "1.0",
		OSProfile:           OS31,
		ScannerBinarySHA256: strings.Repeat("a", 64),
		Verdict:             VerdictInfected,
		DetectionName:       "AAA.Test.Virus",
		RawExit:             "completed",
		RawLog:              []byte("Virus found: AAA.Test.Virus\r\n"),
		InputSHA256:          strings.Repeat("b", 64),
		DerivedInputSHA256:   strings.Repeat("c", 64),
		StartedAt:            start,
		FinishedAt:           start.Add(time.Second),
	}
	result.SealRawLog()
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	if result.RawLogSHA256 != HashBytes(result.RawLog) {
		t.Fatal("raw log digest was not preserved")
	}

	result.RawLog[0] ^= 0xff
	if err := result.Validate(); err == nil {
		t.Fatal("expected mutated raw log rejection")
	}
}

func TestResultFailClosedSemantics(t *testing.T) {
	start := time.Now().UTC()
	base := Result{
		EngineID:            "fixture",
		EngineName:          "Fixture",
		EngineVersion:       "1",
		OSProfile:           OS31,
		ScannerBinarySHA256: strings.Repeat("a", 64),
		Verdict:             VerdictUnknown,
		RawExit:             "completed-unparsed",
		RawLog:              []byte("unrecognized scanner output"),
		InputSHA256:          strings.Repeat("b", 64),
		StartedAt:            start,
		FinishedAt:           start,
	}
	base.SealRawLog()
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}

	infected := base
	infected.Verdict = VerdictInfected
	if err := infected.Validate(); err == nil {
		t.Fatal("infected result without detection name must fail")
	}

	badHash := base
	badHash.InputSHA256 = strings.Repeat("A", 64)
	if err := badHash.Validate(); err == nil {
		t.Fatal("uppercase SHA-256 must fail")
	}
}

func TestRegistryReturnsDefensiveProfileCopies(t *testing.T) {
	registry, err := InitialRegistry()
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := registry.Engine("virusz3")
	engine.SupportedProfiles[0] = OS13
	again, _ := registry.Engine("virusz3")
	if again.SupportedProfiles[0] == OS13 {
		t.Fatal("registry profile metadata was mutated by caller")
	}
}
