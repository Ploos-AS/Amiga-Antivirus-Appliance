package historical

import (
	"strings"
	"testing"
	"time"
)

func fixtureApplianceQualification() ApplianceQualification {
	start := time.Date(2026, 9, 6, 21, 0, 0, 0, time.UTC)
	return ApplianceQualification{
		Hostname:      "aaa",
		HardwareModel: "Orange Pi Zero 3",
		Architecture:  "aarch64",
		OSName:        "DietPi",
		OSVersion:     "fixture",
		KernelVersion: "fixture",
		AAAVersion:    "fixture",
		StartedAt:     start,
		FinishedAt:    start.Add(2 * time.Second),
		Runs: []ApplianceQualificationRun{
			{
				EngineID:             "virusz3",
				EngineVersion:        "1.04ß",
				OSProfile:            OS31,
				ScannerBinarySHA256:  strings.Repeat("a", 64),
				InputSHA256:          strings.Repeat("b", 64),
				InputSHA256After:     strings.Repeat("b", 64),
				Verdict:              VerdictClean,
				ExitState:            "completed",
				DurationMilliseconds: 1200,
				PeakRSSKiB:           65536,
			},
			{
				EngineID:             "mill",
				EngineVersion:        "0.85",
				OSProfile:            OS204,
				ScannerBinarySHA256:  strings.Repeat("c", 64),
				InputSHA256:          strings.Repeat("d", 64),
				InputSHA256After:     strings.Repeat("d", 64),
				Verdict:              VerdictUnknown,
				ExitState:            "completed",
				DurationMilliseconds: 900,
				PeakRSSKiB:           49152,
			},
		},
	}
}

func TestApplianceQualificationValidFixture(t *testing.T) {
	q := fixtureApplianceQualification()
	if err := q.Validate(); err != nil {
		t.Fatal(err)
	}
	runs := q.SortedRuns()
	if runs[0].EngineID != "mill" || runs[1].EngineID != "virusz3" {
		t.Fatalf("runs not deterministic: %#v", runs)
	}
	if q.Runs[0].EngineID != "virusz3" {
		t.Fatal("SortedRuns mutated source")
	}
}

func TestApplianceQualificationRejectsModifiedInput(t *testing.T) {
	q := fixtureApplianceQualification()
	q.Runs[0].InputSHA256After = strings.Repeat("e", 64)
	if err := q.Validate(); err == nil {
		t.Fatal("expected primary evidence modification rejection")
	}
}

func TestApplianceQualificationRejectsDuplicateRun(t *testing.T) {
	q := fixtureApplianceQualification()
	q.Runs = append(q.Runs, q.Runs[0])
	if err := q.Validate(); err == nil {
		t.Fatal("expected duplicate run rejection")
	}
}

func TestApplianceQualificationRequiresTargetIdentity(t *testing.T) {
	q := fixtureApplianceQualification()
	q.HardwareModel = ""
	if err := q.Validate(); err == nil {
		t.Fatal("expected missing target identity rejection")
	}
}
