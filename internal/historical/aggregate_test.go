package historical

import (
	"strings"
	"testing"
	"time"
)

func fixtureHistoricalResult(engine string, verdict Verdict, detection string, input string) Result {
	start := time.Date(2026, 9, 6, 20, 15, 0, 0, time.UTC)
	result := Result{
		EngineID:            engine,
		EngineName:          engine,
		EngineVersion:       "fixture",
		OSProfile:           OS31,
		ScannerBinarySHA256: strings.Repeat("a", 64),
		Verdict:             verdict,
		DetectionName:       detection,
		RawExit:             "completed",
		RawLog:              []byte(engine + ": " + string(verdict)),
		InputSHA256:          input,
		StartedAt:            start,
		FinishedAt:           start.Add(time.Second),
	}
	result.SealRawLog()
	return result
}

func TestAggregatePreservesDisagreement(t *testing.T) {
	input := strings.Repeat("b", 64)
	results := []Result{
		fixtureHistoricalResult("virusz3", VerdictInfected, "SCA", input),
		fixtureHistoricalResult("virusexecutor", VerdictClean, "", input),
		fixtureHistoricalResult("mill", VerdictUnknown, "", input),
	}
	agg, err := AggregateResults(results)
	if err != nil {
		t.Fatal(err)
	}
	if !agg.HasDisagreement {
		t.Fatal("expected disagreement to be preserved")
	}
	if agg.VerdictCounts[VerdictInfected] != 1 || agg.VerdictCounts[VerdictClean] != 1 || agg.VerdictCounts[VerdictUnknown] != 1 {
		t.Fatalf("unexpected verdict counts: %#v", agg.VerdictCounts)
	}
	if agg.Results[0].EngineID != "mill" || agg.Results[1].EngineID != "virusexecutor" || agg.Results[2].EngineID != "virusz3" {
		t.Fatalf("results not deterministically sorted: %#v", agg.Results)
	}
}

func TestAggregateCorroboratesSameDetection(t *testing.T) {
	input := strings.Repeat("c", 64)
	results := []Result{
		fixtureHistoricalResult("virusz3", VerdictInfected, "SCA", input),
		fixtureHistoricalResult("virusslayer2", VerdictInfected, "sca", input),
		fixtureHistoricalResult("mill", VerdictClean, "", input),
	}
	agg, err := AggregateResults(results)
	if err != nil {
		t.Fatal(err)
	}
	if !agg.Corroborated || agg.CorroboratedName != "SCA" {
		t.Fatalf("expected SCA corroboration: %#v", agg)
	}
	if !agg.HasDisagreement {
		t.Fatal("corroboration must not erase clean/infected disagreement")
	}
}

func TestAggregateDoesNotCorroborateDifferentNames(t *testing.T) {
	input := strings.Repeat("d", 64)
	results := []Result{
		fixtureHistoricalResult("virusz3", VerdictInfected, "SCA", input),
		fixtureHistoricalResult("virusslayer2", VerdictInfected, "Byte Bandit", input),
	}
	agg, err := AggregateResults(results)
	if err != nil {
		t.Fatal(err)
	}
	if agg.Corroborated {
		t.Fatalf("different detection names must not corroborate: %#v", agg)
	}
}

func TestAggregateRejectsMixedInputsAndDuplicateEngines(t *testing.T) {
	inputA := strings.Repeat("e", 64)
	inputB := strings.Repeat("f", 64)
	if _, err := AggregateResults([]Result{
		fixtureHistoricalResult("virusz3", VerdictClean, "", inputA),
		fixtureHistoricalResult("mill", VerdictClean, "", inputB),
	}); err == nil {
		t.Fatal("expected mixed input rejection")
	}

	if _, err := AggregateResults([]Result{
		fixtureHistoricalResult("virusz3", VerdictClean, "", inputA),
		fixtureHistoricalResult("virusz3", VerdictClean, "", inputA),
	}); err == nil {
		t.Fatal("expected duplicate engine rejection")
	}
}
