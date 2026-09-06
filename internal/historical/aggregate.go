package historical

import (
	"errors"
	"sort"
	"strings"
)

// Aggregate summarizes independent historical-scanner evidence without hiding
// individual engine disagreement.
type Aggregate struct {
	InputSHA256      string              `json:"input_sha256"`
	Results          []Result            `json:"results"`
	VerdictCounts    map[Verdict]int     `json:"verdict_counts"`
	DetectionNames   []string            `json:"detection_names,omitempty"`
	EnginesByVerdict map[Verdict][]string `json:"engines_by_verdict"`
	HasDisagreement  bool                `json:"has_disagreement"`
	Corroborated     bool                `json:"corroborated"`
	CorroboratedName string              `json:"corroborated_name,omitempty"`
}

// AggregateResults validates and deterministically orders per-engine evidence.
// Corroborated only means at least two independent engines reported infected
// with the same non-empty detection name. It is research evidence, not a
// production-signature promotion decision.
func AggregateResults(results []Result) (Aggregate, error) {
	if len(results) == 0 {
		return Aggregate{}, errors.New("historical aggregation requires at least one result")
	}

	copyResults := append([]Result(nil), results...)
	input := copyResults[0].InputSHA256
	seenEngine := make(map[string]struct{}, len(copyResults))
	for i := range copyResults {
		if err := copyResults[i].Validate(); err != nil {
			return Aggregate{}, err
		}
		if copyResults[i].InputSHA256 != input {
			return Aggregate{}, errors.New("historical results refer to different input hashes")
		}
		if _, ok := seenEngine[copyResults[i].EngineID]; ok {
			return Aggregate{}, errors.New("duplicate historical engine result")
		}
		seenEngine[copyResults[i].EngineID] = struct{}{}
	}

	sort.Slice(copyResults, func(i, j int) bool {
		return copyResults[i].EngineID < copyResults[j].EngineID
	})

	agg := Aggregate{
		InputSHA256:      input,
		Results:          copyResults,
		VerdictCounts:    make(map[Verdict]int),
		EnginesByVerdict: make(map[Verdict][]string),
	}
	nameCounts := make(map[string]int)
	nameVariants := make(map[string][]string)
	verdictKinds := make(map[Verdict]struct{})

	for _, result := range copyResults {
		agg.VerdictCounts[result.Verdict]++
		agg.EnginesByVerdict[result.Verdict] = append(agg.EnginesByVerdict[result.Verdict], result.EngineID)
		verdictKinds[result.Verdict] = struct{}{}
		if result.Verdict == VerdictInfected && strings.TrimSpace(result.DetectionName) != "" {
			name := strings.TrimSpace(result.DetectionName)
			key := strings.ToLower(name)
			nameCounts[key]++
			nameVariants[key] = append(nameVariants[key], name)
		}
	}

	agg.HasDisagreement = len(verdictKinds) > 1
	for verdict := range agg.EnginesByVerdict {
		sort.Strings(agg.EnginesByVerdict[verdict])
	}

	keys := make([]string, 0, len(nameCounts))
	for key := range nameCounts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		variants := append([]string(nil), nameVariants[key]...)
		sort.Strings(variants)
		display := variants[0]
		agg.DetectionNames = append(agg.DetectionNames, display)
		if !agg.Corroborated && nameCounts[key] >= 2 {
			agg.Corroborated = true
			agg.CorroboratedName = display
		}
	}

	return agg, nil
}
