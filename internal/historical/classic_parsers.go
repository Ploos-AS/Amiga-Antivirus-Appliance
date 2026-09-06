package historical

import (
	"errors"
	"strings"
)

// ParseClassicScannerOutput conservatively normalizes captured output from the
// M8.4 historical scanner set. These markers are synthetic compatibility
// fixtures until each real scanner/version is runtime-qualified.
func ParseClassicScannerOutput(engineID string, raw []byte, completed bool) (Verdict, string, error) {
	if !classicEngine(engineID) {
		return VerdictError, "", errors.New("unsupported M8.4 historical engine")
	}
	if !completed {
		return VerdictError, "", errors.New("historical scanner did not complete")
	}
	text := strings.TrimSpace(strings.ReplaceAll(string(raw), "\r", ""))
	if text == "" {
		return VerdictUnknown, "", nil
	}
	lower := strings.ToLower(text)
	if name := classicDetectionName(text); name != "" {
		return VerdictInfected, name, nil
	}
	if strings.Contains(lower, "suspicious") || strings.Contains(lower, "unknown virus") || strings.Contains(lower, "unknown bootblock") {
		return VerdictSuspicious, "", nil
	}
	for _, marker := range []string{"no virus found", "no viruses found", "nothing found", "0 viruses found", "no infection found"} {
		if strings.Contains(lower, marker) {
			return VerdictClean, "", nil
		}
	}
	return VerdictUnknown, "", nil
}

func classicEngine(id string) bool {
	switch id {
	case "virusz3", "virusexecutor", "viruschecker2", "virusslayer2", "mill":
		return true
	default:
		return false
	}
}

func classicDetectionName(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		for _, marker := range []string{"virus found:", "virus:", "infected:"} {
			if i := strings.Index(lower, marker); i >= 0 {
				name := strings.TrimSpace(line[i+len(marker):])
				if name != "" {
					return name
				}
			}
		}
	}
	return ""
}

// ClassicScannerResult applies the common M8 evidence model and validates that
// the selected OS profile is declared by the engine inventory.
func ClassicScannerResult(base Result, completed bool) (Result, error) {
	registry, err := InitialRegistry()
	if err != nil {
		return Result{}, err
	}
	engine, ok := registry.Engine(base.EngineID)
	if !ok || !classicEngine(base.EngineID) {
		return Result{}, errors.New("unsupported M8.4 historical engine")
	}
	if !supportsProfile(engine, base.OSProfile) {
		return Result{}, errors.New("historical scanner does not support selected OS profile")
	}
	verdict, detection, parseErr := ParseClassicScannerOutput(base.EngineID, base.RawLog, completed)
	base.Verdict = verdict
	base.DetectionName = detection
	base.SealRawLog()
	if parseErr != nil {
		base.RawExit = "error"
	}
	if err := base.Validate(); err != nil {
		return Result{}, err
	}
	return base, parseErr
}

func supportsProfile(engine Engine, profile OSProfile) bool {
	for _, supported := range engine.SupportedProfiles {
		if supported == profile {
			return true
		}
	}
	return false
}
