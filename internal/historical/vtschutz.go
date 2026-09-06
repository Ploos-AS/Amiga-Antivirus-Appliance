package historical

import (
	"errors"
	"strings"
)

const VTSchutzEngineID = "vtschutz"

// ParseVTSchutzOutput normalizes captured VT-Schutz 3.17 output. The parser is
// deliberately conservative: only explicit known-clean or detection markers
// produce strong verdicts; unfamiliar successful output remains unknown.
func ParseVTSchutzOutput(raw []byte, completed bool) (Verdict, string, error) {
	text := strings.TrimSpace(strings.ReplaceAll(string(raw), "\r", ""))
	if !completed {
		return VerdictError, "", errors.New("VT-Schutz did not complete")
	}
	if text == "" {
		return VerdictUnknown, "", nil
	}

	lower := strings.ToLower(text)
	if name := vtDetectionName(text); name != "" {
		return VerdictInfected, name, nil
	}
	if strings.Contains(lower, "suspicious") || strings.Contains(lower, "verdächtig") || strings.Contains(lower, "verdaechtig") {
		return VerdictSuspicious, "", nil
	}
	if strings.Contains(lower, "no virus found") || strings.Contains(lower, "no viruses found") || strings.Contains(lower, "kein virus gefunden") {
		return VerdictClean, "", nil
	}
	return VerdictUnknown, "", nil
}

func vtDetectionName(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		for _, marker := range []string{"virus found:", "virus gefunden:"} {
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

// VTSchutzResult builds an M8 normalized result while preserving the exact
// captured scanner log. Actual VT-Schutz execution remains a separate runtime
// qualification step using user-supplied software under the os13 profile.
func VTSchutzResult(base Result, completed bool) (Result, error) {
	if base.EngineID != VTSchutzEngineID {
		return Result{}, errors.New("VT-Schutz result requires vtschutz engine id")
	}
	if base.OSProfile != OS13 {
		return Result{}, errors.New("VT-Schutz M8.3 adapter requires os13")
	}
	verdict, detection, parseErr := ParseVTSchutzOutput(base.RawLog, completed)
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
