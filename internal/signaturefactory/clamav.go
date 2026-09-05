package signaturefactory

import (
	"errors"
	"fmt"
	"strings"
)

const (
	ClamAVEngineName = "clamav"
)

// ClamAVDetection is the normalized subset of a ClamAV result needed for
// provenance. Callers remain responsible for scanning the exact sample whose
// hash is stored on the candidate.
type ClamAVDetection struct {
	DetectionName      string
	EngineVersion      string
	SignatureDBVersion string
	RawResult          string
}

// ParseClamAVVersion parses the common `clamscan --version` representation:
// `ClamAV <engine>/<database>/<build-date>`. The database component is kept as
// an opaque version identifier; dates are deliberately not used as identity.
func ParseClamAVVersion(value string) (engineVersion, signatureDBVersion string, err error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "ClamAV ") {
		return "", "", errors.New("invalid ClamAV version string")
	}
	payload := strings.TrimSpace(strings.TrimPrefix(value, "ClamAV "))
	parts := strings.Split(payload, "/")
	if len(parts) < 2 {
		return "", "", errors.New("ClamAV version string lacks signature database version")
	}
	engineVersion = strings.TrimSpace(parts[0])
	signatureDBVersion = strings.TrimSpace(parts[1])
	if engineVersion == "" || signatureDBVersion == "" {
		return "", "", errors.New("ClamAV version string has empty provenance fields")
	}
	if strings.ContainsAny(engineVersion+signatureDBVersion, "\r\n\t") {
		return "", "", errors.New("ClamAV version provenance contains control whitespace")
	}
	return engineVersion, signatureDBVersion, nil
}

// ParseClamAVResultLine accepts one regular clamscan result line and returns a
// detection only for `FOUND`. Clean/error lines are not malware evidence.
func ParseClamAVResultLine(line string) (detectionName string, found bool, err error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false, errors.New("empty ClamAV result line")
	}
	if strings.HasSuffix(line, ": OK") {
		return "", false, nil
	}
	if !strings.HasSuffix(line, " FOUND") {
		return "", false, nil
	}
	withoutFound := strings.TrimSpace(strings.TrimSuffix(line, " FOUND"))
	separator := strings.LastIndex(withoutFound, ": ")
	if separator < 0 {
		return "", false, errors.New("malformed ClamAV FOUND result")
	}
	detectionName = strings.TrimSpace(withoutFound[separator+2:])
	if detectionName == "" {
		return "", false, errors.New("ClamAV FOUND result lacks detection name")
	}
	if strings.ContainsAny(detectionName, "\r\n\t") {
		return "", false, errors.New("ClamAV detection name contains control whitespace")
	}
	return detectionName, true, nil
}

// NewClamAVEvidence converts one confirmed ClamAV detection into normalized
// M7.1 evidence. Signature database identity is mandatory so correlated
// frontends backed by the same ClamAV database can be collapsed correctly.
func NewClamAVEvidence(input ClamAVDetection) (Evidence, error) {
	detection := strings.TrimSpace(input.DetectionName)
	engineVersion := strings.TrimSpace(input.EngineVersion)
	dbVersion := strings.TrimSpace(input.SignatureDBVersion)
	raw := strings.TrimSpace(input.RawResult)

	if detection == "" {
		return Evidence{}, errors.New("ClamAV detection name is required")
	}
	if engineVersion == "" {
		return Evidence{}, errors.New("ClamAV engine version is required")
	}
	if dbVersion == "" {
		return Evidence{}, errors.New("ClamAV signature database version is required")
	}
	if strings.ContainsAny(detection+engineVersion+dbVersion, "\r\n\t") {
		return Evidence{}, errors.New("ClamAV provenance contains control whitespace")
	}

	detail := detection
	if raw != "" {
		if strings.ContainsAny(raw, "\r\n") {
			return Evidence{}, errors.New("ClamAV raw result must be one line")
		}
		detail = fmt.Sprintf("%s; raw=%s", detection, raw)
	}

	evidence := Evidence{
		Type:               "engine-detection",
		Detail:             detail,
		SourceEngine:       ClamAVEngineName,
		SourceVersion:      engineVersion,
		SignatureDBVersion: dbVersion,
		CorrelationKey:     "clamav-db:" + dbVersion,
	}
	if err := evidence.Validate(); err != nil {
		return Evidence{}, err
	}
	return evidence, nil
}
