package main

import (
	"fmt"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/engineevidence"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/signaturefactory"
)

// scanForDaemon preserves the detailed native scanner result while attaching
// comparable, attributed engine summaries for persistence/API/UI consumers.
// External engine failure is evidence, not a failure of the native scan.
func scanForDaemon(path string) (scanner.Result, error) {
	result, err := scanner.ScanFile(path)
	if err != nil {
		return scanner.Result{}, err
	}

	native := engineevidence.Result{
		Kind:          engineevidence.KindNative,
		EngineID:      "aaa-native",
		EngineName:    "AAA native analyzer",
		EngineVersion: version,
		Status:        engineevidence.StatusCompleted,
		Verdict:       result.Verdict,
		DetectionName: result.Detection,
		InputSHA256:   result.SHA256,
	}
	if err := native.Validate(); err != nil {
		return scanner.Result{}, fmt.Errorf("normalize native engine evidence: %w", err)
	}
	result.EngineResults = append(result.EngineResults, native)

	clamAV, clamErr := signaturefactory.RunClamAV(path)
	clamEvidence := clamAVEvidence(clamAV, result.SHA256, clamErr)
	if err := clamEvidence.Validate(); err != nil {
		return scanner.Result{}, fmt.Errorf("normalize ClamAV engine evidence: %w", err)
	}
	result.EngineResults = append(result.EngineResults, clamEvidence)
	return result, nil
}

func clamAVEvidence(result signaturefactory.ClamAVScanResult, inputSHA256 string, runErr error) engineevidence.Result {
	out := engineevidence.Result{
		Kind:        engineevidence.KindClamAV,
		EngineID:    "clamav",
		EngineName:  "ClamAV",
		InputSHA256: inputSHA256,
	}
	if runErr != nil {
		out.Status = engineevidence.StatusError
		out.Verdict = "error"
		out.Error = runErr.Error()
		return out
	}
	out.Status = engineevidence.StatusCompleted
	out.EngineVersion = result.EngineVersion
	out.Verdict = result.Verdict
	out.DetectionName = result.DetectionName
	out.DatabaseID = "clamav-signatures"
	out.DatabaseVersion = result.SignatureDBVersion
	if result.RawResult != "" {
		out.RawEvidenceSHA256 = engineevidence.HashBytes([]byte(result.RawResult))
	}
	return out
}
