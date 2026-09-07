package historical

import "github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/engineevidence"

// EngineEvidence projects a rich M8 historical result into the common
// attribution envelope while preserving the original M8 result separately.
func EngineEvidence(result Result, components ...engineevidence.Component) engineevidence.Result {
	started := result.StartedAt
	finished := result.FinishedAt
	status := engineevidence.StatusCompleted
	errorText := ""
	if result.Verdict == VerdictError {
		status = engineevidence.StatusError
		errorText = result.RawExit
		if errorText == "" {
			errorText = "historical scanner reported error"
		}
	}
	return engineevidence.Result{
		Kind:              engineevidence.KindHistorical,
		EngineID:          result.EngineID,
		EngineName:        result.EngineName,
		EngineVersion:     result.EngineVersion,
		Status:            status,
		Verdict:           string(result.Verdict),
		DetectionName:     result.DetectionName,
		InputSHA256:       result.InputSHA256,
		DatabaseID:        result.SignatureDatabaseID,
		OSProfile:         string(result.OSProfile),
		BinarySHA256:      result.ScannerBinarySHA256,
		RawEvidenceSHA256: result.RawLogSHA256,
		StartedAt:         &started,
		FinishedAt:        &finished,
		Components:        append([]engineevidence.Component(nil), components...),
		Error:             errorText,
	}
}
