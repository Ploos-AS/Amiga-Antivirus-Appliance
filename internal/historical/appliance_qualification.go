package historical

import (
	"errors"
	"sort"
	"strings"
	"time"
)

// ApplianceQualification captures evidence from an M8.6 target-appliance run.
type ApplianceQualification struct {
	Hostname      string                      `json:"hostname"`
	HardwareModel string                      `json:"hardware_model"`
	Architecture  string                      `json:"architecture"`
	OSName        string                      `json:"os_name"`
	OSVersion     string                      `json:"os_version"`
	KernelVersion string                      `json:"kernel_version"`
	AAAVersion    string                      `json:"aaa_version"`
	StartedAt     time.Time                   `json:"started_at"`
	FinishedAt    time.Time                   `json:"finished_at"`
	Runs          []ApplianceQualificationRun `json:"runs"`
}

// ApplianceQualificationRun records one scanner/profile execution on target hardware.
type ApplianceQualificationRun struct {
	EngineID             string    `json:"engine_id"`
	EngineVersion        string    `json:"engine_version"`
	OSProfile            OSProfile `json:"os_profile"`
	ScannerBinarySHA256  string    `json:"scanner_binary_sha256"`
	InputSHA256          string    `json:"input_sha256"`
	InputSHA256After     string    `json:"input_sha256_after"`
	Verdict              Verdict   `json:"verdict"`
	ExitState            string    `json:"exit_state"`
	DurationMilliseconds int64     `json:"duration_ms"`
	PeakRSSKiB           uint64    `json:"peak_rss_kib"`
}

// Validate verifies an appliance qualification record without claiming that
// the record came from real target hardware. That provenance remains an
// external qualification responsibility.
func (q ApplianceQualification) Validate() error {
	for name, value := range map[string]string{
		"hostname":       q.Hostname,
		"hardware model": q.HardwareModel,
		"architecture":   q.Architecture,
		"os name":        q.OSName,
		"os version":     q.OSVersion,
		"kernel version": q.KernelVersion,
		"aaa version":    q.AAAVersion,
	} {
		if strings.TrimSpace(value) == "" {
			return errors.New("missing " + name)
		}
	}
	if q.FinishedAt.Before(q.StartedAt) || q.StartedAt.IsZero() || q.FinishedAt.IsZero() {
		return errors.New("invalid appliance qualification timestamps")
	}
	if len(q.Runs) == 0 {
		return errors.New("appliance qualification requires at least one run")
	}
	seen := make(map[string]struct{}, len(q.Runs))
	for _, run := range q.Runs {
		if err := run.Validate(); err != nil {
			return err
		}
		key := run.EngineID + "\x00" + string(run.OSProfile) + "\x00" + run.InputSHA256
		if _, ok := seen[key]; ok {
			return errors.New("duplicate appliance qualification run")
		}
		seen[key] = struct{}{}
	}
	return nil
}

// SortedRuns returns a deterministic copy ordered by engine, profile and input.
func (q ApplianceQualification) SortedRuns() []ApplianceQualificationRun {
	runs := append([]ApplianceQualificationRun(nil), q.Runs...)
	sort.Slice(runs, func(i, j int) bool {
		if runs[i].EngineID != runs[j].EngineID {
			return runs[i].EngineID < runs[j].EngineID
		}
		if runs[i].OSProfile != runs[j].OSProfile {
			return runs[i].OSProfile < runs[j].OSProfile
		}
		return runs[i].InputSHA256 < runs[j].InputSHA256
	})
	return runs
}

func (r ApplianceQualificationRun) Validate() error {
	if strings.TrimSpace(r.EngineID) == "" || strings.TrimSpace(r.EngineVersion) == "" {
		return errors.New("appliance qualification run missing engine identity")
	}
	if !r.OSProfile.Valid() {
		return errors.New("appliance qualification run has invalid os profile")
	}
	if !isLowerSHA256(r.ScannerBinarySHA256) || !isLowerSHA256(r.InputSHA256) || !isLowerSHA256(r.InputSHA256After) {
		return errors.New("appliance qualification run has invalid sha256")
	}
	if r.InputSHA256After != r.InputSHA256 {
		return errors.New("historical scan modified primary input evidence")
	}
	if !r.Verdict.Valid() {
		return errors.New("appliance qualification run has invalid verdict")
	}
	if strings.TrimSpace(r.ExitState) == "" {
		return errors.New("appliance qualification run missing exit state")
	}
	if r.DurationMilliseconds < 0 {
		return errors.New("appliance qualification run has negative duration")
	}
	return nil
}
