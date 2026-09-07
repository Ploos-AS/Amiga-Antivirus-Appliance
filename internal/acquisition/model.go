// Package acquisition models provenance for physical-media acquisition separately from malware scan evidence.
package acquisition

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Evidence records how one preservation image was acquired from physical media.
type Evidence struct {
	Method          string    `json:"method"`
	Tool            string    `json:"tool"`
	ToolVersion     string    `json:"tool_version"`
	Device          string    `json:"device,omitempty"`
	Format          string    `json:"format"`
	OutputName      string    `json:"output_name"`
	OutputSHA256    string    `json:"output_sha256"`
	OutputSize      int64     `json:"output_size"`
	Command         []string  `json:"command"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
	RawLogSHA256    string    `json:"raw_log_sha256,omitempty"`
	AcquisitionNote string    `json:"acquisition_note,omitempty"`
}

// Validate enforces the minimum provenance contract for a completed acquisition.
func (e Evidence) Validate() error {
	if e.Method == "" || e.Tool == "" || e.ToolVersion == "" {
		return errors.New("method, tool and tool version are required")
	}
	if e.Format == "" || e.OutputName == "" {
		return errors.New("format and output name are required")
	}
	if !sha256Pattern.MatchString(e.OutputSHA256) {
		return fmt.Errorf("invalid output SHA-256")
	}
	if e.OutputSize < 1 {
		return errors.New("output size must be positive")
	}
	if len(e.Command) < 2 {
		return errors.New("acquisition command is required")
	}
	if e.StartedAt.IsZero() || e.FinishedAt.IsZero() || e.FinishedAt.Before(e.StartedAt) {
		return errors.New("invalid acquisition timestamps")
	}
	if e.RawLogSHA256 != "" && !sha256Pattern.MatchString(e.RawLogSHA256) {
		return errors.New("invalid raw log SHA-256")
	}
	return nil
}
