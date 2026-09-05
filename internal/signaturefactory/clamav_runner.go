package signaturefactory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	clamAVVersionTimeout = 5 * time.Second
	clamAVScanTimeout    = 30 * time.Second
	clamAVOutputLimit    = 64 * 1024
)

type ClamAVScanResult struct {
	Verdict            string
	DetectionName      string
	EngineVersion      string
	SignatureDBVersion string
	RawResult          string
	Evidence           *Evidence
}

func RunClamAV(path string) (ClamAVScanResult, error) {
	executable := strings.TrimSpace(os.Getenv("AAA_CLAMSCAN"))
	if executable == "" {
		executable = "clamscan"
	}
	return runClamAVWithExecutable(path, executable, clamAVScanTimeout)
}

func runClamAVWithExecutable(path, executable string, scanTimeout time.Duration) (ClamAVScanResult, error) {
	if strings.TrimSpace(path) == "" {
		return ClamAVScanResult{}, errors.New("ClamAV scan path is required")
	}
	if strings.TrimSpace(executable) == "" {
		return ClamAVScanResult{}, errors.New("ClamAV executable is not configured")
	}
	if scanTimeout <= 0 {
		return ClamAVScanResult{}, errors.New("ClamAV scan timeout must be positive")
	}
	info, err := os.Stat(path)
	if err != nil {
		return ClamAVScanResult{}, fmt.Errorf("stat ClamAV scan target: %w", err)
	}
	if !info.Mode().IsRegular() {
		return ClamAVScanResult{}, fmt.Errorf("ClamAV scan target is not a regular file")
	}

	versionOutput, err := runClamAVCommand(executable, clamAVVersionTimeout, "--version")
	if err != nil {
		return ClamAVScanResult{}, fmt.Errorf("query ClamAV version: %w", err)
	}
	engineVersion, dbVersion, err := ParseClamAVVersion(strings.TrimSpace(versionOutput.stdout))
	if err != nil {
		return ClamAVScanResult{}, fmt.Errorf("parse ClamAV version: %w", err)
	}

	scanOutput, err := runClamAVCommand(executable, scanTimeout, "--no-summary", "--stdout", "--", path)
	if err != nil && scanOutput.exitCode != 1 {
		return ClamAVScanResult{}, fmt.Errorf("ClamAV scan failed: %w", err)
	}

	resultLine, detectionName, found, parseErr := parseClamAVScanOutput(scanOutput.stdout)
	if parseErr != nil {
		return ClamAVScanResult{}, parseErr
	}

	result := ClamAVScanResult{
		Verdict:            "clean",
		EngineVersion:      engineVersion,
		SignatureDBVersion: dbVersion,
		RawResult:          resultLine,
	}
	if found {
		if scanOutput.exitCode != 1 {
			return ClamAVScanResult{}, fmt.Errorf("ClamAV FOUND result had unexpected exit code %d", scanOutput.exitCode)
		}
		evidence, err := NewClamAVEvidence(ClamAVDetection{
			DetectionName:      detectionName,
			EngineVersion:      engineVersion,
			SignatureDBVersion: dbVersion,
			RawResult:          resultLine,
		})
		if err != nil {
			return ClamAVScanResult{}, fmt.Errorf("normalize ClamAV evidence: %w", err)
		}
		result.Verdict = "infected"
		result.DetectionName = detectionName
		result.Evidence = &evidence
		return result, nil
	}
	if scanOutput.exitCode != 0 {
		return ClamAVScanResult{}, fmt.Errorf("ClamAV clean result had unexpected exit code %d", scanOutput.exitCode)
	}
	return result, nil
}

func parseClamAVScanOutput(stdout string) (resultLine, detectionName string, found bool, err error) {
	var cleanLine string
	for _, rawLine := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		detection, isFound, parseErr := ParseClamAVResultLine(line)
		if parseErr != nil {
			return "", "", false, parseErr
		}
		if isFound {
			if resultLine != "" {
				return "", "", false, errors.New("ClamAV returned multiple FOUND lines for one file")
			}
			resultLine = line
			detectionName = detection
			found = true
			continue
		}
		if strings.HasSuffix(line, ": OK") {
			cleanLine = line
		}
	}
	if found {
		return resultLine, detectionName, true, nil
	}
	if cleanLine == "" {
		return "", "", false, errors.New("ClamAV output contained no OK or FOUND result line")
	}
	return cleanLine, "", false, nil
}

type clamAVCommandResult struct {
	stdout   string
	stderr   string
	exitCode int
}

func runClamAVCommand(executable string, timeout time.Duration, args ...string) (clamAVCommandResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	stdout := &clamAVCappedBuffer{limit: clamAVOutputLimit}
	stderr := &clamAVCappedBuffer{limit: clamAVOutputLimit}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	result := clamAVCommandResult{
		stdout:   stdout.String(),
		stderr:   stderr.String(),
		exitCode: 0,
	}
	if ctx.Err() == context.DeadlineExceeded {
		return result, fmt.Errorf("ClamAV command exceeded %s timeout", timeout)
	}
	if stdout.exceeded || stderr.exceeded {
		return result, fmt.Errorf("ClamAV command output exceeded %d-byte safety limit", clamAVOutputLimit)
	}
	if err == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.exitCode = exitErr.ExitCode()
		if result.stderr != "" {
			return result, fmt.Errorf("exit code %d: %s", result.exitCode, strings.TrimSpace(result.stderr))
		}
		return result, fmt.Errorf("exit code %d", result.exitCode)
	}
	return result, err
}

type clamAVCappedBuffer struct {
	bytes.Buffer
	limit    int64
	exceeded bool
}

func (b *clamAVCappedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - int64(b.Len())
	if remaining <= 0 {
		b.exceeded = true
		return 0, errors.New("buffer limit exceeded")
	}
	if int64(len(p)) > remaining {
		_, _ = b.Buffer.Write(p[:remaining])
		b.exceeded = true
		return int(remaining), errors.New("buffer limit exceeded")
	}
	return b.Buffer.Write(p)
}
