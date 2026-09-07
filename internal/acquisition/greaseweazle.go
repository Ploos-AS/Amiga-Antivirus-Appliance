package acquisition

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const defaultGreaseweazleTimeout = 10 * time.Minute

// Greaseweazle reads one AmigaDOS floppy into an ADF while retaining acquisition provenance.
type Greaseweazle struct {
	Executable string
	Device     string
	Timeout    time.Duration
}

// Result is a completed physical-media acquisition.
type Result struct {
	ImagePath string
	Evidence  Evidence
	RawLog    string
}

// ReadADF invokes the Greaseweazle host tools and returns a verified acquisition result.
func (g Greaseweazle) ReadADF(ctx context.Context, outputPath string) (Result, error) {
	if outputPath == "" {
		return Result{}, fmt.Errorf("output path is required")
	}
	executable := strings.TrimSpace(g.Executable)
	if executable == "" {
		executable = strings.TrimSpace(os.Getenv("AAA_GW"))
	}
	if executable == "" {
		executable = "gw"
	}
	timeout := g.Timeout
	if timeout <= 0 {
		timeout = defaultGreaseweazleTimeout
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o750); err != nil {
		return Result{}, fmt.Errorf("prepare acquisition directory: %w", err)
	}
	if _, err := os.Stat(outputPath); err == nil {
		return Result{}, fmt.Errorf("refusing to overwrite existing acquisition: %s", outputPath)
	} else if !os.IsNotExist(err) {
		return Result{}, fmt.Errorf("inspect acquisition output: %w", err)
	}

	toolVersion, err := greaseweazleVersion(ctx, executable, timeout)
	if err != nil {
		return Result{}, err
	}

	args := []string{"read", "--format", "amiga.amigados"}
	if g.Device != "" {
		args = append(args, "--device", g.Device)
	}
	args = append(args, outputPath)

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now().UTC()
	cmd := exec.CommandContext(runCtx, executable, args...)
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	if err := cmd.Run(); err != nil {
		_ = os.Remove(outputPath)
		if runCtx.Err() != nil {
			return Result{}, fmt.Errorf("greaseweazle acquisition timed out: %w", runCtx.Err())
		}
		return Result{}, fmt.Errorf("greaseweazle acquisition failed: %w: %s", err, strings.TrimSpace(combined.String()))
	}
	finished := time.Now().UTC()

	sha, size, err := hashFile(outputPath)
	if err != nil {
		_ = os.Remove(outputPath)
		return Result{}, fmt.Errorf("verify acquired image: %w", err)
	}
	if size == 0 {
		_ = os.Remove(outputPath)
		return Result{}, fmt.Errorf("greaseweazle produced an empty image")
	}

	rawLog := combined.String()
	logSum := sha256.Sum256([]byte(rawLog))
	command := append([]string{executable}, args...)
	evidence := Evidence{
		Method:       "physical-floppy",
		Tool:         "greaseweazle",
		ToolVersion:  toolVersion,
		Device:       g.Device,
		Format:       "adf",
		OutputName:   filepath.Base(outputPath),
		OutputSHA256: sha,
		OutputSize:   size,
		Command:      command,
		StartedAt:    started,
		FinishedAt:   finished,
		RawLogSHA256: hex.EncodeToString(logSum[:]),
	}
	if err := evidence.Validate(); err != nil {
		_ = os.Remove(outputPath)
		return Result{}, fmt.Errorf("invalid acquisition evidence: %w", err)
	}
	return Result{ImagePath: outputPath, Evidence: evidence, RawLog: rawLog}, nil
}

func greaseweazleVersion(ctx context.Context, executable string, timeout time.Duration) (string, error) {
	versionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(versionCtx, executable, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("greaseweazle version probe failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	version := strings.TrimSpace(string(out))
	if version == "" {
		return "", fmt.Errorf("greaseweazle version probe returned no version")
	}
	return version, nil
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
