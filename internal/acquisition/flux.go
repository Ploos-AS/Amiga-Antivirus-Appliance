package acquisition

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ReadSCP captures preservation-grade raw flux to SuperCard Pro format.
// The --raw flag is mandatory: --format without --raw would store regenerated
// decoded flux instead of the physical flux stream.
func (g Greaseweazle) ReadSCP(ctx context.Context, outputPath string) (Result, error) {
	if outputPath == "" {
		return Result{}, fmt.Errorf("output path is required")
	}
	if strings.ToLower(filepath.Ext(outputPath)) != ".scp" {
		return Result{}, fmt.Errorf("flux acquisition output must use .scp")
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
		return Result{}, fmt.Errorf("prepare flux acquisition directory: %w", err)
	}
	if _, err := os.Stat(outputPath); err == nil {
		return Result{}, fmt.Errorf("refusing to overwrite existing acquisition: %s", outputPath)
	} else if !os.IsNotExist(err) {
		return Result{}, fmt.Errorf("inspect flux acquisition output: %w", err)
	}

	toolVersion, err := greaseweazleVersion(ctx, executable, timeout)
	if err != nil {
		return Result{}, err
	}

	args := []string{"read", "--raw", "--format", "amiga.amigados"}
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
			return Result{}, fmt.Errorf("greaseweazle flux acquisition timed out: %w", runCtx.Err())
		}
		return Result{}, fmt.Errorf("greaseweazle flux acquisition failed: %w: %s", err, strings.TrimSpace(combined.String()))
	}
	finished := time.Now().UTC()

	sha, size, err := hashFile(outputPath)
	if err != nil {
		_ = os.Remove(outputPath)
		return Result{}, fmt.Errorf("verify acquired flux image: %w", err)
	}
	if size == 0 {
		_ = os.Remove(outputPath)
		return Result{}, fmt.Errorf("greaseweazle produced an empty flux image")
	}

	rawLog := combined.String()
	logSum := sha256.Sum256([]byte(rawLog))
	evidence := Evidence{
		Method:       "physical-floppy-flux",
		Tool:         "greaseweazle",
		ToolVersion:  toolVersion,
		Device:       g.Device,
		Format:       "scp-raw-flux",
		OutputName:   filepath.Base(outputPath),
		OutputSHA256: sha,
		OutputSize:   size,
		Command:      append([]string{executable}, args...),
		StartedAt:    started,
		FinishedAt:   finished,
		RawLogSHA256: hex.EncodeToString(logSum[:]),
	}
	if err := evidence.Validate(); err != nil {
		_ = os.Remove(outputPath)
		return Result{}, fmt.Errorf("invalid flux acquisition evidence: %w", err)
	}
	return Result{ImagePath: outputPath, Evidence: evidence, RawLog: rawLog}, nil
}
