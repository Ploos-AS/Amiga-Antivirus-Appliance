package archive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const (
	dmsDecodeTimeout = 15 * time.Second
	maxToolStderr    = 64 * 1024
)

// DecodeDMS expands a DMS disk image through the reference xDMS decoder.
// Input and output are streamed through stdin/stdout; no submitted archive or
// expanded image is written to a temporary host path. The output is bounded by
// MaxExpandedSize and the subprocess is killed when dmsDecodeTimeout expires.
func DecodeDMS(data []byte) ([]byte, *Analysis, error) {
	return DecodeDMSLimited(data, MaxExpandedSize)
}

// DecodeDMSLimited expands a DMS image while enforcing a caller-supplied
// output ceiling. Nested scanners use this to pass the remaining per-job
// expansion budget into xDMS before any output is accepted into memory.
func DecodeDMSLimited(data []byte, maxExpanded int64) ([]byte, *Analysis, error) {
	executable := os.Getenv("AAA_XDMS")
	if executable == "" {
		executable = "xdms"
	}
	return decodeDMSWithExecutableLimited(data, executable, maxExpanded)
}

func decodeDMSWithExecutable(data []byte, executable string) ([]byte, *Analysis, error) {
	return decodeDMSWithExecutableLimited(data, executable, MaxExpandedSize)
}

func decodeDMSWithExecutableLimited(data []byte, executable string, maxExpanded int64) ([]byte, *Analysis, error) {
	if len(data) < 4 || string(data[:4]) != "DMS!" {
		return nil, nil, fmt.Errorf("not a recognized DMS stream")
	}
	if executable == "" {
		return nil, nil, fmt.Errorf("xDMS executable is not configured")
	}
	if maxExpanded <= 0 || maxExpanded > MaxExpandedSize {
		return nil, nil, fmt.Errorf("invalid DMS expansion limit %d", maxExpanded)
	}

	ctx, cancel := context.WithTimeout(context.Background(), dmsDecodeTimeout)
	defer cancel()

	stdout := &cappedBuffer{limit: maxExpanded}
	stderr := &cappedBuffer{limit: maxToolStderr}
	cmd := exec.CommandContext(ctx, executable, "-q", "u", "stdin", "+stdout")
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, nil, fmt.Errorf("xDMS decode exceeded %s timeout", dmsDecodeTimeout)
	}
	if stdout.exceeded {
		return nil, nil, fmt.Errorf("expanded DMS exceeds %d-byte safety limit", maxExpanded)
	}
	if err != nil {
		if stderr.Len() > 0 {
			return nil, nil, fmt.Errorf("xDMS decode failed: %w: %s", err, stderr.String())
		}
		return nil, nil, fmt.Errorf("xDMS decode failed: %w", err)
	}
	if stdout.Len() == 0 {
		return nil, nil, fmt.Errorf("xDMS produced no disk image")
	}

	expanded := append([]byte(nil), stdout.Bytes()...)
	sum := sha256.Sum256(expanded)
	analysis := &Analysis{
		Format:       "dms",
		ExpandedSize: int64(len(expanded)),
		Members: []Member{{
			Name:   "disk.adf",
			Size:   int64(len(expanded)),
			SHA256: hex.EncodeToString(sum[:]),
			Format: "adf",
		}},
	}
	return expanded, analysis, nil
}

type cappedBuffer struct {
	bytes.Buffer
	limit    int64
	exceeded bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - int64(b.Len())
	if remaining <= 0 {
		b.exceeded = true
		return 0, fmt.Errorf("buffer limit exceeded")
	}
	if int64(len(p)) > remaining {
		_, _ = b.Buffer.Write(p[:remaining])
		b.exceeded = true
		return int(remaining), fmt.Errorf("buffer limit exceeded")
	}
	return b.Buffer.Write(p)
}
