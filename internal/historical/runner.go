package historical

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const DefaultEmulatorTimeout = 2 * time.Minute
const MaxEmulatorLogBytes = int64(4 << 20)

type RunRequest struct {
	Profile   OSProfile
	InputPath string
	Command   string
	Args      []string
	Env       []string
	Timeout   time.Duration
}

type RunEvidence struct {
	Profile         OSProfile
	InputSHA256     string
	StagedInputPath string
	Stdout          []byte
	Stderr          []byte
	StdoutSHA256    string
	StderrSHA256    string
	ExitState       string
	StartedAt       time.Time
	FinishedAt      time.Time
}

type EmulatorRunner struct {
	TempRoot string
}

func (r EmulatorRunner) Run(ctx context.Context, req RunRequest) (RunEvidence, error) {
	var evidence RunEvidence
	if !req.Profile.Valid() {
		return evidence, fmt.Errorf("invalid OS profile %q", req.Profile)
	}
	if req.Command == "" {
		return evidence, errors.New("emulator command is required")
	}
	if req.InputPath == "" {
		return evidence, errors.New("input path is required")
	}
	info, err := os.Stat(req.InputPath)
	if err != nil {
		return evidence, err
	}
	if !info.Mode().IsRegular() {
		return evidence, errors.New("input must be a regular file")
	}
	inputData, err := os.ReadFile(req.InputPath)
	if err != nil {
		return evidence, err
	}
	evidence.InputSHA256 = HashBytes(inputData)
	evidence.Profile = req.Profile

	root, err := os.MkdirTemp(r.TempRoot, "aaa-historical-")
	if err != nil {
		return evidence, err
	}
	defer os.RemoveAll(root)

	staged := filepath.Join(root, "media", filepath.Base(req.InputPath))
	if err := os.MkdirAll(filepath.Dir(staged), 0o700); err != nil {
		return evidence, err
	}
	if err := os.WriteFile(staged, inputData, 0o400); err != nil {
		return evidence, err
	}
	evidence.StagedInputPath = staged

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = DefaultEmulatorTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, req.Command, req.Args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), req.Env...)
	cmd.Env = append(cmd.Env,
		"AAA_HISTORICAL_PROFILE="+string(req.Profile),
		"AAA_HISTORICAL_INPUT="+staged,
	)

	stdout := newBoundedBuffer(MaxEmulatorLogBytes)
	stderr := newBoundedBuffer(MaxEmulatorLogBytes)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	evidence.StartedAt = time.Now().UTC()
	err = cmd.Run()
	evidence.FinishedAt = time.Now().UTC()
	evidence.Stdout = stdout.Bytes()
	evidence.Stderr = stderr.Bytes()
	evidence.StdoutSHA256 = HashBytes(evidence.Stdout)
	evidence.StderrSHA256 = HashBytes(evidence.Stderr)

	if runCtx.Err() == context.DeadlineExceeded {
		evidence.ExitState = "timeout"
		return evidence, context.DeadlineExceeded
	}
	if stdout.Overflowed() || stderr.Overflowed() {
		evidence.ExitState = "output-limit"
		return evidence, errors.New("emulator output exceeded configured limit")
	}
	if err != nil {
		evidence.ExitState = "error"
		return evidence, err
	}
	evidence.ExitState = "completed"
	return evidence, nil
}

type boundedBuffer struct {
	buf        bytes.Buffer
	remaining  int64
	overflowed bool
}

func newBoundedBuffer(limit int64) *boundedBuffer {
	return &boundedBuffer{remaining: limit}
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if int64(len(p)) > b.remaining {
		allowed := b.remaining
		if allowed > 0 {
			_, _ = b.buf.Write(p[:allowed])
		}
		b.remaining = 0
		b.overflowed = true
		return len(p), nil
	}
	n, err := b.buf.Write(p)
	b.remaining -= int64(n)
	return n, err
}

func (b *boundedBuffer) Bytes() []byte {
	return append([]byte(nil), b.buf.Bytes()...)
}

func (b *boundedBuffer) Overflowed() bool {
	return b.overflowed
}

var _ io.Writer = (*boundedBuffer)(nil)
