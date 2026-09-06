package historical

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEmulatorRunnerSyntheticFixture(t *testing.T) {
	root := t.TempDir()
	input := root + "/sample.adf"
	original := []byte("synthetic-amiga-disk-image")
	if err := os.WriteFile(input, original, 0o600); err != nil {
		t.Fatal(err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runner := EmulatorRunner{TempRoot: root}
	evidence, err := runner.Run(context.Background(), RunRequest{
		Profile:   OS13,
		InputPath: input,
		Command:   exe,
		Args:      []string{"-test.run=TestHistoricalFixtureProcess"},
		Env:       []string{"AAA_HISTORICAL_FIXTURE=success"},
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if evidence.ExitState != "completed" {
		t.Fatalf("exit state=%q want completed", evidence.ExitState)
	}
	if evidence.Profile != OS13 || evidence.InputSHA256 != HashBytes(original) {
		t.Fatal("profile/input evidence mismatch")
	}
	if evidence.StdoutSHA256 != HashBytes(evidence.Stdout) || evidence.StderrSHA256 != HashBytes(evidence.Stderr) {
		t.Fatal("captured output digest mismatch")
	}
	if !strings.Contains(string(evidence.Stdout), "profile=os13") || !strings.Contains(string(evidence.Stdout), "input_sha256="+HashBytes(original)) {
		t.Fatalf("unexpected synthetic fixture output: %q", evidence.Stdout)
	}
	if strings.Contains(string(evidence.Stdout), "write=allowed") {
		t.Fatal("staged evidence was writable")
	}

	after, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatal("primary evidence changed")
	}
	if _, err := os.Stat(evidence.StagedInputPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("disposable staged media still exists: %v", err)
	}
}

func TestEmulatorRunnerTimeout(t *testing.T) {
	root := t.TempDir()
	input := root + "/sample.adf"
	if err := os.WriteFile(input, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := (EmulatorRunner{TempRoot: root}).Run(context.Background(), RunRequest{
		Profile:   OS31,
		InputPath: input,
		Command:   exe,
		Args:      []string{"-test.run=TestHistoricalFixtureProcess"},
		Env:       []string{"AAA_HISTORICAL_FIXTURE=timeout"},
		Timeout:   50 * time.Millisecond,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v want deadline exceeded", err)
	}
	if evidence.ExitState != "timeout" {
		t.Fatalf("exit state=%q want timeout", evidence.ExitState)
	}
}

func TestEmulatorRunnerRejectsInvalidRequest(t *testing.T) {
	runner := EmulatorRunner{}
	if _, err := runner.Run(context.Background(), RunRequest{Profile: "os99"}); err == nil {
		t.Fatal("invalid profile accepted")
	}
}

func TestBoundedBuffer(t *testing.T) {
	buf := newBoundedBuffer(4)
	if n, err := buf.Write([]byte("abcdef")); err != nil || n != 6 {
		t.Fatalf("write=(%d,%v)", n, err)
	}
	if !buf.Overflowed() || string(buf.Bytes()) != "abcd" {
		t.Fatalf("overflow=%v bytes=%q", buf.Overflowed(), buf.Bytes())
	}
}

func TestHistoricalFixtureProcess(t *testing.T) {
	mode := os.Getenv("AAA_HISTORICAL_FIXTURE")
	if mode == "" {
		return
	}
	if mode == "timeout" {
		time.Sleep(5 * time.Second)
		return
	}
	profile := os.Getenv("AAA_HISTORICAL_PROFILE")
	input := os.Getenv("AAA_HISTORICAL_INPUT")
	data, err := os.ReadFile(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read error: %v\n", err)
		os.Exit(2)
	}
	writeState := "denied"
	if err := os.WriteFile(input, []byte("mutated"), 0o400); err == nil {
		writeState = "allowed"
	}
	fmt.Printf("profile=%s input_sha256=%s write=%s\n", profile, HashBytes(data), writeState)
	os.Exit(0)
}
