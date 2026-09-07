package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/acquisition"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
)

func TestRunAcquireBindsExactImageHashAndWritesSidecars(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "disk.adf")
	payload := []byte("captured-image")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	now := time.Now().UTC()

	acquire := func(context.Context, string) (acquisition.Result, error) {
		if err := os.WriteFile(image, payload, 0o640); err != nil {
			return acquisition.Result{}, err
		}
		return acquisition.Result{
			ImagePath: image,
			RawLog:    "gw read ok\n",
			Evidence: acquisition.Evidence{
				Method:       "physical-floppy",
				Tool:         "greaseweazle",
				ToolVersion:  "gw 1.23",
				Format:       "adf",
				OutputName:   "disk.adf",
				OutputSHA256: digest,
				OutputSize:   int64(len(payload)),
				Command:      []string{"gw", "read"},
				StartedAt:    now,
				FinishedAt:   now,
				RawLogSHA256: digest,
			},
		}, nil
	}
	scan := func(path string) (scanner.Result, error) {
		return scanner.Result{Name: filepath.Base(path), SHA256: digest, Format: "adf", Verdict: "unknown"}, nil
	}

	out, err := runAcquire(context.Background(), acquireOptions{OutputPath: image, Note: "drawer A"}, acquire, scan)
	if err != nil {
		t.Fatal(err)
	}
	if out.Acquisition.OutputSHA256 != out.Scan.SHA256 {
		t.Fatalf("hash binding failed: %s != %s", out.Acquisition.OutputSHA256, out.Scan.SHA256)
	}
	if out.Acquisition.AcquisitionNote != "drawer A" {
		t.Fatalf("note=%q", out.Acquisition.AcquisitionNote)
	}
	for _, path := range []string{image + ".acquisition.json", image + ".gw.log"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing sidecar %s: %v", path, err)
		}
	}
}

func TestRunAcquireRejectsHashMismatch(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "disk.adf")
	now := time.Now().UTC()
	good := strings.Repeat("a", 64)
	bad := strings.Repeat("b", 64)
	acquire := func(context.Context, string) (acquisition.Result, error) {
		if err := os.WriteFile(image, []byte("x"), 0o640); err != nil {
			return acquisition.Result{}, err
		}
		return acquisition.Result{ImagePath: image, Evidence: acquisition.Evidence{Method: "physical-floppy", Tool: "greaseweazle", ToolVersion: "gw", Format: "adf", OutputName: "disk.adf", OutputSHA256: good, OutputSize: 1, Command: []string{"gw", "read"}, StartedAt: now, FinishedAt: now}}, nil
	}
	scan := func(string) (scanner.Result, error) { return scanner.Result{SHA256: bad}, nil }
	_, err := runAcquire(context.Background(), acquireOptions{OutputPath: image}, acquire, scan)
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunAcquireRefusesExistingSidecarBeforeAcquisition(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "disk.adf")
	if err := os.WriteFile(image+".acquisition.json", []byte("keep"), 0o640); err != nil {
		t.Fatal(err)
	}
	called := false
	acquire := func(context.Context, string) (acquisition.Result, error) {
		called = true
		return acquisition.Result{}, nil
	}
	_, err := runAcquire(context.Background(), acquireOptions{OutputPath: image}, acquire, func(string) (scanner.Result, error) { return scanner.Result{}, nil })
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite existing sidecar") {
		t.Fatalf("err=%v", err)
	}
	if called {
		t.Fatal("physical acquisition started despite existing sidecar")
	}
}
