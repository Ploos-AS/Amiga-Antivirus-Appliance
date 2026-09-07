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

func TestRunAcquireSeriesReproducible(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "disk.adf")
	payload := []byte("same-image")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	now := time.Now().UTC()

	acquire := func(_ context.Context, path string) (acquisition.Result, error) {
		if err := os.WriteFile(path, payload, 0o640); err != nil {
			return acquisition.Result{}, err
		}
		return acquisition.Result{
			ImagePath: path,
			RawLog:    "read ok\n",
			Evidence: acquisition.Evidence{
				Method:       "physical-floppy",
				Tool:         "greaseweazle",
				ToolVersion:  "gw 1.23",
				Format:       "adf",
				OutputName:   filepath.Base(path),
				OutputSHA256: digest,
				OutputSize:   int64(len(payload)),
				Command:      []string{"gw", "read"},
				StartedAt:    now,
				FinishedAt:   now,
			},
		}, nil
	}
	scan := func(path string) (scanner.Result, error) {
		return scanner.Result{Name: filepath.Base(path), SHA256: digest, Format: "adf", Verdict: "unknown"}, nil
	}

	out, err := runAcquireSeries(context.Background(), acquireOptions{OutputPath: base}, 2, "", acquire, scan)
	if err != nil {
		t.Fatal(err)
	}
	if out.Repeatability.Status != acquisition.RepeatabilityReproducible || out.Repeatability.ReadCount != 2 {
		t.Fatalf("repeatability=%+v", out.Repeatability)
	}
	if len(out.Reads) != 2 {
		t.Fatalf("reads=%d", len(out.Reads))
	}
	if out.Reads[0].Acquisition.OutputName != "disk.read-01.adf" || out.Reads[1].Acquisition.OutputName != "disk.read-02.adf" {
		t.Fatalf("names=%q,%q", out.Reads[0].Acquisition.OutputName, out.Reads[1].Acquisition.OutputName)
	}
	if out.Manifest != filepath.Join(dir, "disk.repeatability.json") {
		t.Fatalf("manifest=%q", out.Manifest)
	}
	if _, err := os.Stat(out.Manifest); err != nil {
		t.Fatalf("missing manifest: %v", err)
	}
}

func TestRunAcquireSeriesDivergentPreservesReads(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "disk.adf")
	now := time.Now().UTC()
	call := 0
	acquire := func(_ context.Context, path string) (acquisition.Result, error) {
		call++
		payload := []byte(fmt.Sprintf("image-%d", call))
		sum := sha256.Sum256(payload)
		digest := hex.EncodeToString(sum[:])
		if err := os.WriteFile(path, payload, 0o640); err != nil {
			return acquisition.Result{}, err
		}
		return acquisition.Result{ImagePath: path, Evidence: acquisition.Evidence{Method: "physical-floppy", Tool: "greaseweazle", ToolVersion: "gw", Format: "adf", OutputName: filepath.Base(path), OutputSHA256: digest, OutputSize: int64(len(payload)), Command: []string{"gw", "read"}, StartedAt: now, FinishedAt: now}}, nil
	}
	scan := func(path string) (scanner.Result, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return scanner.Result{}, err
		}
		sum := sha256.Sum256(data)
		return scanner.Result{Name: filepath.Base(path), SHA256: hex.EncodeToString(sum[:]), Format: "adf", Verdict: "unknown"}, nil
	}

	out, err := runAcquireSeries(context.Background(), acquireOptions{OutputPath: base}, 2, "", acquire, scan)
	if err != nil {
		t.Fatal(err)
	}
	if out.Repeatability.Status != acquisition.RepeatabilityDivergent || out.Repeatability.UniqueHashes != 2 {
		t.Fatalf("repeatability=%+v", out.Repeatability)
	}
	for i := 1; i <= 2; i++ {
		if _, err := os.Stat(repeatedOutputPath(base, i)); err != nil {
			t.Fatalf("read %d was not preserved: %v", i, err)
		}
	}
}

func TestRunAcquireSeriesPreflightStopsBeforeRead(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "disk.adf")
	manifest := repeatabilityManifestPath(base)
	if err := os.WriteFile(manifest, []byte("keep"), 0o640); err != nil {
		t.Fatal(err)
	}
	called := false
	acquire := func(context.Context, string) (acquisition.Result, error) {
		called = true
		return acquisition.Result{}, nil
	}
	_, err := runAcquireSeries(context.Background(), acquireOptions{OutputPath: base}, 2, "", acquire, func(string) (scanner.Result, error) { return scanner.Result{}, nil })
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite existing multi-read artifact") {
		t.Fatalf("err=%v", err)
	}
	if called {
		t.Fatal("physical acquisition started despite existing manifest")
	}
}
