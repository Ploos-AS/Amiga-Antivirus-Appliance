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

func TestRunAcquireSessionCreatesFluxADFSeriesAndManifest(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "disk")
	now := time.Now().UTC()

	fluxAcquire := func(_ context.Context, path string) (acquisition.Result, error) {
		payload := []byte("raw-flux")
		sum := sha256.Sum256(payload)
		digest := hex.EncodeToString(sum[:])
		if err := os.WriteFile(path, payload, 0o640); err != nil {
			return acquisition.Result{}, err
		}
		return acquisition.Result{ImagePath: path, RawLog: "flux ok\n", Evidence: acquisition.Evidence{
			Method: "physical-floppy-flux", Tool: "greaseweazle", ToolVersion: "gw 1.23", Device: "gw0", Format: "scp-raw-flux", OutputName: filepath.Base(path), OutputSHA256: digest, OutputSize: int64(len(payload)), Command: []string{"gw", "read", "--raw"}, StartedAt: now, FinishedAt: now,
		}}, nil
	}
	adfPayload := []byte("same-adf")
	adfSum := sha256.Sum256(adfPayload)
	adfDigest := hex.EncodeToString(adfSum[:])
	adfAcquire := func(_ context.Context, path string) (acquisition.Result, error) {
		if err := os.WriteFile(path, adfPayload, 0o640); err != nil {
			return acquisition.Result{}, err
		}
		return acquisition.Result{ImagePath: path, RawLog: "adf ok\n", Evidence: acquisition.Evidence{
			Method: "physical-floppy", Tool: "greaseweazle", ToolVersion: "gw 1.23", Device: "gw0", Format: "adf", OutputName: filepath.Base(path), OutputSHA256: adfDigest, OutputSize: int64(len(adfPayload)), Command: []string{"gw", "read"}, StartedAt: now, FinishedAt: now,
		}}, nil
	}
	scan := func(path string) (scanner.Result, error) {
		return scanner.Result{Name: filepath.Base(path), SHA256: adfDigest, Format: "adf", Verdict: "unknown"}, nil
	}

	out, err := runAcquireSession(context.Background(), prefix, 2, "drawer A", fluxAcquire, adfAcquire, scan)
	if err != nil {
		t.Fatal(err)
	}
	if out.Session.Repeatability.Status != acquisition.RepeatabilityReproducible {
		t.Fatalf("repeatability=%+v", out.Session.Repeatability)
	}
	if out.Session.Relationship != "same-operator-session; no SCP-to-ADF derivation asserted" {
		t.Fatalf("relationship=%q", out.Session.Relationship)
	}
	if out.Session.Note != "drawer A" || out.Flux.Acquisition.AcquisitionNote != "drawer A" {
		t.Fatalf("note propagation failed: session=%q flux=%q", out.Session.Note, out.Flux.Acquisition.AcquisitionNote)
	}
	for _, path := range []string{
		prefix + ".scp",
		prefix + ".scp.acquisition.json",
		prefix + ".scp.gw.log",
		prefix + ".read-01.adf",
		prefix + ".read-02.adf",
		prefix + ".repeatability.json",
		prefix + ".session.json",
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing session artifact %s: %v", path, err)
		}
	}
}

func TestRunAcquireSessionPreflightStopsBeforePhysicalRead(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "disk")
	if err := os.WriteFile(prefix+".session.json", []byte("keep"), 0o640); err != nil {
		t.Fatal(err)
	}
	called := false
	acquire := func(context.Context, string) (acquisition.Result, error) {
		called = true
		return acquisition.Result{}, nil
	}
	_, err := runAcquireSession(context.Background(), prefix, 2, "", acquire, acquire, func(string) (scanner.Result, error) { return scanner.Result{}, nil })
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite existing session artifact") {
		t.Fatalf("err=%v", err)
	}
	if called {
		t.Fatal("physical acquisition started despite pre-existing session artifact")
	}
}

func TestRunAcquireSessionPreservesFluxWhenADFCaptureFails(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "disk")
	now := time.Now().UTC()
	fluxAcquire := func(_ context.Context, path string) (acquisition.Result, error) {
		payload := []byte("raw-flux")
		sum := sha256.Sum256(payload)
		digest := hex.EncodeToString(sum[:])
		if err := os.WriteFile(path, payload, 0o640); err != nil {
			return acquisition.Result{}, err
		}
		return acquisition.Result{ImagePath: path, Evidence: acquisition.Evidence{Method: "physical-floppy-flux", Tool: "greaseweazle", ToolVersion: "gw", Format: "scp-raw-flux", OutputName: filepath.Base(path), OutputSHA256: digest, OutputSize: int64(len(payload)), Command: []string{"gw", "read"}, StartedAt: now, FinishedAt: now}}, nil
	}
	adfAcquire := func(context.Context, string) (acquisition.Result, error) { return acquisition.Result{}, os.ErrInvalid }

	_, err := runAcquireSession(context.Background(), prefix, 2, "", fluxAcquire, adfAcquire, func(string) (scanner.Result, error) { return scanner.Result{}, nil })
	if err == nil {
		t.Fatal("expected ADF acquisition failure")
	}
	if _, err := os.Stat(prefix + ".scp"); err != nil {
		t.Fatalf("flux evidence should be preserved: %v", err)
	}
	if _, err := os.Stat(prefix + ".session.json"); !os.IsNotExist(err) {
		t.Fatalf("session manifest must not exist after incomplete session: %v", err)
	}
}
