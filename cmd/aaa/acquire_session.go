package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/acquisition"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
)

type acquireSessionOutput struct {
	SessionPath string                    `json:"session_path"`
	Session     acquisition.Session       `json:"session"`
	Flux        fluxAcquireOutput         `json:"flux"`
	ADFSeries   acquireSeriesOutput       `json:"adf_series"`
}

func acquireSessionCommand(args []string) {
	fs := flag.NewFlagSet("acquire-session", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON")
	device := fs.String("device", "", "Greaseweazle device selector")
	gw := fs.String("gw", "", "Greaseweazle executable (default: AAA_GW or gw)")
	timeout := fs.Duration("timeout", 10*time.Minute, "maximum acquisition duration per physical read")
	reads := fs.Int("reads", 2, "number of independent ADF reads")
	note := fs.String("note", "", "operator/session note")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "acquire-session requires exactly one output prefix")
		os.Exit(2)
	}
	if *timeout <= 0 || *reads < 2 {
		fmt.Fprintln(os.Stderr, "acquire-session requires a positive timeout and at least 2 ADF reads")
		os.Exit(2)
	}

	g := acquisition.Greaseweazle{Executable: *gw, Device: *device, Timeout: *timeout}
	out, err := runAcquireSession(context.Background(), fs.Arg(0), *reads, *note, g.ReadSCP, g.ReadADF, scanner.ScanFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "acquire-session failed: %v\n", err)
		os.Exit(1)
	}
	recordAcquireCandidates(out.ADFSeries.Reads)
	if *jsonOut {
		encodeAcquireJSON(out)
		return
	}
	fmt.Println("AAA physical-media acquisition session")
	fmt.Printf("Flux:     %s %s\n", out.Flux.Acquisition.OutputName, out.Flux.Acquisition.OutputSHA256)
	fmt.Printf("ADF reads: %d (%s)\n", out.Session.Repeatability.ReadCount, out.Session.Repeatability.Status)
	fmt.Printf("Session:  %s\n", out.SessionPath)
	fmt.Printf("Relation: %s\n", out.Session.Relationship)
}

func runAcquireSession(ctx context.Context, prefix string, reads int, note string, fluxAcquire acquireFunc, adfAcquire acquireFunc, scan acquireScanFunc) (acquireSessionOutput, error) {
	if strings.TrimSpace(prefix) == "" {
		return acquireSessionOutput{}, errors.New("output prefix is required")
	}
	if reads < 2 {
		return acquireSessionOutput{}, errors.New("acquisition session requires at least two ADF reads")
	}
	if fluxAcquire == nil || adfAcquire == nil || scan == nil {
		return acquireSessionOutput{}, errors.New("flux acquisition, ADF acquisition and scan functions are required")
	}

	fluxPath := prefix + ".scp"
	fluxEvidencePath := fluxPath + ".acquisition.json"
	fluxLogPath := fluxPath + ".gw.log"
	adfBase := prefix + ".adf"
	repeatabilityPath := repeatabilityManifestPath(adfBase)
	sessionPath := prefix + ".session.json"

	planned := []string{fluxPath, fluxEvidencePath, fluxLogPath, repeatabilityPath, sessionPath}
	for i := 1; i <= reads; i++ {
		image := repeatedOutputPath(adfBase, i)
		planned = append(planned, image, image+".acquisition.json", image+".gw.log")
	}
	for _, path := range planned {
		if _, err := os.Stat(path); err == nil {
			return acquireSessionOutput{}, fmt.Errorf("refusing to overwrite existing session artifact: %s", path)
		} else if !os.IsNotExist(err) {
			return acquireSessionOutput{}, fmt.Errorf("inspect session artifact %s: %w", path, err)
		}
	}

	fluxResult, err := fluxAcquire(ctx, fluxPath)
	if err != nil {
		return acquireSessionOutput{}, fmt.Errorf("capture raw flux: %w", err)
	}
	fluxResult.Evidence.AcquisitionNote = note
	if err := fluxResult.Evidence.Validate(); err != nil {
		return acquireSessionOutput{}, fmt.Errorf("validate raw flux evidence: %w", err)
	}
	if err := writeJSONExclusive(fluxEvidencePath, fluxResult.Evidence); err != nil {
		return acquireSessionOutput{}, fmt.Errorf("write raw flux evidence: %w", err)
	}
	if err := writeFileExclusive(fluxLogPath, []byte(fluxResult.RawLog)); err != nil {
		return acquireSessionOutput{}, fmt.Errorf("write raw flux log: %w", err)
	}
	fluxOut := fluxAcquireOutput{Acquisition: fluxResult.Evidence, Image: fluxPath, Evidence: fluxEvidencePath, Log: fluxLogPath}

	series, err := runAcquireSeries(ctx, acquireOptions{OutputPath: adfBase, Note: note}, reads, repeatabilityPath, adfAcquire, scan)
	if err != nil {
		return acquireSessionOutput{}, fmt.Errorf("capture ADF series: %w", err)
	}
	adfEvidence := make([]acquisition.Evidence, 0, len(series.Reads))
	for _, read := range series.Reads {
		adfEvidence = append(adfEvidence, read.Acquisition)
	}
	session, err := acquisition.BuildSession(fluxResult.Evidence, adfEvidence, note, time.Now().UTC())
	if err != nil {
		return acquireSessionOutput{}, fmt.Errorf("build acquisition session: %w", err)
	}
	if err := writeJSONExclusive(sessionPath, session); err != nil {
		return acquireSessionOutput{}, fmt.Errorf("write acquisition session: %w", err)
	}
	return acquireSessionOutput{SessionPath: sessionPath, Session: session, Flux: fluxOut, ADFSeries: series}, nil
}

func sessionPrefix(path string) string {
	ext := filepath.Ext(path)
	if ext == ".adf" || ext == ".scp" {
		return strings.TrimSuffix(path, ext)
	}
	return path
}
