package main

import (
	"context"
	"encoding/json"
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

type acquireOutput struct {
	Acquisition acquisition.Evidence `json:"acquisition"`
	Scan        scanner.Result       `json:"scan"`
	Evidence    string               `json:"evidence_path"`
	Log         string               `json:"log_path"`
}

type acquireSeriesOutput struct {
	Reads         []acquireOutput          `json:"reads"`
	Repeatability acquisition.Repeatability `json:"repeatability"`
	Manifest      string                   `json:"manifest_path"`
}

type acquireOptions struct {
	OutputPath   string
	EvidencePath string
	LogPath      string
	Device       string
	Executable   string
	Note         string
	Timeout      time.Duration
}

type acquireFunc func(context.Context, string) (acquisition.Result, error)
type acquireScanFunc func(string) (scanner.Result, error)

func acquireCommand(args []string) {
	fs := flag.NewFlagSet("acquire", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON")
	device := fs.String("device", "", "Greaseweazle device selector")
	gw := fs.String("gw", "", "Greaseweazle executable (default: AAA_GW or gw)")
	timeout := fs.Duration("timeout", 10*time.Minute, "maximum acquisition duration per read")
	evidencePath := fs.String("evidence", "", "acquisition evidence JSON path (single-read only; default: OUTPUT.acquisition.json)")
	logPath := fs.String("log", "", "raw Greaseweazle log path (single-read only; default: OUTPUT.gw.log)")
	note := fs.String("note", "", "operator acquisition note")
	reads := fs.Int("reads", 1, "number of independent physical reads")
	repeatabilityPath := fs.String("repeatability", "", "multi-read manifest path (default: OUTPUT stem + .repeatability.json)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "acquire requires exactly one output ADF path")
		os.Exit(2)
	}
	if *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "acquire timeout must be positive")
		os.Exit(2)
	}
	if *reads < 1 {
		fmt.Fprintln(os.Stderr, "acquire reads must be at least 1")
		os.Exit(2)
	}
	if *reads > 1 && (*evidencePath != "" || *logPath != "") {
		fmt.Fprintln(os.Stderr, "--evidence and --log are single-read options; multi-read sidecars are derived automatically")
		os.Exit(2)
	}
	if *reads == 1 && *repeatabilityPath != "" {
		fmt.Fprintln(os.Stderr, "--repeatability requires --reads greater than 1")
		os.Exit(2)
	}

	opts := acquireOptions{
		OutputPath:   fs.Arg(0),
		EvidencePath: *evidencePath,
		LogPath:      *logPath,
		Device:       *device,
		Executable:   *gw,
		Note:         *note,
		Timeout:      *timeout,
	}
	g := acquisition.Greaseweazle{Executable: opts.Executable, Device: opts.Device, Timeout: opts.Timeout}

	if *reads == 1 {
		out, err := runAcquire(context.Background(), opts, g.ReadADF, scanner.ScanFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "acquire failed: %v\n", err)
			os.Exit(1)
		}
		recordAcquireCandidates([]acquireOutput{out})
		if *jsonOut {
			encodeAcquireJSON(out)
			return
		}
		printAcquire(out, opts.OutputPath)
		return
	}

	series, err := runAcquireSeries(context.Background(), opts, *reads, *repeatabilityPath, g.ReadADF, scanner.ScanFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "acquire failed: %v\n", err)
		os.Exit(1)
	}
	recordAcquireCandidates(series.Reads)
	if *jsonOut {
		encodeAcquireJSON(series)
		return
	}
	fmt.Println("AAA multi-read acquisition")
	fmt.Printf("Reads:    %d\n", series.Repeatability.ReadCount)
	fmt.Printf("Status:   %s\n", series.Repeatability.Status)
	fmt.Printf("Unique:   %d image hash(es)\n", series.Repeatability.UniqueHashes)
	for _, read := range series.Reads {
		fmt.Printf("  %-20s %s verdict=%s\n", read.Acquisition.OutputName, read.Acquisition.OutputSHA256, read.Scan.Verdict)
	}
	fmt.Printf("Manifest: %s\n", series.Manifest)
}

func encodeAcquireJSON(value any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		fmt.Fprintf(os.Stderr, "output failed: %v\n", err)
		os.Exit(1)
	}
}

func printAcquire(out acquireOutput, imagePath string) {
	fmt.Println("AAA acquisition")
	fmt.Printf("Image:    %s\n", imagePath)
	fmt.Printf("SHA-256:  %s\n", out.Acquisition.OutputSHA256)
	fmt.Printf("Size:     %d bytes\n", out.Acquisition.OutputSize)
	fmt.Printf("Tool:     %s %s\n", out.Acquisition.Tool, out.Acquisition.ToolVersion)
	fmt.Printf("Evidence: %s\n", out.Evidence)
	fmt.Printf("Log:      %s\n", out.Log)
	fmt.Printf("Scan:     %s (%s)\n", out.Scan.Verdict, out.Scan.Format)
}

func recordAcquireCandidates(reads []acquireOutput) {
	for _, out := range reads {
		if out.Scan.Verdict == "infected" {
			if err := recordSignatureCandidates(out.Scan); err != nil {
				fmt.Fprintf(os.Stderr, "signature factory warning: %v\n", err)
			}
		}
	}
}

func runAcquireSeries(ctx context.Context, opts acquireOptions, reads int, manifestPath string, acquire acquireFunc, scan acquireScanFunc) (acquireSeriesOutput, error) {
	if reads < 2 {
		return acquireSeriesOutput{}, errors.New("multi-read acquisition requires at least two reads")
	}
	if filepath.Ext(opts.OutputPath) != ".adf" {
		return acquireSeriesOutput{}, errors.New("M12.2 acquisition output must use .adf")
	}
	if manifestPath == "" {
		manifestPath = repeatabilityManifestPath(opts.OutputPath)
	}
	planned := make([]string, 0, reads*3+1)
	planned = append(planned, manifestPath)
	for i := 1; i <= reads; i++ {
		image := repeatedOutputPath(opts.OutputPath, i)
		planned = append(planned, image, image+".acquisition.json", image+".gw.log")
	}
	for _, path := range planned {
		if _, err := os.Stat(path); err == nil {
			return acquireSeriesOutput{}, fmt.Errorf("refusing to overwrite existing multi-read artifact: %s", path)
		} else if !os.IsNotExist(err) {
			return acquireSeriesOutput{}, fmt.Errorf("inspect multi-read artifact %s: %w", path, err)
		}
	}

	outputs := make([]acquireOutput, 0, reads)
	evidence := make([]acquisition.Evidence, 0, reads)
	for i := 1; i <= reads; i++ {
		readOpts := opts
		readOpts.OutputPath = repeatedOutputPath(opts.OutputPath, i)
		readOpts.EvidencePath = ""
		readOpts.LogPath = ""
		out, err := runAcquire(ctx, readOpts, acquire, scan)
		if err != nil {
			return acquireSeriesOutput{}, fmt.Errorf("read %d/%d: %w", i, reads, err)
		}
		outputs = append(outputs, out)
		evidence = append(evidence, out.Acquisition)
	}

	repeatability, err := acquisition.CompareReads(evidence)
	if err != nil {
		return acquireSeriesOutput{}, fmt.Errorf("compare repeated acquisitions: %w", err)
	}
	series := acquireSeriesOutput{Reads: outputs, Repeatability: repeatability, Manifest: manifestPath}
	if err := writeJSONExclusive(manifestPath, series); err != nil {
		return acquireSeriesOutput{}, fmt.Errorf("write repeatability manifest: %w", err)
	}
	return series, nil
}

func repeatedOutputPath(base string, read int) string {
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return fmt.Sprintf("%s.read-%02d%s", stem, read, ext)
}

func repeatabilityManifestPath(base string) string {
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return stem + ".repeatability.json"
}

func runAcquire(ctx context.Context, opts acquireOptions, acquire acquireFunc, scan acquireScanFunc) (acquireOutput, error) {
	if acquire == nil || scan == nil {
		return acquireOutput{}, errors.New("acquire and scan functions are required")
	}
	if opts.OutputPath == "" {
		return acquireOutput{}, errors.New("output path is required")
	}
	if filepath.Ext(opts.OutputPath) != ".adf" {
		return acquireOutput{}, errors.New("M12.1 acquisition output must use .adf")
	}
	if opts.EvidencePath == "" {
		opts.EvidencePath = opts.OutputPath + ".acquisition.json"
	}
	if opts.LogPath == "" {
		opts.LogPath = opts.OutputPath + ".gw.log"
	}
	if opts.EvidencePath == opts.OutputPath || opts.LogPath == opts.OutputPath || opts.EvidencePath == opts.LogPath {
		return acquireOutput{}, errors.New("image, evidence and log paths must be distinct")
	}
	for _, path := range []string{opts.EvidencePath, opts.LogPath} {
		if _, err := os.Stat(path); err == nil {
			return acquireOutput{}, fmt.Errorf("refusing to overwrite existing sidecar: %s", path)
		} else if !os.IsNotExist(err) {
			return acquireOutput{}, fmt.Errorf("inspect sidecar %s: %w", path, err)
		}
	}

	acquired, err := acquire(ctx, opts.OutputPath)
	if err != nil {
		return acquireOutput{}, err
	}
	acquired.Evidence.AcquisitionNote = opts.Note
	if err := acquired.Evidence.Validate(); err != nil {
		return acquireOutput{}, fmt.Errorf("validate acquisition evidence: %w", err)
	}
	if err := writeJSONExclusive(opts.EvidencePath, acquired.Evidence); err != nil {
		return acquireOutput{}, fmt.Errorf("write acquisition evidence: %w", err)
	}
	if err := writeFileExclusive(opts.LogPath, []byte(acquired.RawLog)); err != nil {
		return acquireOutput{}, fmt.Errorf("write acquisition log: %w", err)
	}

	scanResult, err := scan(acquired.ImagePath)
	if err != nil {
		return acquireOutput{}, fmt.Errorf("scan acquired image: %w", err)
	}
	if scanResult.SHA256 != acquired.Evidence.OutputSHA256 {
		return acquireOutput{}, fmt.Errorf("acquisition/scan SHA-256 mismatch: acquired=%s scan=%s", acquired.Evidence.OutputSHA256, scanResult.SHA256)
	}
	return acquireOutput{Acquisition: acquired.Evidence, Scan: scanResult, Evidence: opts.EvidencePath, Log: opts.LogPath}, nil
}

func writeJSONExclusive(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileExclusive(path, data)
}

func writeFileExclusive(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
