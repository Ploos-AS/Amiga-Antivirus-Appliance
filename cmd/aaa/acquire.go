package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
	timeout := fs.Duration("timeout", 10*time.Minute, "maximum acquisition duration")
	evidencePath := fs.String("evidence", "", "acquisition evidence JSON path (default: OUTPUT.acquisition.json)")
	logPath := fs.String("log", "", "raw Greaseweazle log path (default: OUTPUT.gw.log)")
	note := fs.String("note", "", "operator acquisition note")
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
	out, err := runAcquire(context.Background(), opts, g.ReadADF, scanner.ScanFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "acquire failed: %v\n", err)
		os.Exit(1)
	}
	if out.Scan.Verdict == "infected" {
		if err := recordSignatureCandidates(out.Scan); err != nil {
			fmt.Fprintf(os.Stderr, "signature factory warning: %v\n", err)
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(os.Stderr, "output failed: %v\n", err)
			os.Exit(1)
		}
		return
	}
	fmt.Println("AAA acquisition")
	fmt.Printf("Image:    %s\n", opts.OutputPath)
	fmt.Printf("SHA-256:  %s\n", out.Acquisition.OutputSHA256)
	fmt.Printf("Size:     %d bytes\n", out.Acquisition.OutputSize)
	fmt.Printf("Tool:     %s %s\n", out.Acquisition.Tool, out.Acquisition.ToolVersion)
	fmt.Printf("Evidence: %s\n", out.Evidence)
	fmt.Printf("Log:      %s\n", out.Log)
	fmt.Printf("Scan:     %s (%s)\n", out.Scan.Verdict, out.Scan.Format)
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
