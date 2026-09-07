package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/acquisition"
)

type fluxAcquireOutput struct {
	Acquisition acquisition.Evidence `json:"acquisition"`
	Image       string               `json:"image_path"`
	Evidence    string               `json:"evidence_path"`
	Log         string               `json:"log_path"`
}

func acquireFluxCommand(args []string) {
	fs := flag.NewFlagSet("acquire-flux", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON")
	device := fs.String("device", "", "Greaseweazle device selector")
	gw := fs.String("gw", "", "Greaseweazle executable (default: AAA_GW or gw)")
	timeout := fs.Duration("timeout", 10*time.Minute, "maximum acquisition duration")
	evidencePath := fs.String("evidence", "", "flux evidence JSON path (default: OUTPUT.acquisition.json)")
	logPath := fs.String("log", "", "raw Greaseweazle log path (default: OUTPUT.gw.log)")
	note := fs.String("note", "", "operator acquisition note")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "acquire-flux requires exactly one output SCP path")
		os.Exit(2)
	}
	if *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "acquire-flux timeout must be positive")
		os.Exit(2)
	}

	outputPath := fs.Arg(0)
	if *evidencePath == "" {
		*evidencePath = outputPath + ".acquisition.json"
	}
	if *logPath == "" {
		*logPath = outputPath + ".gw.log"
	}
	for _, path := range []string{outputPath, *evidencePath, *logPath} {
		if _, err := os.Stat(path); err == nil {
			fmt.Fprintf(os.Stderr, "acquire-flux failed: refusing to overwrite existing artifact: %s\n", path)
			os.Exit(1)
		} else if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "acquire-flux failed: inspect artifact %s: %v\n", path, err)
			os.Exit(1)
		}
	}

	g := acquisition.Greaseweazle{Executable: *gw, Device: *device, Timeout: *timeout}
	result, err := g.ReadSCP(context.Background(), outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "acquire-flux failed: %v\n", err)
		os.Exit(1)
	}
	result.Evidence.AcquisitionNote = *note
	if err := result.Evidence.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "acquire-flux failed: validate evidence: %v\n", err)
		os.Exit(1)
	}
	if err := writeJSONExclusive(*evidencePath, result.Evidence); err != nil {
		fmt.Fprintf(os.Stderr, "acquire-flux failed: write evidence: %v\n", err)
		os.Exit(1)
	}
	if err := writeFileExclusive(*logPath, []byte(result.RawLog)); err != nil {
		fmt.Fprintf(os.Stderr, "acquire-flux failed: write log: %v\n", err)
		os.Exit(1)
	}

	out := fluxAcquireOutput{Acquisition: result.Evidence, Image: outputPath, Evidence: *evidencePath, Log: *logPath}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(os.Stderr, "output failed: %v\n", err)
			os.Exit(1)
		}
		return
	}
	fmt.Println("AAA raw flux acquisition")
	fmt.Printf("SCP:      %s\n", outputPath)
	fmt.Printf("SHA-256:  %s\n", result.Evidence.OutputSHA256)
	fmt.Printf("Size:     %d bytes\n", result.Evidence.OutputSize)
	fmt.Printf("Tool:     %s %s\n", result.Evidence.Tool, result.Evidence.ToolVersion)
	fmt.Printf("Evidence: %s\n", *evidencePath)
	fmt.Printf("Log:      %s\n", *logPath)
	fmt.Println("Scan:     not run (raw flux is preservation evidence, not ADF scan input)")
}
