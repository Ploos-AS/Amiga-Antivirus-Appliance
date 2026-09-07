package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/signaturefactory"
)

const version = "0.6.0-dev"

type scanJSONOutput struct {
	Scan   scanner.Result                     `json:"scan"`
	ClamAV *signaturefactory.ClamAVScanResult `json:"clamav,omitempty"`
}

func usage() {
	fmt.Fprintf(os.Stderr, "AAA — Amiga AntiVirus Appliance\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  aaa scan [--json] [--clamav] <file>\n")
	fmt.Fprintf(os.Stderr, "  aaa daemon [--workers <n>] [--queue-depth <n>] [--state-root <dir>] [--incoming-root <dir>] [--max-upload-bytes <n>] [--listen <addr>]\n")
	fmt.Fprintf(os.Stderr, "  aaa support identify --kind <kind> --version <version> [--name <name>] [--source <source>] <file>\n")
	fmt.Fprintf(os.Stderr, "  aaa signatures candidates [--json]\n")
	fmt.Fprintf(os.Stderr, "  aaa signatures validate\n")
	fmt.Fprintf(os.Stderr, "  aaa signatures promote [--validation <result.json>] <id>\n")
	fmt.Fprintf(os.Stderr, "  aaa signatures reject <id>\n")
	fmt.Fprintf(os.Stderr, "  aaa signatures export aaa\n")
	fmt.Fprintf(os.Stderr, "  aaa signatures export clamav\n")
	fmt.Fprintf(os.Stderr, "  aaa signatures bundle build --version <version> --output <dir>\n")
	fmt.Fprintf(os.Stderr, "  aaa signatures bundle sign --private-key <file> <dir>\n")
	fmt.Fprintf(os.Stderr, "  aaa signatures bundle verify --trusted-key <file> <dir>\n")
	fmt.Fprintf(os.Stderr, "  aaa signatures bundle install --trusted-key <file> <dir>\n")
	fmt.Fprintf(os.Stderr, "  aaa signatures update check [--source <url>]\n")
	fmt.Fprintf(os.Stderr, "  aaa signatures update download --version <version> --url <url> [--output <path>] [--sha256 <digest>]\n")
	fmt.Fprintf(os.Stderr, "  aaa signatures update verify --trusted-key <file> <artifact-or-dir>\n")
	fmt.Fprintf(os.Stderr, "  aaa signatures update install --trusted-key <file> <artifact-or-dir>\n")
	fmt.Fprintf(os.Stderr, "  aaa version\n")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "scan":
		scanCommand(os.Args[2:])
	case "daemon":
		daemonCommand(os.Args[2:])
	case "support":
		supportCommand(os.Args[2:])
	case "signatures":
		signaturesCommand(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func scanCommand(args []string) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "print JSON result")
	clamAV := fs.Bool("clamav", false, "scan the input with clamscan and include attributed ClamAV evidence")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "scan requires exactly one file")
		os.Exit(2)
	}

	result, err := scanner.ScanFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		os.Exit(1)
	}

	output := scanJSONOutput{Scan: result}
	if *clamAV {
		startedAt := time.Now().UTC()
		clamResult := signaturefactory.RunClamAVScan(signaturefactory.ClamAVScanRequest{
			SamplePath:   fs.Arg(0),
			SampleSHA256: result.SHA256,
			StartedAt:    startedAt,
		})
		output.ClamAV = &clamResult
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(output); err != nil {
			fmt.Fprintf(os.Stderr, "encode result: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Printf("Name: %s\n", result.Name)
	fmt.Printf("Size: %d\n", result.Size)
	fmt.Printf("SHA256: %s\n", result.SHA256)
	fmt.Printf("Format: %s\n", result.Format)
	fmt.Printf("Verdict: %s\n", result.Verdict)
	if result.Detection != "" {
		fmt.Printf("Detection: %s\n", result.Detection)
	}
	if output.ClamAV != nil {
		fmt.Printf("ClamAV engine: %s\n", output.ClamAV.Engine.Name)
		fmt.Printf("ClamAV version: %s\n", output.ClamAV.Engine.Version)
		fmt.Printf("ClamAV database: %s\n", output.ClamAV.Engine.DatabaseVersion)
		fmt.Printf("ClamAV verdict: %s\n", output.ClamAV.Verdict)
		if output.ClamAV.DetectionName != "" {
			fmt.Printf("ClamAV detection: %s\n", output.ClamAV.DetectionName)
		}
		if output.ClamAV.Error != "" {
			fmt.Printf("ClamAV error: %s\n", output.ClamAV.Error)
		}
	}
}

func signaturesCommand(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "signatures requires a subcommand")
		os.Exit(2)
	}

	switch args[0] {
	case "candidates":
		signaturesCandidates(args[1:])
	case "validate":
		signaturesValidate(args[1:])
	case "promote":
		signaturesPromote(args[1:])
	case "reject":
		signaturesReject(args[1:])
	case "export":
		signaturesExport(args[1:])
	case "bundle":
		signaturesBundle(args[1:])
	case "update":
		signaturesUpdate(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown signatures subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

func signaturesCandidates(args []string) {
	fs := flag.NewFlagSet("signatures candidates", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "print candidates as JSON")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "signatures candidates takes no positional arguments")
		os.Exit(2)
	}

	store, err := signaturefactory.NewStore(signaturefactory.DefaultRoot())
	if err != nil {
		fmt.Fprintf(os.Stderr, "signature store failed: %v\n", err)
		os.Exit(1)
	}
	candidates, err := store.ListCandidates()
	if err != nil {
		fmt.Fprintf(os.Stderr, "list candidates failed: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(candidates); err != nil {
			fmt.Fprintf(os.Stderr, "encode candidates: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if len(candidates) == 0 {
		fmt.Println("No signature candidates.")
		return
	}
	for _, candidate := range candidates {
		fmt.Printf("%s\t%s\t%s\n", candidate.ID, candidate.Status, candidate.DetectionName)
	}
}

func signaturesValidate(args []string) {
	fs := flag.NewFlagSet("signatures validate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "signatures validate takes no positional arguments")
		os.Exit(2)
	}

	root := signaturefactory.DefaultRoot()
	result, err := signaturefactory.ValidateStore(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signature validation failed: %v\n", err)
		os.Exit(1)
	}
	if !result.Valid {
		fmt.Fprintf(os.Stderr, "signature validation failed:\n")
		for _, issue := range result.Issues {
			fmt.Fprintf(os.Stderr, "- %s\n", issue)
		}
		os.Exit(1)
	}
	fmt.Printf("Signature store valid: %d candidates, %d promoted, %d rejected\n", result.Candidates, result.Promoted, result.Rejected)
}

func signaturesReject(args []string) {
	fs := flag.NewFlagSet("signatures reject", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "signatures reject requires exactly one candidate id")
		os.Exit(2)
	}

	store, err := signaturefactory.NewStore(signaturefactory.DefaultRoot())
	if err != nil {
		fmt.Fprintf(os.Stderr, "signature store failed: %v\n", err)
		os.Exit(1)
	}
	candidate, err := store.Reject(fs.Arg(0), time.Now().UTC())
	if err != nil {
		fmt.Fprintf(os.Stderr, "reject candidate failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Rejected signature candidate %s\n", candidate.ID)
}
