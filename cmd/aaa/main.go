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
	Scan   scanner.Result                    `json:"scan"`
	ClamAV *signaturefactory.ClamAVScanResult `json:"clamav,omitempty"`
}

func usage() {
	fmt.Fprintf(os.Stderr, "AAA — Amiga AntiVirus Appliance\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  aaa scan [--json] [--clamav] <file>\n")
	fmt.Fprintf(os.Stderr, "  aaa signatures candidates [--json]\n")
	fmt.Fprintf(os.Stderr, "  aaa signatures validate\n")
	fmt.Fprintf(os.Stderr, "  aaa signatures promote <id>\n")
	fmt.Fprintf(os.Stderr, "  aaa signatures reject <id>\n")
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
	case "signatures":
		signaturesCommand(os.Args[2:])
	case "version", "--version", "-version":
		fmt.Printf("aaa %s\n", version)
	case "help", "--help", "-h":
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
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON")
	clamAVEnabled := fs.Bool("clamav", false, "also scan the exact input file with ClamAV")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "scan requires exactly one file")
		os.Exit(2)
	}

	path := fs.Arg(0)
	result, err := scanner.ScanFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		os.Exit(1)
	}
	if result.Verdict == "infected" {
		if err := recordSignatureCandidates(result); err != nil {
			fmt.Fprintf(os.Stderr, "signature factory warning: %v\n", err)
		}
	}

	var clamResult *signaturefactory.ClamAVScanResult
	if *clamAVEnabled {
		clam, err := signaturefactory.RunClamAV(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "clamav scan failed: %v\n", err)
			os.Exit(1)
		}
		clamResult = &clam
		if clam.Verdict == "infected" {
			if err := recordClamAVCandidate(result, clam); err != nil {
				fmt.Fprintf(os.Stderr, "signature factory warning: %v\n", err)
			}
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if clamResult != nil {
			if err := enc.Encode(scanJSONOutput{Scan: result, ClamAV: clamResult}); err != nil {
				fmt.Fprintf(os.Stderr, "output failed: %v\n", err)
				os.Exit(1)
			}
		} else if err := enc.Encode(result); err != nil {
			fmt.Fprintf(os.Stderr, "output failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Printf("AAA scan\n")
	fmt.Printf("File:     %s\n", result.Name)
	fmt.Printf("Size:     %d bytes\n", result.Size)
	fmt.Printf("SHA-256:  %s\n", result.SHA256)
	fmt.Printf("Format:   %s\n", result.Format)
	if result.Archive != nil {
		fmt.Printf("Archive:  %s expanded=%d bytes\n", result.Archive.Format, result.Archive.ExpandedSize)
		for _, member := range result.Archive.Members {
			fmt.Printf("  member    %s [%d bytes, %s]\n", member.Name, member.Size, member.Format)
			fmt.Printf("            SHA-256 %s\n", member.SHA256)
		}
		for _, warning := range result.Archive.Warnings {
			fmt.Printf("Archive warn: %s\n", warning)
		}
	}
	for _, member := range result.MemberResults {
		fmt.Printf("Member scan: %s [%s] verdict=%s\n", member.Name, member.Format, member.Verdict)
		if member.ADF != nil {
			fmt.Printf("             ADF %s DOS\\%d (%s) boot-sha=%s\n", member.ADF.DiskType, member.ADF.DOSVersion, member.ADF.Filesystem, member.ADF.BootblockSHA256)
		}
		if member.Filesystem != nil {
			fmt.Printf("             FS %d files, %d directories, %d Hunk files\n", member.Filesystem.FileCount, member.Filesystem.DirectoryCount, member.Filesystem.HunkFileCount)
		}
		if member.Hunk != nil {
			fmt.Printf("             Hunk %d segments, code=%d data=%d bss=%d bytes\n", member.Hunk.HunkCount, member.Hunk.CodeBytes, member.Hunk.DataBytes, member.Hunk.BSSBytes)
		}
		if member.Detection != "" {
			fmt.Printf("             Detect %s\n", member.Detection)
		}
		if member.Error != "" {
			fmt.Printf("             Error %s\n", member.Error)
		}
	}
	if result.ADF != nil {
		fmt.Printf("Disk:     %s (%d blocks)\n", result.ADF.DiskType, result.ADF.Blocks)
		fmt.Printf("DOS type: DOS\\%d (%s)\n", result.ADF.DOSVersion, result.ADF.Filesystem)
		fmt.Printf("Bootable: %t\n", result.ADF.Bootable)
		fmt.Printf("Boot SHA: %s\n", result.ADF.BootblockSHA256)
		fmt.Printf("Checksum: stored=%08x calculated=%08x valid=%t\n", result.ADF.StoredChecksum, result.ADF.CalculatedChecksum, result.ADF.ChecksumValid)
		fmt.Printf("Root:     %d expected=%d plausible=%t\n", result.ADF.RootBlock, result.ADF.ExpectedRootBlock, result.ADF.RootBlockPlausible)
		if result.Filesystem != nil {
			fmt.Printf("FS root:  %d valid=%t\n", result.Filesystem.RootBlock, result.Filesystem.RootBlockValid)
			fmt.Printf("FS items: %d files, %d directories, %d Hunk files\n", result.Filesystem.FileCount, result.Filesystem.DirectoryCount, result.Filesystem.HunkFileCount)
			for _, entry := range result.Filesystem.Entries {
				if entry.Payload != nil {
					fmt.Printf("  %-9s %s [block %d, %d bytes, complete=%t]\n", entry.Type, entry.Path, entry.HeaderBlock, entry.Payload.Size, entry.Payload.Complete)
					if entry.Payload.SHA256 != "" {
						fmt.Printf("             SHA-256 %s\n", entry.Payload.SHA256)
					}
					if entry.Hunk != nil {
						fmt.Printf("             Hunk: %d segments, code=%d data=%d bss=%d bytes\n", entry.Hunk.HunkCount, entry.Hunk.CodeBytes, entry.Hunk.DataBytes, entry.Hunk.BSSBytes)
					}
				} else {
					fmt.Printf("  %-9s %s [block %d]\n", entry.Type, entry.Path, entry.HeaderBlock)
				}
			}
			for _, warning := range result.Filesystem.Warnings {
				fmt.Printf("FS warn:  %s\n", warning)
			}
		}
		if result.BootblockMatch == nil {
			fmt.Printf("Boot DB:  unknown\n")
		} else {
			fmt.Printf("Boot DB:  %s — %s\n", result.BootblockMatch.Status, result.BootblockMatch.Name)
			fmt.Printf("Source:   %s\n", result.BootblockMatch.Source)
		}
	}
	if result.Hunk != nil {
		fmt.Printf("Hunk:     recognized=%t segments=%d code=%d data=%d bss=%d bytes\n", result.Hunk.Recognized, result.Hunk.HunkCount, result.Hunk.CodeBytes, result.Hunk.DataBytes, result.Hunk.BSSBytes)
		for _, warning := range result.Hunk.Warnings {
			fmt.Printf("Hunk warn: %s\n", warning)
		}
	}
	if result.Detection != "" {
		fmt.Printf("Detect:   %s\n", result.Detection)
	}
	fmt.Printf("Verdict:  %s\n", result.Verdict)
	if clamResult != nil {
		fmt.Printf("ClamAV:   %s engine=%s db=%s\n", clamResult.Verdict, clamResult.EngineVersion, clamResult.SignatureDBVersion)
		if clamResult.DetectionName != "" {
			fmt.Printf("Clam detect: %s\n", clamResult.DetectionName)
		}
	}
}

func signaturesCommand(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "signatures requires a subcommand")
		usage()
		os.Exit(2)
	}
	store, err := signaturefactory.NewStore(signaturefactory.StoreRootFromEnv())
	if err != nil {
		fmt.Fprintf(os.Stderr, "signature store failed: %v\n", err)
		os.Exit(1)
	}

	switch args[0] {
	case "candidates":
		signatureCandidatesCommand(store, args[1:])
	case "validate":
		if len(args) != 1 {
			fmt.Fprintln(os.Stderr, "signatures validate takes no arguments")
			os.Exit(2)
		}
		if err := store.ValidateCandidates(); err != nil {
			fmt.Fprintf(os.Stderr, "signature validation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("signature candidates valid")
	case "promote", "reject":
		if len(args) != 2 {
			fmt.Fprintf(os.Stderr, "signatures %s requires exactly one candidate id\n", args[0])
			os.Exit(2)
		}
		var candidate signaturefactory.Candidate
		if args[0] == "promote" {
			candidate, err = store.Promote(args[1])
		} else {
			candidate, err = store.Reject(args[1])
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "signature %s failed: %v\n", args[0], err)
			os.Exit(1)
		}
		fmt.Printf("%s %s\n", candidate.Status, candidate.ID)
	default:
		fmt.Fprintf(os.Stderr, "unknown signatures subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

func signatureCandidatesCommand(store *signaturefactory.Store, args []string) {
	fs := flag.NewFlagSet("signatures candidates", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "signatures candidates takes no positional arguments")
		os.Exit(2)
	}
	candidates, err := store.ListCandidates()
	if err != nil {
		fmt.Fprintf(os.Stderr, "list signature candidates failed: %v\n", err)
		os.Exit(1)
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(candidates); err != nil {
			fmt.Fprintf(os.Stderr, "output failed: %v\n", err)
			os.Exit(1)
		}
		return
	}
	for _, candidate := range candidates {
		fmt.Printf("%s\t%s\t%s\t%s\n", candidate.ID, candidate.Kind, candidate.Confidence, candidate.DetectionName)
	}
}

func recordSignatureCandidates(result scanner.Result) error {
	store, err := signaturefactory.NewStore(signaturefactory.StoreRootFromEnv())
	if err != nil {
		return err
	}
	_, err = signaturefactory.RecordScanResult(store, result, time.Now().UTC())
	return err
}

func recordClamAVCandidate(result scanner.Result, clam signaturefactory.ClamAVScanResult) error {
	store, err := signaturefactory.NewStore(signaturefactory.StoreRootFromEnv())
	if err != nil {
		return err
	}
	_, _, err = signaturefactory.RecordClamAVResult(store, result, clam, time.Now().UTC())
	return err
}
