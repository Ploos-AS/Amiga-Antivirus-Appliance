package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
)

const version = "0.4.0-dev"

func usage() {
	fmt.Fprintf(os.Stderr, "AAA — Amiga AntiVirus Appliance\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  aaa scan [--json] <file>\n")
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

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
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
	if result.ADF != nil {
		fmt.Printf("Disk:     %s (%d blocks)\n", result.ADF.DiskType, result.ADF.Blocks)
		fmt.Printf("DOS type: DOS\\%d (%s)\n", result.ADF.DOSVersion, result.ADF.Filesystem)
		fmt.Printf("Bootable: %t\n", result.ADF.Bootable)
		fmt.Printf("Boot SHA: %s\n", result.ADF.BootblockSHA256)
		fmt.Printf("Boot CRC: stored=%08x calculated=%08x valid=%t\n", result.ADF.StoredChecksum, result.ADF.CalculatedChecksum, result.ADF.ChecksumValid)
		fmt.Printf("Root:     %d expected=%d plausible=%t\n", result.ADF.RootBlock, result.ADF.ExpectedRootBlock, result.ADF.RootBlockPlausible)
		if result.Filesystem != nil {
			fmt.Printf("FS root:  %d valid=%t\n", result.Filesystem.RootBlock, result.Filesystem.RootBlockValid)
			fmt.Printf("FS items: %d files, %d directories\n", result.Filesystem.FileCount, result.Filesystem.DirectoryCount)
			for _, entry := range result.Filesystem.Entries {
				fmt.Printf("  %-9s %s [block %d]\n", entry.Type, entry.Path, entry.HeaderBlock)
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
	if result.Detection != "" {
		fmt.Printf("Detect:   %s\n", result.Detection)
	}
	fmt.Printf("Verdict:  %s\n", result.Verdict)
}
