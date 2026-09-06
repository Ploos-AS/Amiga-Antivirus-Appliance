package main

import (
	"fmt"
	"os"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/signaturefactory"
)

func signatureExportCommand(store *signaturefactory.Store, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "signatures export requires a target")
		os.Exit(2)
	}

	if args[0] == "amiguard" {
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "signatures export amiguard requires exactly one candidate id")
			os.Exit(2)
		}
		candidate, err := store.ReadCandidate(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "read AmiGuard export candidate failed: %v\n", err)
			os.Exit(1)
		}
		encoded, err := signaturefactory.MarshalAmiGuardResearch(candidate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "AmiGuard research export failed: %v\n", err)
			os.Exit(1)
		}
		if _, err := os.Stdout.Write(encoded); err != nil {
			fmt.Fprintf(os.Stderr, "AmiGuard research output failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "signatures export aaa/clamav take no additional arguments")
		os.Exit(2)
	}

	var (
		path  string
		count int
		err   error
	)
	switch args[0] {
	case "aaa":
		path, count, err = store.ExportNativeBootblocks()
	case "clamav":
		path, count, err = store.ExportClamAVHashes()
	default:
		fmt.Fprintf(os.Stderr, "unknown signatures export target: %s\n", args[0])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "signature export failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("exported %s signatures: %d -> %s\n", args[0], count, path)
}
