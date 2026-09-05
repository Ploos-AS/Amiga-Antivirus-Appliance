package main

import (
	"fmt"
	"os"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/signaturefactory"
)

func signatureExportCommand(store *signaturefactory.Store, args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "signatures export requires exactly one target")
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
