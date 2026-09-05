package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/signaturefactory"
)

func signaturePromoteCommand(store *signaturefactory.Store, args []string) {
	fs := flag.NewFlagSet("signatures promote", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	validationPath := fs.String("validation", "", "M7.3 corpus validation result JSON required for pattern candidates")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "signatures promote requires exactly one candidate id")
		os.Exit(2)
	}
	id := fs.Arg(0)
	candidate, err := store.ReadCandidate(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signature promote failed: %v\n", err)
		os.Exit(1)
	}

	var promoted signaturefactory.Candidate
	if candidate.Kind == signaturefactory.KindPattern {
		if *validationPath == "" {
			fmt.Fprintln(os.Stderr, "signature promote failed: pattern candidates require --validation <result.json>")
			os.Exit(1)
		}
		data, err := os.ReadFile(*validationPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "signature promote failed: read validation result: %v\n", err)
			os.Exit(1)
		}
		result, err := signaturefactory.DecodeCorpusValidationResultStrict(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "signature promote failed: %v\n", err)
			os.Exit(1)
		}
		promoted, err = store.PromotePattern(id, result)
	} else {
		if *validationPath != "" {
			fmt.Fprintln(os.Stderr, "signature promote failed: --validation is only valid for pattern candidates")
			os.Exit(2)
		}
		promoted, err = store.Promote(id)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "signature promote failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s %s\n", promoted.Status, promoted.ID)
}
