package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	m8support "github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/m8/support"
)

func supportCommand(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "support requires a subcommand")
		os.Exit(2)
	}

	switch args[0] {
	case "identify":
		supportIdentifyCommand(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown support subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

func supportIdentifyCommand(args []string) {
	fs := flag.NewFlagSet("support identify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	kind := fs.String("kind", "", "support kind: xvs-library or virusz-iii-bootblocks")
	name := fs.String("name", "", "component name")
	version := fs.String("version", "", "component version")
	source := fs.String("source", "", "source/provenance label")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "support identify requires exactly one file")
		os.Exit(2)
	}
	if *kind == "" || *version == "" {
		fmt.Fprintln(os.Stderr, "support identify requires --kind and --version")
		os.Exit(2)
	}

	componentKind := m8support.Kind(*kind)
	componentName := *name
	if componentName == "" {
		switch componentKind {
		case m8support.KindXVS:
			componentName = "xvs.library"
		case m8support.KindVirusZBootblocks:
			componentName = "VirusZ_III.Bootblocks"
		}
	}

	component, err := m8support.IdentifyFile(componentKind, componentName, *version, *source, fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "support identify failed: %v\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(component); err != nil {
		fmt.Fprintf(os.Stderr, "output failed: %v\n", err)
		os.Exit(1)
	}
}
