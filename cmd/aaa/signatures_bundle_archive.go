package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/signaturefactory"
)

func signatureBundleArchiveCommand(args []string) {
	fs := flag.NewFlagSet("signatures bundle archive", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	trustedKeyPath := fs.String("trusted-key", "", "file containing one lowercase hex Ed25519 public key")
	output := fs.String("output", "", "output aaa-signatures-<version>.tar.gz path")
	checksum := fs.String("checksum", "", "optional output .sha256 path")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 || *trustedKeyPath == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "signatures bundle archive requires --trusted-key <file> --output <archive> [--checksum <file>] <dir>")
		os.Exit(2)
	}
	trusted, err := loadTrustedDistributionKey(*trustedKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trusted key invalid: %v\n", err)
		os.Exit(1)
	}
	manifest, digest, err := signaturefactory.BuildDistributionReleaseArchive(fs.Arg(0), *output, trusted)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bundle archive failed: %v\n", err)
		os.Exit(1)
	}
	if *checksum != "" {
		want := *output + signaturefactory.DistributionArchiveChecksumSuffix
		if filepath.Clean(*checksum) != filepath.Clean(want) {
			fmt.Fprintf(os.Stderr, "checksum path must be %s\n", want)
			_ = os.Remove(*output)
			os.Exit(1)
		}
		checksumBytes, checksumDigest, err := signaturefactory.DistributionArchiveChecksumBytes(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bundle checksum failed: %v\n", err)
			_ = os.Remove(*output)
			os.Exit(1)
		}
		if checksumDigest != digest {
			fmt.Fprintln(os.Stderr, "bundle checksum identity mismatch")
			_ = os.Remove(*output)
			os.Exit(1)
		}
		if err := os.WriteFile(*checksum, checksumBytes, 0o640); err != nil {
			fmt.Fprintf(os.Stderr, "write checksum failed: %v\n", err)
			_ = os.Remove(*output)
			os.Exit(1)
		}
	}
	fmt.Printf("archived bundle %s archive-sha256=%s\n", manifest.Version, digest)
}
