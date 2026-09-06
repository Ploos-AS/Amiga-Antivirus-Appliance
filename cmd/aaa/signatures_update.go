package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/signaturefactory"
)

const defaultSignatureReleaseSource = "https://api.github.com/repos/Ploos-AS/Amiga-Antivirus-Appliance/releases?per_page=100"

func signatureUpdateCommand(store *signaturefactory.Store, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "signatures update requires a subcommand")
		os.Exit(2)
	}
	switch args[0] {
	case "check":
		signatureUpdateCheckCommand(store, args[1:])
	case "download":
		signatureUpdateDownloadCommand(args[1:])
	case "verify":
		signatureUpdateVerifyCommand(args[1:])
	case "install":
		signatureUpdateInstallCommand(store, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown signatures update subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

func signatureUpdateCheckCommand(store *signaturefactory.Store, args []string) {
	fs := flag.NewFlagSet("signatures update check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	source := fs.String("source", defaultSignatureReleaseSource, "GitHub-compatible releases API URL")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "signatures update check takes no positional arguments")
		os.Exit(2)
	}
	state, have, err := signaturefactory.ReadDistributionInstallState(store.Root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read active signature distribution failed: %v\n", err)
		os.Exit(1)
	}
	var current *signaturefactory.DistributionInstallState
	if have {
		current = &state
	} else {
		fmt.Println("no active signature distribution")
	}
	candidate, err := signaturefactory.DiscoverDistributionRelease(context.Background(), *source, current)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update check failed: %v\n", err)
		os.Exit(1)
	}
	if candidate == nil {
		fmt.Println("no newer signature release")
		return
	}
	fmt.Printf("signature update available %s\narchive: %s\n", candidate.Version, candidate.ArchiveURL)
	if candidate.ChecksumURL != "" {
		fmt.Printf("checksum: %s\n", candidate.ChecksumURL)
	}
}

func signatureUpdateDownloadCommand(args []string) {
	fs := flag.NewFlagSet("signatures update download", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	version := fs.String("version", "", "release version MAJOR.MINOR.PATCH")
	archiveURL := fs.String("url", "", "HTTP(S) release archive URL")
	output := fs.String("output", "", "completed archive path")
	sha := fs.String("sha256", "", "optional expected transport SHA-256")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 || *version == "" || *archiveURL == "" {
		fmt.Fprintln(os.Stderr, "signatures update download requires --version <version> --url <url> [--output <path>] [--sha256 <digest>]")
		os.Exit(2)
	}
	if *output == "" {
		*output = signaturefactory.DistributionArchivePrefix + *version + signaturefactory.DistributionArchiveSuffix
	}
	digest, err := signaturefactory.DownloadDistributionArchive(context.Background(), *archiveURL, *version, *output, *sha)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update download failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("downloaded signature release %s sha256=%s -> %s\n", *version, digest, *output)
}

func signatureUpdateVerifyCommand(args []string) {
	fs := flag.NewFlagSet("signatures update verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	key := fs.String("trusted-key", "", "trusted Ed25519 public key file")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 || *key == "" {
		fmt.Fprintln(os.Stderr, "signatures update verify requires --trusted-key <file> <artifact-or-dir>")
		os.Exit(2)
	}
	trusted, err := loadTrustedDistributionKey(*key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trusted key invalid: %v\n", err)
		os.Exit(1)
	}
	root, cleanup, err := updateBundleRoot(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "update extraction failed: %v\n", err)
		os.Exit(1)
	}
	defer cleanup()
	manifest, identity, err := signaturefactory.VerifyDistributionBundle(root, trusted)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update verify failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("verified signature release %s manifest-sha256=%s\n", manifest.Version, identity)
}

func signatureUpdateInstallCommand(store *signaturefactory.Store, args []string) {
	fs := flag.NewFlagSet("signatures update install", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	key := fs.String("trusted-key", "", "trusted Ed25519 public key file")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 || *key == "" {
		fmt.Fprintln(os.Stderr, "signatures update install requires --trusted-key <file> <artifact-or-dir>")
		os.Exit(2)
	}
	trusted, err := loadTrustedDistributionKey(*key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trusted key invalid: %v\n", err)
		os.Exit(1)
	}
	root, cleanup, err := updateBundleRoot(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "update extraction failed: %v\n", err)
		os.Exit(1)
	}
	defer cleanup()
	state, err := signaturefactory.InstallDistributionBundle(root, store.Root, trusted)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update install failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("installed signature release %s manifest-sha256=%s\n", state.Version, state.ManifestSHA256)
}

func updateBundleRoot(input string) (string, func(), error) {
	info, err := os.Stat(input)
	if err != nil {
		return "", func() {}, err
	}
	if info.IsDir() {
		return input, func() {}, nil
	}
	if !info.Mode().IsRegular() {
		return "", func() {}, fmt.Errorf("update input must be a regular archive or directory")
	}
	root, err := os.MkdirTemp("", "aaa-signature-update-")
	if err != nil {
		return "", func() {}, err
	}
	_ = os.Remove(root)
	if _, err := signaturefactory.ExtractDistributionReleaseArchive(input, root); err != nil {
		_ = os.RemoveAll(root)
		return "", func() {}, err
	}
	return filepath.Clean(root), func() { _ = os.RemoveAll(root) }, nil
}
