package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/signaturefactory"
)

func signatureBundleCommand(store *signaturefactory.Store, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "signatures bundle requires a subcommand")
		os.Exit(2)
	}
	switch args[0] {
	case "build":
		signatureBundleBuildCommand(store, args[1:])
	case "sign":
		signatureBundleSignCommand(args[1:])
	case "verify":
		signatureBundleVerifyCommand(args[1:])
	case "install":
		signatureBundleInstallCommand(store, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown signatures bundle subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

func signatureBundleBuildCommand(store *signaturefactory.Store, args []string) {
	fs := flag.NewFlagSet("signatures bundle build", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	version := fs.String("version", "", "release version MAJOR.MINOR.PATCH")
	output := fs.String("output", "", "new output bundle directory")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 || *version == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "signatures bundle build requires --version and --output")
		os.Exit(2)
	}
	manifest, err := signaturefactory.BuildDistributionBundle(store.Root, *output, *version, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(os.Stderr, "bundle build failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("built unsigned bundle %s -> %s\n", manifest.Version, *output)
}

func signatureBundleSignCommand(args []string) {
	fs := flag.NewFlagSet("signatures bundle sign", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	privateKeyPath := fs.String("private-key", "", "file containing one lowercase hex Ed25519 private key")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 || *privateKeyPath == "" {
		fmt.Fprintln(os.Stderr, "signatures bundle sign requires --private-key <file> <dir>")
		os.Exit(2)
	}
	keyData, err := os.ReadFile(*privateKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read private key failed: %v\n", err)
		os.Exit(1)
	}
	privateKey, err := signaturefactory.ParseDistributionPrivateKeyHexFile(keyData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "private key invalid: %v\n", err)
		os.Exit(1)
	}
	manifest, identity, err := signaturefactory.SignDistributionBundle(fs.Arg(0), privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bundle sign failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("signed bundle %s manifest-sha256=%s\n", manifest.Version, identity)
}

func signatureBundleVerifyCommand(args []string) {
	fs := flag.NewFlagSet("signatures bundle verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	trustedKeyPath := fs.String("trusted-key", "", "file containing one lowercase hex Ed25519 public key")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 || *trustedKeyPath == "" {
		fmt.Fprintln(os.Stderr, "signatures bundle verify requires --trusted-key <file> <dir>")
		os.Exit(2)
	}
	trusted, err := loadTrustedDistributionKey(*trustedKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trusted key invalid: %v\n", err)
		os.Exit(1)
	}
	manifest, identity, err := signaturefactory.VerifyDistributionBundle(fs.Arg(0), trusted)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bundle verify failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("verified bundle %s manifest-sha256=%s\n", manifest.Version, identity)
}

func signatureBundleInstallCommand(store *signaturefactory.Store, args []string) {
	fs := flag.NewFlagSet("signatures bundle install", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	trustedKeyPath := fs.String("trusted-key", "", "file containing one lowercase hex Ed25519 public key")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 || *trustedKeyPath == "" {
		fmt.Fprintln(os.Stderr, "signatures bundle install requires --trusted-key <file> <dir>")
		os.Exit(2)
	}
	trusted, err := loadTrustedDistributionKey(*trustedKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trusted key invalid: %v\n", err)
		os.Exit(1)
	}
	state, err := signaturefactory.InstallDistributionBundle(fs.Arg(0), store.Root, trusted)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bundle install failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("installed bundle %s manifest-sha256=%s\n", state.Version, state.ManifestSHA256)
}

func loadTrustedDistributionKey(path string) (*signaturefactory.TrustedDistributionKeys, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	publicKeyHex, err := signaturefactory.ParseDistributionPublicKeyHexFile(data)
	if err != nil {
		return nil, err
	}
	return signaturefactory.NewTrustedDistributionKeys(publicKeyHex)
}
