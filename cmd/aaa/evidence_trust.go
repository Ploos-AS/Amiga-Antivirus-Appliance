package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidencebundle"
)

const maxEvidenceTrustStoreBytes = 1 << 20

func runEvidenceTrust(args []string, stdout, stderr io.Writer) error {
	if len(args) < 1 {
		return errors.New("trust requires a subcommand: validate")
	}
	switch args[0] {
	case "validate":
		fs := flag.NewFlagSet("evidence trust validate", flag.ContinueOnError)
		fs.SetOutput(stderr)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("requires exactly one trust-store path")
		}
		store, err := readEvidenceTrustStore(fs.Arg(0))
		if err != nil {
			return err
		}
		active, revoked := 0, 0
		for _, key := range store.Keys {
			switch key.Status {
			case evidencebundle.TrustKeyActive:
				active++
			case evidencebundle.TrustKeyRevoked:
				revoked++
			}
		}
		fmt.Fprintf(stdout, "validated evidence trust store %s keys=%d active=%d revoked=%d\n", fs.Arg(0), len(store.Keys), active, revoked)
		return nil
	default:
		return fmt.Errorf("unknown trust subcommand: %s", args[0])
	}
}

func runEvidenceVerifyTrusted(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("evidence verify-trusted", flag.ContinueOnError)
	fs.SetOutput(stderr)
	trustStorePath := fs.String("trust-store", "", "operator-supplied evidence trust store")
	signaturePath := fs.String("signature", "", "detached signature path (default: BUNDLE.sig)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *trustStorePath == "" {
		return errors.New("requires --trust-store <store.json> <bundle.zip>")
	}
	bundlePath := fs.Arg(0)
	store, err := readEvidenceTrustStore(*trustStorePath)
	if err != nil {
		return err
	}
	sigPath := *signaturePath
	if sigPath == "" {
		sigPath = bundlePath + ".sig"
	}
	sigData, err := readSmallRegularFile(sigPath, maxEvidenceSignatureBytes, "evidence signature")
	if err != nil {
		return err
	}
	signature, err := evidencebundle.DecodeSignatureStrict(sigData)
	if err != nil {
		return err
	}
	manifest, key, err := evidencebundle.VerifySignedArchiveWithTrustStore(bundlePath, signature, store, now().UTC())
	if err != nil {
		return err
	}
	label := key.Label
	if label == "" {
		label = "-"
	}
	fmt.Fprintf(stdout, "verified trusted evidence bundle %s entries=%d signer-key-id=%s signer-label=%s bundle-sha256=%s\n", bundlePath, len(manifest.Entries), key.KeyID, label, signature.BundleSHA256)
	return nil
}

func readEvidenceTrustStore(path string) (evidencebundle.TrustStore, error) {
	data, err := readSmallRegularFile(path, maxEvidenceTrustStoreBytes, "evidence trust store")
	if err != nil {
		return evidencebundle.TrustStore{}, err
	}
	return evidencebundle.DecodeTrustStoreStrict(data)
}
