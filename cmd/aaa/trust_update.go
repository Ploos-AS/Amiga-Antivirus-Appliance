package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidencebundle"
)

const maxEvidenceTrustUpdateBytes = 4096

func trustUpdateCommand(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "trust-update requires a subcommand: sign, verify, install or status")
		os.Exit(2)
	}
	var err error
	switch args[0] {
	case "sign":
		err = runTrustUpdateSign(args[1:], os.Stdout, os.Stderr)
	case "verify":
		err = runTrustUpdateVerify(args[1:], os.Stdout, os.Stderr)
	case "install":
		err = runTrustUpdateInstall(args[1:], os.Stdout, os.Stderr)
	case "status":
		err = runTrustUpdateStatus(args[1:], os.Stdout, os.Stderr)
	default:
		fmt.Fprintf(os.Stderr, "unknown trust-update subcommand: %s\n", args[0])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "trust-update %s failed: %v\n", args[0], err)
		os.Exit(1)
	}
}

func runTrustUpdateSign(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("trust-update sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rootPrivatePath := fs.String("root-private-key", "", "pinned-root Ed25519 private key file")
	sequence := fs.Uint64("sequence", 0, "monotonic trust-update sequence")
	output := fs.String("output", "", "new detached trust-update document")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *rootPrivatePath == "" || *sequence == 0 || *output == "" {
		return errors.New("requires --root-private-key <file> --sequence <n> --output <update.json> <trust-store.json>")
	}
	storeData, err := readSmallRegularFile(fs.Arg(0), maxEvidenceTrustStoreBytes, "evidence trust store")
	if err != nil {
		return err
	}
	keyData, err := readSmallRegularFile(*rootPrivatePath, maxEvidenceKeyFileBytes, "root private key")
	if err != nil {
		return err
	}
	privateKey, err := evidencebundle.ParsePrivateKeyHexFile(keyData)
	if err != nil {
		return err
	}
	update, err := evidencebundle.SignTrustStore(storeData, *sequence, privateKey)
	if err != nil {
		return err
	}
	data, err := update.MarshalDeterministic()
	if err != nil {
		return err
	}
	if err := writeNewFile(*output, data, 0o640); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "signed trust update sequence=%d root-key-id=%s trust-store-sha256=%s output=%s\n", update.Sequence, update.RootKeyID, update.TrustStoreSHA256, *output)
	return nil
}

func runTrustUpdateVerify(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("trust-update verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rootPublicPath := fs.String("root-public-key", "", "independently pinned root Ed25519 public key file")
	currentSequenceText := fs.String("current-sequence", "0", "last accepted trust-update sequence")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 || *rootPublicPath == "" {
		return errors.New("requires --root-public-key <file> [--current-sequence <n>] <trust-store.json> <update.json>")
	}
	currentSequence, err := strconv.ParseUint(*currentSequenceText, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid --current-sequence: %w", err)
	}
	storeData, err := readSmallRegularFile(fs.Arg(0), maxEvidenceTrustStoreBytes, "evidence trust store")
	if err != nil {
		return err
	}
	updateData, err := readSmallRegularFile(fs.Arg(1), maxEvidenceTrustUpdateBytes, "trust update")
	if err != nil {
		return err
	}
	update, err := evidencebundle.DecodeTrustUpdateStrict(updateData)
	if err != nil {
		return err
	}
	keyData, err := readSmallRegularFile(*rootPublicPath, maxEvidenceKeyFileBytes, "pinned root public key")
	if err != nil {
		return err
	}
	rootPublic, rootID, err := evidencebundle.ParsePublicKeyHexFile(keyData)
	if err != nil {
		return err
	}
	store, err := evidencebundle.VerifyTrustStoreUpdate(storeData, update, rootPublic, currentSequence)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "verified trust update sequence=%d previous=%d keys=%d root-key-id=%s trust-store-sha256=%s\n", update.Sequence, currentSequence, len(store.Keys), rootID, update.TrustStoreSHA256)
	return nil
}
