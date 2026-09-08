package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidencereplica"
)

const maxReplicaReceiptBytes = 16 << 10

func runEvidenceReplicate(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("evidence replicate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	destination := fs.String("destination", "", "replica root directory")
	kind := fs.String("kind", "", "replica object kind")
	receiptPath := fs.String("receipt", "", "new receipt path (default: SOURCE.replica.json)")
	note := fs.String("note", "", "operator note")
	if err := fs.Parse(args); err != nil { return err }
	if fs.NArg() != 1 || *destination == "" || *kind == "" { return errors.New("requires --destination <dir> --kind <kind> <source>") }
	source := fs.Arg(0)
	sha, size, err := hashRegularFile(source)
	if err != nil { return err }
	receipt, err := evidencereplica.BuildReceipt(evidencereplica.ObjectKind(*kind), sha, size, now().UTC(), *note)
	if err != nil { return err }
	if err := replicateObject(source, *destination, receipt); err != nil { return err }
	data, err := receipt.MarshalDeterministic()
	if err != nil { return err }
	out := *receiptPath
	if out == "" { out = source + ".replica.json" }
	if err := writeNewFile(out, data, 0o640); err != nil { return err }
	fmt.Fprintf(stdout, "replicated evidence object kind=%s bytes=%d sha256=%s receipt=%s\n", receipt.ObjectKind, receipt.Size, receipt.SHA256, out)
	return nil
}

func runEvidenceReplica(args []string, stdout, stderr io.Writer) error {
	if len(args) < 1 || args[0] != "verify" { return errors.New("evidence replica requires subcommand: verify") }
	fs := flag.NewFlagSet("evidence replica verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "", "replica root directory")
	if err := fs.Parse(args[1:]); err != nil { return err }
	if fs.NArg() != 1 || *root == "" { return errors.New("requires --root <dir> <receipt.json>") }
	data, err := readSmallRegularFile(fs.Arg(0), maxReplicaReceiptBytes, "replica receipt")
	if err != nil { return err }
	receipt, err := evidencereplica.DecodeReceiptStrict(data)
	if err != nil { return err }
	if err := verifyReplicaRoot(*root); err != nil { return err }
	objectPath := filepath.Join(*root, filepath.FromSlash(receipt.ReplicaName))
	sha, size, err := hashRegularFile(objectPath)
	if err != nil { return err }
	if sha != receipt.SHA256 || size != receipt.Size { return errors.New("replica object does not match receipt") }
	fmt.Fprintf(stdout, "verified replica object kind=%s bytes=%d sha256=%s\n", receipt.ObjectKind, size, sha)
	return nil
}

func replicateObject(source, root string, receipt evidencereplica.Receipt) error {
	if err := ensureReplicaDirectories(root, receipt.SHA256); err != nil { return err }
	destination := filepath.Join(root, filepath.FromSlash(receipt.ReplicaName))
	if _, err := os.Lstat(destination); err == nil {
		sha, size, err := hashRegularFile(destination)
		if err != nil { return err }
		if sha == receipt.SHA256 && size == receipt.Size { return nil }
		return errors.New("replica destination object conflicts with expected content")
	} else if !errors.Is(err, os.ErrNotExist) { return err }

	src, err := os.Open(source)
	if err != nil { return err }
	defer src.Close()
	opened, err := src.Stat()
	if err != nil { return err }
	current, err := os.Lstat(source)
	if err != nil { return err }
	if !opened.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(opened, current) { return errors.New("source must remain the same regular file while opened") }

	tmp, err := os.CreateTemp(filepath.Dir(destination), ".aaa-replica-*")
	if err != nil { return err }
	tmpName := tmp.Name()
	published := false
	defer func() { _ = tmp.Close(); if !published { _ = os.Remove(tmpName) } }()
	if err := tmp.Chmod(0o640); err != nil { return err }
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), src)
	if err != nil { return err }
	finished, err := src.Stat()
	if err != nil { return err }
	if n != opened.Size() || finished.Size() != opened.Size() || !finished.ModTime().Equal(opened.ModTime()) { return errors.New("source changed while replicating") }
	if n != receipt.Size || hex.EncodeToString(h.Sum(nil)) != receipt.SHA256 { return errors.New("replicated bytes do not match receipt") }
	if err := tmp.Sync(); err != nil { return err }
	if err := tmp.Close(); err != nil { return err }
	if err := os.Link(tmpName, destination); err != nil {
		if errors.Is(err, os.ErrExist) {
			sha, size, checkErr := hashRegularFile(destination)
			if checkErr != nil { return checkErr }
			if sha != receipt.SHA256 || size != receipt.Size { return errors.New("replica destination object conflicts with expected content") }
		} else { return err }
	} else { published = true }
	_ = os.Remove(tmpName)
	published = true
	sha, size, err := hashRegularFile(destination)
	if err != nil { return err }
	if sha != receipt.SHA256 || size != receipt.Size { return errors.New("published replica object failed verification") }
	return syncDirectory(filepath.Dir(destination))
}

func verifyReplicaRoot(root string) error {
	info, err := os.Lstat(root)
	if err != nil { return err }
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return errors.New("replica root must be a real directory") }
	return nil
}

func ensureReplicaDirectories(root, sha string) error {
	if err := verifyReplicaRoot(root); err != nil { return err }
	parts := []string{"aaa-replica-v1", "objects", "sha256", sha[:2]}
	current := root
	for _, part := range parts {
		current = filepath.Join(current, part)
		if err := os.Mkdir(current, 0o750); err != nil && !errors.Is(err, os.ErrExist) { return err }
		info, err := os.Lstat(current)
		if err != nil { return err }
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return fmt.Errorf("replica namespace component must be a real directory: %s", current) }
	}
	return nil
}
