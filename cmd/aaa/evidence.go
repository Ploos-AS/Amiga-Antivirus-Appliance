package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidencebundle"
)

const maxEvidenceManifestBytes = 4 << 20

type evidenceEntrySpecs []string

func (v *evidenceEntrySpecs) String() string { return strings.Join(*v, ",") }
func (v *evidenceEntrySpecs) Set(value string) error {
	*v = append(*v, value)
	return nil
}

func evidenceCommand(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "evidence requires a subcommand: create, verify, pack or verify-bundle")
		os.Exit(2)
	}
	switch args[0] {
	case "create":
		if err := runEvidenceCreate(args[1:], os.Stdout, os.Stderr, time.Now); err != nil {
			fmt.Fprintf(os.Stderr, "evidence create failed: %v\n", err)
			os.Exit(1)
		}
	case "verify":
		if err := runEvidenceVerify(args[1:], os.Stdout, os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "evidence verify failed: %v\n", err)
			os.Exit(1)
		}
	case "pack":
		if err := runEvidencePack(args[1:], os.Stdout, os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "evidence pack failed: %v\n", err)
			os.Exit(1)
		}
	case "verify-bundle":
		if err := runEvidenceVerifyBundle(args[1:], os.Stdout, os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "evidence verify-bundle failed: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown evidence subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

func runEvidenceCreate(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("evidence create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	output := fs.String("output", "", "new evidence manifest path")
	note := fs.String("note", "", "operator note")
	var specs evidenceEntrySpecs
	fs.Var(&specs, "entry", "evidence entry KIND:PORTABLE-NAME:SOURCE-PATH (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *output == "" || len(specs) == 0 {
		return errors.New("requires --output and at least one --entry KIND:PORTABLE-NAME:SOURCE-PATH")
	}
	if _, err := os.Lstat(*output); err == nil {
		return fmt.Errorf("output already exists: %s", *output)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	entries := make([]evidencebundle.Entry, 0, len(specs))
	for _, spec := range specs {
		entry, err := evidenceEntryFromSpec(spec)
		if err != nil {
			return err
		}
		entries = append(entries, entry)
	}

	manifest, err := evidencebundle.Build(version, now().UTC(), *note, entries, nil)
	if err != nil {
		return err
	}
	data, err := manifest.MarshalDeterministic()
	if err != nil {
		return err
	}
	if err := writeNewFile(*output, data, 0o640); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	fmt.Fprintf(stdout, "created evidence manifest %s entries=%d manifest-sha256=%s\n", *output, len(manifest.Entries), hex.EncodeToString(sum[:]))
	return nil
}

func runEvidenceVerify(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("evidence verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "", "root directory containing manifest entries (default: manifest directory)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("requires exactly one manifest path")
	}
	manifestPath := fs.Arg(0)
	manifest, err := readEvidenceManifest(manifestPath)
	if err != nil {
		return err
	}
	verifyRoot := *root
	if verifyRoot == "" {
		verifyRoot = filepath.Dir(manifestPath)
	}
	if err := manifest.VerifyFiles(verifyRoot); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "verified evidence manifest %s entries=%d\n", manifestPath, len(manifest.Entries))
	return nil
}

func runEvidencePack(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("evidence pack", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifestPath := fs.String("manifest", "", "evidence manifest to package")
	root := fs.String("root", "", "root directory containing manifest entries (default: manifest directory)")
	output := fs.String("output", "", "new portable evidence ZIP path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *manifestPath == "" || *output == "" {
		return errors.New("requires --manifest <manifest.json> --output <bundle.zip>")
	}
	manifest, err := readEvidenceManifest(*manifestPath)
	if err != nil {
		return err
	}
	bundleRoot := *root
	if bundleRoot == "" {
		bundleRoot = filepath.Dir(*manifestPath)
	}
	if err := evidencebundle.CreateArchive(manifest, bundleRoot, *output); err != nil {
		return err
	}
	sha, size, err := hashRegularFile(*output)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "packed evidence bundle %s entries=%d bytes=%d sha256=%s\n", *output, len(manifest.Entries), size, sha)
	return nil
}

func runEvidenceVerifyBundle(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("evidence verify-bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("requires exactly one portable evidence bundle path")
	}
	path := fs.Arg(0)
	manifest, err := evidencebundle.VerifyArchive(path)
	if err != nil {
		return err
	}
	sha, size, err := hashRegularFile(path)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "verified evidence bundle %s entries=%d bytes=%d sha256=%s\n", path, len(manifest.Entries), size, sha)
	return nil
}

func evidenceEntryFromSpec(spec string) (evidencebundle.Entry, error) {
	parts := strings.SplitN(spec, ":", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return evidencebundle.Entry{}, fmt.Errorf("invalid --entry %q; expected KIND:PORTABLE-NAME:SOURCE-PATH", spec)
	}
	kind := evidencebundle.Kind(parts[0])
	name := parts[1]
	sourcePath := parts[2]
	sha, size, err := hashRegularFile(sourcePath)
	if err != nil {
		return evidencebundle.Entry{}, fmt.Errorf("entry %q: %w", name, err)
	}
	entry := evidencebundle.Entry{Name: name, Kind: kind, SHA256: sha, Size: size}
	if err := entry.Validate(); err != nil {
		return evidencebundle.Entry{}, fmt.Errorf("entry %q: %w", name, err)
	}
	return entry, nil
}

func hashRegularFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	opened, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if !opened.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return "", 0, errors.New("source must remain the same regular file while opened")
	}

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	finished, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	if n != opened.Size() || finished.Size() != opened.Size() || !finished.ModTime().Equal(opened.ModTime()) {
		return "", 0, errors.New("source changed while hashing")
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func readEvidenceManifest(path string) (evidencebundle.Manifest, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return evidencebundle.Manifest{}, err
	}
	if !info.Mode().IsRegular() {
		return evidencebundle.Manifest{}, errors.New("manifest must be a regular file")
	}
	if info.Size() > maxEvidenceManifestBytes {
		return evidencebundle.Manifest{}, errors.New("manifest exceeds 4 MiB limit")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return evidencebundle.Manifest{}, err
	}
	var manifest evidencebundle.Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return evidencebundle.Manifest{}, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return evidencebundle.Manifest{}, errors.New("manifest contains trailing JSON data")
		}
		return evidencebundle.Manifest{}, err
	}
	if err := manifest.Validate(); err != nil {
		return evidencebundle.Manifest{}, err
	}
	return manifest, nil
}

func writeNewFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = f.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}
