package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidencereplica"
)

const maxReplicaSessionBytes = 4 << 20

type replicaObjectSpecs []string

func (v *replicaObjectSpecs) String() string         { return strings.Join(*v, ",") }
func (v *replicaObjectSpecs) Set(value string) error { *v = append(*v, value); return nil }

type replicaSessionSource struct {
	kind    evidencereplica.ObjectKind
	path    string
	receipt evidencereplica.Receipt
}

func runEvidenceReplicateSession(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("evidence replicate-session", flag.ContinueOnError)
	fs.SetOutput(stderr)
	destination := fs.String("destination", "", "replica root directory")
	sessionPath := fs.String("session", "", "new operator-held session path")
	note := fs.String("note", "", "operator note")
	var specs replicaObjectSpecs
	fs.Var(&specs, "object", "replica object KIND:SOURCE-PATH (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *destination == "" || *sessionPath == "" || len(specs) == 0 {
		return errors.New("requires --destination <dir> --session <session.json> and at least one --object KIND:SOURCE-PATH")
	}

	sources := make([]replicaSessionSource, 0, len(specs))
	intents := make([]evidencereplica.SessionObject, 0, len(specs))
	for _, spec := range specs {
		kind, source, err := parseReplicaObjectSpec(spec)
		if err != nil {
			return err
		}
		sha, size, err := hashRegularFile(source)
		if err != nil {
			return fmt.Errorf("cannot prepare replica session object: %w", err)
		}
		receipt, err := evidencereplica.BuildReceipt(kind, sha, size, now().UTC(), "")
		if err != nil {
			return err
		}
		sources = append(sources, replicaSessionSource{kind: kind, path: source, receipt: receipt})
		intents = append(intents, evidencereplica.SessionObject{ObjectKind: kind, SHA256: sha, Size: size, ReplicaName: receipt.ReplicaName, Result: evidencereplica.ResultReplicated})
	}
	if _, err := evidencereplica.SessionID(intents); err != nil {
		return err
	}

	results := make([]evidencereplica.SessionObject, 0, len(sources))
	failed := false
	for _, source := range sources {
		result := evidencereplica.SessionObject{ObjectKind: source.kind, SHA256: source.receipt.SHA256, Size: source.receipt.Size, ReplicaName: source.receipt.ReplicaName}
		already, err := replicaObjectAlreadyPresent(*destination, source.receipt)
		if err == nil && already {
			result.Result = evidencereplica.ResultAlreadyPresent
		} else if err := replicateObject(source.path, *destination, source.receipt); err != nil {
			result.Result = evidencereplica.ResultFailed
			result.Error = replicaSessionErrorClass(err)
			failed = true
		} else {
			result.Result = evidencereplica.ResultReplicated
		}
		results = append(results, result)
	}

	session, err := evidencereplica.BuildSession(results, now().UTC(), *note)
	if err != nil {
		return err
	}
	data, err := session.MarshalDeterministic()
	if err != nil {
		return err
	}
	if err := writeNewFile(*sessionPath, data, 0o640); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "replica session %s objects=%d session-id=%s\n", *sessionPath, len(session.Objects), session.SessionID)
	if failed {
		return errors.New("replica session completed with failed objects")
	}
	return nil
}

func runEvidenceReplicaVerifySession(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("evidence replica verify-session", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "", "replica root directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *root == "" {
		return errors.New("requires --root <dir> <session.json>")
	}
	data, err := readSmallRegularFile(fs.Arg(0), maxReplicaSessionBytes, "replica session")
	if err != nil {
		return err
	}
	session, err := evidencereplica.DecodeSessionStrict(data)
	if err != nil {
		return err
	}
	incomplete := false
	for _, object := range session.Objects {
		if object.Result == evidencereplica.ResultFailed {
			incomplete = true
			continue
		}
		if err := verifyReplicaNamespace(*root, object.SHA256); err != nil {
			return err
		}
		objectPath := filepath.Join(*root, filepath.FromSlash(object.ReplicaName))
		sha, size, err := hashRegularFile(objectPath)
		if err != nil {
			return err
		}
		if sha != object.SHA256 || size != object.Size {
			return errors.New("replica session object does not match session")
		}
	}
	if incomplete {
		return errors.New("replica session is valid but incomplete")
	}
	fmt.Fprintf(stdout, "verified replica session objects=%d session-id=%s\n", len(session.Objects), session.SessionID)
	return nil
}

func parseReplicaObjectSpec(spec string) (evidencereplica.ObjectKind, string, error) {
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid --object %q; expected KIND:SOURCE-PATH", spec)
	}
	return evidencereplica.ObjectKind(parts[0]), parts[1], nil
}

func replicaObjectAlreadyPresent(root string, receipt evidencereplica.Receipt) (bool, error) {
	if err := verifyReplicaRoot(root); err != nil {
		return false, err
	}
	objectPath := filepath.Join(root, filepath.FromSlash(receipt.ReplicaName))
	info, err := os.Lstat(objectPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("replica destination object is not a regular file")
	}
	if err := verifyReplicaNamespace(root, receipt.SHA256); err != nil {
		return false, err
	}
	sha, size, err := hashRegularFile(objectPath)
	if err != nil {
		return false, err
	}
	if sha != receipt.SHA256 || size != receipt.Size {
		return false, errors.New("replica destination object conflicts with expected content")
	}
	return true, nil
}

func replicaSessionErrorClass(err error) string {
	if err == nil {
		return ""
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "conflict"):
		return "destination-conflict"
	case strings.Contains(message, "symlink"), strings.Contains(message, "real directory"):
		return "unsafe-namespace"
	case strings.Contains(message, "source"):
		return "source-invalid"
	default:
		return "replication-failed"
	}
}
