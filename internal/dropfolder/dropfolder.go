// Package dropfolder implements safe ingestion from an externally writable drop directory.
package dropfolder

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Submitter is the daemon queue boundary used after a file has been snapshotted.
type Submitter interface {
	Submit(path string) (Job, error)
}

// Job is the minimal job identity returned by a Submitter.
type Job struct {
	ID string
}

// Candidate is a regular drop-folder file observed at one point in time.
type Candidate struct {
	Path    string
	Name    string
	Size    int64
	ModTime time.Time
}

// Snapshot is the immutable, content-addressed copy submitted to AAA.
type Snapshot struct {
	Path      string
	SHA256    string
	Size      int64
	Duplicate bool
}

// Observe returns a candidate only for a visible regular file directly inside root.
func Observe(root, name string) (Candidate, bool, error) {
	if err := safeName(name); err != nil {
		return Candidate{}, false, nil
	}
	if strings.HasPrefix(name, ".") {
		return Candidate{}, false, nil
	}
	path := filepath.Join(root, name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Candidate{}, false, nil
	}
	if err != nil {
		return Candidate{}, false, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return Candidate{}, false, nil
	}
	return Candidate{Path: path, Name: name, Size: info.Size(), ModTime: info.ModTime()}, true, nil
}

// Stable reports whether two observations describe an unchanged file.
func Stable(first, second Candidate) bool {
	return first.Path == second.Path && first.Size == second.Size && first.ModTime.Equal(second.ModTime)
}

// Stage copies candidate into incomingRoot, hashes while copying, fsyncs the snapshot,
// and publishes it under <sha256>-<basename>. The source file is never scanned live.
func Stage(candidate Candidate, incomingRoot string, maxBytes int64) (Snapshot, error) {
	if maxBytes < 1 {
		return Snapshot{}, errors.New("max bytes must be at least 1")
	}
	if candidate.Size < 1 || candidate.Size > maxBytes {
		return Snapshot{}, fmt.Errorf("drop file size %d outside allowed range", candidate.Size)
	}
	if err := safeName(candidate.Name); err != nil {
		return Snapshot{}, err
	}

	source, err := os.Open(candidate.Path)
	if err != nil {
		return Snapshot{}, err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return Snapshot{}, err
	}
	if !info.Mode().IsRegular() || info.Size() != candidate.Size || !info.ModTime().Equal(candidate.ModTime) {
		return Snapshot{}, errors.New("drop file changed before staging")
	}

	if err := os.MkdirAll(incomingRoot, 0o750); err != nil {
		return Snapshot{}, err
	}
	tmp, err := os.CreateTemp(incomingRoot, ".drop-*")
	if err != nil {
		return Snapshot{}, err
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		_ = tmp.Close()
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(source, maxBytes+1))
	if err != nil {
		return Snapshot{}, err
	}
	if n != candidate.Size || n > maxBytes {
		return Snapshot{}, errors.New("drop file changed while staging")
	}
	if err := tmp.Sync(); err != nil {
		return Snapshot{}, err
	}
	if err := tmp.Close(); err != nil {
		return Snapshot{}, err
	}

	digest := hex.EncodeToString(h.Sum(nil))
	target := filepath.Join(incomingRoot, digest+"-"+candidate.Name)
	duplicate := false
	if err := os.Link(tmpPath, target); err != nil {
		if errors.Is(err, os.ErrExist) {
			duplicate = true
		} else {
			return Snapshot{}, err
		}
	}
	if err := os.Remove(tmpPath); err != nil {
		return Snapshot{}, err
	}
	removeTemp = false
	return Snapshot{Path: target, SHA256: digest, Size: n, Duplicate: duplicate}, nil
}

func safeName(name string) error {
	if name == "" || len(name) > 255 || name == "." || name == ".." || strings.ContainsAny(name, `/\\`) || filepath.Base(name) != name {
		return errors.New("unsafe drop filename")
	}
	return nil
}
