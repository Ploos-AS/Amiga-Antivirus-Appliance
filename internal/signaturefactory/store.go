package signaturefactory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var ErrCandidateConflict = errors.New("candidate already exists with different evidence")

type Store struct {
	Root string
}

func NewStore(root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("signature store root is required")
	}
	store := &Store{Root: filepath.Clean(root)}
	if err := store.Init(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) Init() error {
	if s == nil || s.Root == "" {
		return errors.New("invalid signature store")
	}
	for _, dir := range []string{
		"candidates",
		"promoted",
		filepath.Join("generated", "aaa"),
		filepath.Join("generated", "clamav"),
		"rejected",
		"state",
	} {
		if err := os.MkdirAll(filepath.Join(s.Root, dir), 0o750); err != nil {
			return fmt.Errorf("create signature store directory %q: %w", dir, err)
		}
	}
	return nil
}

func (s *Store) WriteCandidate(candidate Candidate) (string, error) {
	if s == nil {
		return "", errors.New("nil signature store")
	}
	if candidate.Status != StatusCandidate {
		return "", fmt.Errorf("candidate store requires status %q", StatusCandidate)
	}
	if err := candidate.Validate(); err != nil {
		return "", fmt.Errorf("validate candidate: %w", err)
	}
	if err := s.Init(); err != nil {
		return "", err
	}

	encoded, err := marshalCandidate(candidate)
	if err != nil {
		return "", err
	}
	path, err := s.candidatePath(candidate.ID)
	if err != nil {
		return "", err
	}

	if existing, err := os.ReadFile(path); err == nil {
		if bytes.Equal(existing, encoded) {
			return path, nil
		}
		return "", ErrCandidateConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read existing candidate: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".candidate-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create candidate temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return "", fmt.Errorf("set candidate permissions: %w", err)
	}
	if _, err := tmp.Write(encoded); err != nil {
		tmp.Close()
		return "", fmt.Errorf("write candidate temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", fmt.Errorf("sync candidate temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close candidate temp file: %w", err)
	}

	if err := os.Link(tmpPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, readErr := os.ReadFile(path)
			if readErr != nil {
				return "", fmt.Errorf("read concurrently created candidate: %w", readErr)
			}
			if bytes.Equal(existing, encoded) {
				return path, nil
			}
			return "", ErrCandidateConflict
		}
		return "", fmt.Errorf("commit candidate: %w", err)
	}
	return path, nil
}

func (s *Store) ReadCandidate(id string) (Candidate, error) {
	if s == nil {
		return Candidate{}, errors.New("nil signature store")
	}
	path, err := s.candidatePath(id)
	if err != nil {
		return Candidate{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Candidate{}, fmt.Errorf("read candidate: %w", err)
	}

	var candidate Candidate
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&candidate); err != nil {
		return Candidate{}, fmt.Errorf("decode candidate: %w", err)
	}
	if err := candidate.Validate(); err != nil {
		return Candidate{}, fmt.Errorf("validate stored candidate: %w", err)
	}
	if candidate.Status != StatusCandidate {
		return Candidate{}, fmt.Errorf("stored candidate has status %q", candidate.Status)
	}
	if candidate.ID != id {
		return Candidate{}, errors.New("stored candidate id does not match filename")
	}
	return candidate, nil
}

func (s *Store) candidatePath(id string) (string, error) {
	if !candidateIDPattern.MatchString(id) {
		return "", errors.New("invalid candidate id")
	}
	base := filepath.Join(s.Root, "candidates")
	path := filepath.Join(base, id+".json")
	if filepath.Dir(path) != base {
		return "", errors.New("candidate path escaped store")
	}
	return path, nil
}

func marshalCandidate(candidate Candidate) ([]byte, error) {
	encoded, err := json.MarshalIndent(candidate, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode candidate: %w", err)
	}
	encoded = append(encoded, '\n')
	return encoded, nil
}
