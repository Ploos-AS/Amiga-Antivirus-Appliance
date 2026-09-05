package signaturefactory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

func (s *Store) ListCandidates() ([]Candidate, error) {
	if s == nil {
		return nil, errors.New("nil signature store")
	}
	if err := s.Init(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(s.Root, "candidates"))
	if err != nil {
		return nil, fmt.Errorf("list candidates: %w", err)
	}
	candidates := make([]Candidate, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := entry.Name()[:len(entry.Name())-len(".json")]
		candidate, err := s.ReadCandidate(id)
		if err != nil {
			return nil, fmt.Errorf("read listed candidate %q: %w", id, err)
		}
		candidates = append(candidates, candidate)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
	return candidates, nil
}

func (s *Store) ValidateCandidates() error {
	_, err := s.ListCandidates()
	return err
}

func (s *Store) Promote(id string) (Candidate, error) {
	candidate, err := s.ReadCandidate(id)
	if err != nil {
		return Candidate{}, err
	}
	if candidate.Kind == KindPattern {
		return Candidate{}, errors.New("pattern candidates require a passing M7.3 corpus validation result")
	}
	return s.transition(id, StatusPromoted, "promoted")
}

func (s *Store) Reject(id string) (Candidate, error) {
	return s.transition(id, StatusRejected, "rejected")
}

func (s *Store) transition(id string, status Status, destination string) (Candidate, error) {
	if s == nil {
		return Candidate{}, errors.New("nil signature store")
	}
	if status != StatusPromoted && status != StatusRejected {
		return Candidate{}, fmt.Errorf("unsupported lifecycle status %q", status)
	}
	candidate, err := s.ReadCandidate(id)
	if err != nil {
		return Candidate{}, err
	}
	candidate.Status = status
	if err := candidate.Validate(); err != nil {
		return Candidate{}, fmt.Errorf("validate transitioned candidate: %w", err)
	}
	encoded, err := marshalCandidate(candidate)
	if err != nil {
		return Candidate{}, err
	}

	base := filepath.Join(s.Root, destination)
	path := filepath.Join(base, id+".json")
	if filepath.Dir(path) != base {
		return Candidate{}, errors.New("lifecycle destination escaped store")
	}
	if existing, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(existing, encoded) {
			return Candidate{}, ErrCandidateConflict
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Candidate{}, fmt.Errorf("read lifecycle destination: %w", err)
	} else if err := writeAtomicExclusive(base, path, encoded); err != nil {
		return Candidate{}, err
	}

	source, err := s.candidatePath(id)
	if err != nil {
		return Candidate{}, err
	}
	if err := os.Remove(source); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Candidate{}, fmt.Errorf("remove candidate after transition: %w", err)
	}
	return candidate, nil
}

func writeAtomicExclusive(dir, path string, encoded []byte) error {
	tmp, err := os.CreateTemp(dir, ".lifecycle-*.tmp")
	if err != nil {
		return fmt.Errorf("create lifecycle temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return fmt.Errorf("set lifecycle permissions: %w", err)
	}
	if _, err := tmp.Write(encoded); err != nil {
		tmp.Close()
		return fmt.Errorf("write lifecycle temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync lifecycle temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close lifecycle temp file: %w", err)
	}
	if err := os.Link(tmpPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, readErr := os.ReadFile(path)
			if readErr == nil && bytes.Equal(existing, encoded) {
				return nil
			}
			return ErrCandidateConflict
		}
		return fmt.Errorf("commit lifecycle record: %w", err)
	}
	return nil
}

func DecodeCandidateStrict(data []byte) (Candidate, error) {
	var candidate Candidate
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&candidate); err != nil {
		return Candidate{}, fmt.Errorf("decode candidate: %w", err)
	}
	if err := candidate.Validate(); err != nil {
		return Candidate{}, err
	}
	return candidate, nil
}
