package signaturefactory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

func DecodeCorpusValidationResultStrict(data []byte) (CorpusValidationResult, error) {
	var result CorpusValidationResult
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return CorpusValidationResult{}, fmt.Errorf("decode corpus validation result: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return CorpusValidationResult{}, errors.New("decode corpus validation result: trailing data")
		}
		return CorpusValidationResult{}, fmt.Errorf("decode corpus validation result trailing data: %w", err)
	}
	if err := result.Validate(); err != nil {
		return CorpusValidationResult{}, fmt.Errorf("validate corpus validation result: %w", err)
	}
	return result, nil
}

func (s *Store) PromotePattern(id string, result CorpusValidationResult) (Candidate, error) {
	if s == nil {
		return Candidate{}, errors.New("nil signature store")
	}
	candidate, err := s.ReadCandidate(id)
	if err != nil {
		return Candidate{}, err
	}
	if candidate.Kind != KindPattern || candidate.Pattern == nil {
		return Candidate{}, errors.New("pattern promotion gate requires a pattern candidate")
	}
	if err := result.Validate(); err != nil {
		return Candidate{}, fmt.Errorf("validate pattern qualification: %w", err)
	}
	if result.CandidateID != candidate.ID {
		return Candidate{}, errors.New("pattern qualification candidate id mismatch")
	}
	patternSHA256, err := candidate.Pattern.IdentitySHA256()
	if err != nil {
		return Candidate{}, fmt.Errorf("pattern identity: %w", err)
	}
	if result.PatternSHA256 != patternSHA256 {
		return Candidate{}, errors.New("pattern qualification identity mismatch")
	}
	if !result.PassingPatternGate() {
		return Candidate{}, errors.New("pattern qualification does not pass clean/malware corpus gates")
	}
	return s.transition(id, StatusPromoted, "promoted")
}
