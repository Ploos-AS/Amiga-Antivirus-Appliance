package signaturefactory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type CorpusSamplePath func(entry CorpusEntry) (string, error)

func MatchPatternCorpora(candidate Candidate, clean, malware CorpusManifest, resolve CorpusSamplePath, validatedAt time.Time) (CorpusValidationResult, error) {
	if err := candidate.Validate(); err != nil {
		return CorpusValidationResult{}, fmt.Errorf("validate candidate: %w", err)
	}
	if candidate.Kind != KindPattern || candidate.Pattern == nil {
		return CorpusValidationResult{}, errors.New("corpus matcher requires a pattern candidate")
	}
	if err := clean.Validate(); err != nil {
		return CorpusValidationResult{}, fmt.Errorf("validate clean corpus: %w", err)
	}
	if clean.Class != CorpusClassClean {
		return CorpusValidationResult{}, fmt.Errorf("clean manifest has class %q", clean.Class)
	}
	if err := malware.Validate(); err != nil {
		return CorpusValidationResult{}, fmt.Errorf("validate malware corpus: %w", err)
	}
	if malware.Class != CorpusClassMalware {
		return CorpusValidationResult{}, fmt.Errorf("malware manifest has class %q", malware.Class)
	}
	if resolve == nil {
		return CorpusValidationResult{}, errors.New("corpus sample resolver is required")
	}
	if validatedAt.IsZero() {
		return CorpusValidationResult{}, errors.New("validated_at is required")
	}

	patternSHA256, err := candidate.Pattern.IdentitySHA256()
	if err != nil {
		return CorpusValidationResult{}, fmt.Errorf("pattern identity: %w", err)
	}
	cleanSHA256, err := clean.SHA256()
	if err != nil {
		return CorpusValidationResult{}, fmt.Errorf("clean manifest identity: %w", err)
	}
	malwareSHA256, err := malware.SHA256()
	if err != nil {
		return CorpusValidationResult{}, fmt.Errorf("malware manifest identity: %w", err)
	}

	cleanMatches, err := matchCorpus(*candidate.Pattern, clean, resolve)
	if err != nil {
		return CorpusValidationResult{}, fmt.Errorf("match clean corpus: %w", err)
	}
	malwareMatches, err := matchCorpus(*candidate.Pattern, malware, resolve)
	if err != nil {
		return CorpusValidationResult{}, fmt.Errorf("match malware corpus: %w", err)
	}

	result := CorpusValidationResult{
		Schema:                CorpusSchemaVersion,
		CandidateID:           candidate.ID,
		PatternSHA256:         patternSHA256,
		CleanManifestSHA256:   cleanSHA256,
		MalwareManifestSHA256: malwareSHA256,
		CleanSampleCount:      len(clean.Entries),
		CleanMatchCount:       len(cleanMatches),
		MalwareSampleCount:    len(malware.Entries),
		MalwareMatchCount:     len(malwareMatches),
		CleanMatches:          cleanMatches,
		MalwareMatches:        malwareMatches,
		ValidatedAt:           validatedAt.UTC(),
	}
	if err := result.Validate(); err != nil {
		return CorpusValidationResult{}, fmt.Errorf("validate corpus result: %w", err)
	}
	return result, nil
}

func matchCorpus(pattern FixedPattern, manifest CorpusManifest, resolve CorpusSamplePath) ([]string, error) {
	needle, err := hex.DecodeString(pattern.BytesHex)
	if err != nil {
		return nil, fmt.Errorf("decode pattern: %w", err)
	}
	matches := make([]string, 0)
	for _, entry := range manifest.Entries {
		path, err := resolve(entry)
		if err != nil {
			return nil, fmt.Errorf("resolve sample %s: %w", entry.SHA256, err)
		}
		if path == "" {
			return nil, fmt.Errorf("resolve sample %s: empty path", entry.SHA256)
		}
		data, err := readVerifiedCorpusSample(path, entry)
		if err != nil {
			return nil, fmt.Errorf("sample %s: %w", entry.SHA256, err)
		}
		if fixedPatternMatches(needle, pattern.Offset, data) {
			matches = append(matches, entry.SHA256)
		}
	}
	sort.Strings(matches)
	return matches, nil
}

func readVerifiedCorpusSample(path string, entry CorpusEntry) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("corpus sample is not a regular file")
	}
	if info.Size() != entry.Size {
		return nil, fmt.Errorf("size mismatch: manifest=%d actual=%d", entry.Size, info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if actual != entry.SHA256 {
		return nil, fmt.Errorf("sha256 mismatch: manifest=%s actual=%s", entry.SHA256, actual)
	}
	return data, nil
}

func fixedPatternMatches(needle []byte, offset *int64, data []byte) bool {
	if offset == nil {
		return bytes.Contains(data, needle)
	}
	start := *offset
	if start < 0 || start > int64(len(data)) || int64(len(needle)) > int64(len(data))-start {
		return false
	}
	return bytes.Equal(data[int(start):int(start)+len(needle)], needle)
}

func SHA256CorpusResolver(root string) CorpusSamplePath {
	return func(entry CorpusEntry) (string, error) {
		if !validSHA256(entry.SHA256) {
			return "", errors.New("invalid corpus sample sha256")
		}
		return filepath.Join(root, entry.SHA256), nil
	}
}
