package signaturefactory

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
)

// RecordClamAVResult records a ClamAV detection as a separate signature
// candidate. It deliberately does not mutate the native AAA scan result:
// engine agreement is represented by evidence/provenance, not by overwriting
// the native verdict or detection name.
func RecordClamAVResult(store *Store, scan scanner.Result, clam ClamAVScanResult, createdAt time.Time) (Candidate, bool, error) {
	if store == nil {
		return Candidate{}, false, fmt.Errorf("signature store is required")
	}
	if clam.Verdict != "infected" {
		return Candidate{}, false, nil
	}
	if clam.Evidence == nil {
		return Candidate{}, false, fmt.Errorf("infected ClamAV result has no normalized evidence")
	}
	if err := clam.Evidence.Validate(); err != nil {
		return Candidate{}, false, fmt.Errorf("invalid ClamAV evidence: %w", err)
	}
	if strings.TrimSpace(scan.SHA256) == "" {
		return Candidate{}, false, fmt.Errorf("scan SHA-256 is required")
	}

	candidate, err := NewExactCandidate(ExactCandidateInput{
		Family:             normalizedFamily("", clam.DetectionName),
		Kind:               KindFileSHA256,
		MalwareName:        clam.DetectionName,
		SampleSHA256:       scan.SHA256,
		SampleSize:         scan.Size,
		Format:             scan.Format,
		SourceEngine:       "clamav",
		SourceVersion:      clam.EngineVersion,
		SignatureDBVersion: clam.SignatureDBVersion,
		DetectionName:      clam.DetectionName,
		Confidence:         ConfidenceSingleEngine,
		Evidence:           []Evidence{*clam.Evidence},
		CreatedAt:          createdAt.UTC(),
	})
	if err != nil {
		return Candidate{}, false, fmt.Errorf("build ClamAV candidate: %w", err)
	}

	if existing, err := store.ReadCandidate(candidate.ID); err == nil {
		equal, compareErr := candidatesEqual(existing, candidate)
		if compareErr != nil {
			return Candidate{}, false, compareErr
		}
		if equal {
			return existing, false, nil
		}
		return Candidate{}, false, ErrCandidateConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return Candidate{}, false, err
	}

	if _, err := store.WriteCandidate(candidate); err != nil {
		if errors.Is(err, ErrCandidateConflict) {
			existing, readErr := store.ReadCandidate(candidate.ID)
			if readErr == nil {
				equal, compareErr := candidatesEqual(existing, candidate)
				if compareErr != nil {
					return Candidate{}, false, compareErr
				}
				if equal {
					return existing, false, nil
				}
			}
		}
		return Candidate{}, false, err
	}
	return candidate, true, nil
}

func candidatesEqual(left, right Candidate) (bool, error) {
	leftEncoded, err := marshalCandidate(left)
	if err != nil {
		return false, err
	}
	rightEncoded, err := marshalCandidate(right)
	if err != nil {
		return false, err
	}
	return bytes.Equal(leftEncoded, rightEncoded), nil
}
