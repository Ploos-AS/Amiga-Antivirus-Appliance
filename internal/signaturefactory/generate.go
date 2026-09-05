package signaturefactory

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/signatures"
)

const DefaultStoreRoot = "/data/aaa/signatures"

func StoreRootFromEnv() string {
	if root := strings.TrimSpace(os.Getenv("AAA_SIGNATURE_STORE_ROOT")); root != "" {
		return root
	}
	return DefaultStoreRoot
}

func RecordScanResult(store *Store, result scanner.Result, createdAt time.Time) ([]Candidate, error) {
	if store == nil {
		return nil, fmt.Errorf("nil signature store")
	}
	if result.Verdict != "infected" {
		return nil, nil
	}
	if createdAt.IsZero() {
		return nil, fmt.Errorf("created_at is required")
	}

	var candidates []Candidate
	if candidate, ok, err := candidateFromScanNode(result.SHA256, result.Size, result.Format, result.Verdict, result.Detection, result.ADF, result.BootblockMatch, createdAt); err != nil {
		return nil, err
	} else if ok {
		candidates = append(candidates, candidate)
	}
	for _, member := range result.MemberResults {
		generated, err := candidatesFromMember(member, createdAt)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, generated...)
	}

	written := make([]Candidate, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if _, ok := seen[candidate.ID]; ok {
			continue
		}
		if _, err := store.WriteCandidate(candidate); err != nil {
			return nil, fmt.Errorf("write signature candidate %s: %w", candidate.ID, err)
		}
		seen[candidate.ID] = struct{}{}
		written = append(written, candidate)
	}
	return written, nil
}

func candidatesFromMember(member scanner.MemberResult, createdAt time.Time) ([]Candidate, error) {
	if member.Verdict != "infected" {
		return nil, nil
	}
	var candidates []Candidate
	if candidate, ok, err := candidateFromScanNode(member.SHA256, member.Size, member.Format, member.Verdict, member.Detection, member.ADF, member.BootblockMatch, createdAt); err != nil {
		return nil, err
	} else if ok {
		candidates = append(candidates, candidate)
	}
	for _, child := range member.Children {
		generated, err := candidatesFromMember(child, createdAt)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, generated...)
	}
	return candidates, nil
}

func candidateFromScanNode(sampleSHA string, sampleSize int64, format, verdict, detection string, adfAnalysis interface{ GetBootblockSHA256() string }, match *signatures.Match, createdAt time.Time) (Candidate, bool, error) {
	_ = adfAnalysis
	if verdict != "infected" {
		return Candidate{}, false, nil
	}

	if match != nil && match.Status == signatures.StatusKnownMalicious {
		bootSHA := ""
		// scanner ADF analysis is concrete, but keep the extraction local to avoid
		// making signature generation depend on any disk-image bytes.
		switch value := any(adfAnalysis).(type) {
		case interface{ BootblockHash() string }:
			bootSHA = value.BootblockHash()
		}
		if bootSHA == "" {
			return Candidate{}, false, fmt.Errorf("infected bootblock match missing bootblock sha256")
		}
		family := normalizedFamily(match.Family, match.Name)
		candidate, err := NewExactCandidate(ExactCandidateInput{
			Family:          family,
			Kind:            KindBootblockSHA256,
			MalwareName:     match.Name,
			SampleSHA256:    sampleSHA,
			BootblockSHA256: bootSHA,
			SampleSize:      sampleSize,
			Format:          format,
			SourceEngine:    "aaa-native",
			DetectionName:   detectionOrName(detection, match.Name),
			Confidence:      ConfidenceConfirmed,
			Evidence: []Evidence{
				{Type: "bootblock-database", Detail: match.Source},
			},
			CreatedAt: createdAt,
		})
		return candidate, true, err
	}

	if strings.HasPrefix(detection, "archive-member:") {
		return Candidate{}, false, nil
	}
	family := normalizedFamily("", detection)
	candidate, err := NewExactCandidate(ExactCandidateInput{
		Family:        family,
		Kind:          KindFileSHA256,
		MalwareName:   detectionOrName(detection, "AAA detection"),
		SampleSHA256:  sampleSHA,
		SampleSize:    sampleSize,
		Format:        format,
		SourceEngine:  "aaa-native",
		DetectionName: detectionOrName(detection, "aaa-native-infected"),
		Confidence:    ConfidenceConfirmed,
		CreatedAt:     createdAt,
	})
	return candidate, true, err
}

func normalizedFamily(family, fallback string) string {
	family = sanitizeFamily(family)
	if validFamily(family) {
		return family
	}
	family = sanitizeFamily(fallback)
	if validFamily(family) {
		return family
	}
	return "Unknown"
}

func sanitizeFamily(value string) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else if b.Len() > 0 && b.String()[b.Len()-1] != '-' {
			b.WriteByte('-')
		}
		if b.Len() >= 64 {
			break
		}
	}
	return strings.Trim(b.String(), "._-")
}

func detectionOrName(detection, fallback string) string {
	if strings.TrimSpace(detection) != "" {
		return strings.TrimSpace(detection)
	}
	return strings.TrimSpace(fallback)
}
