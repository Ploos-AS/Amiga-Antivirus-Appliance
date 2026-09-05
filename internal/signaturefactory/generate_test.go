package signaturefactory

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/adf"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/signatures"
)

func TestRecordScanResultCreatesBootblockCandidate(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "signatures"))
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 9, 5, 13, 0, 0, 0, time.UTC)
	sampleSHA := strings.Repeat("ab", 32)
	bootSHA := strings.Repeat("cd", 32)
	result := scanner.Result{
		Size:      901120,
		SHA256:    sampleSHA,
		Format:    "adf",
		Verdict:   "infected",
		Detection: "bootblock:Test Virus",
		ADF:       &adf.Analysis{BootblockSHA256: bootSHA},
		BootblockMatch: &signatures.Match{
			Status: signatures.StatusKnownMalicious,
			Name:   "Test Virus",
			Family: "TestVirus",
			Source: "synthetic provenance",
		},
	}

	candidates, err := RecordScanResult(store, result, created)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("got %d candidates, want 1", len(candidates))
	}
	candidate := candidates[0]
	if candidate.Kind != KindBootblockSHA256 || candidate.SampleSHA256 != sampleSHA || candidate.BootblockSHA256 != bootSHA {
		t.Fatalf("unexpected candidate: %+v", candidate)
	}
	if candidate.SourceEngine != "aaa-native" || candidate.Confidence != ConfidenceConfirmed {
		t.Fatalf("unexpected provenance: %+v", candidate)
	}
	stored, err := store.ReadCandidate(candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ID != candidate.ID {
		t.Fatalf("stored id %q != %q", stored.ID, candidate.ID)
	}
}

func TestRecordScanResultCreatesDirectFileCandidate(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "signatures"))
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 9, 5, 13, 0, 0, 0, time.UTC)
	result := scanner.Result{
		Size:      4096,
		SHA256:    strings.Repeat("ef", 32),
		Format:    "amiga-hunk-executable",
		Verdict:   "infected",
		Detection: "Synthetic File Virus",
	}
	candidates, err := RecordScanResult(store, result, created)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].Kind != KindFileSHA256 {
		t.Fatalf("unexpected candidates: %+v", candidates)
	}
}

func TestRecordScanResultUsesInfectedArchiveMemberNotContainer(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "signatures"))
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 9, 5, 13, 0, 0, 0, time.UTC)
	memberSHA := strings.Repeat("11", 32)
	bootSHA := strings.Repeat("22", 32)
	result := scanner.Result{
		Size:      10000,
		SHA256:    strings.Repeat("33", 32),
		Format:    "zip",
		Verdict:   "infected",
		Detection: "archive-member:disk.adf:bootblock:Test Virus",
		MemberResults: []scanner.MemberResult{
			{
				Name:      "disk.adf",
				Size:      901120,
				SHA256:    memberSHA,
				Format:    "adf",
				Verdict:   "infected",
				Detection: "bootblock:Test Virus",
				ADF:       &adf.Analysis{BootblockSHA256: bootSHA},
				BootblockMatch: &signatures.Match{
					Status: signatures.StatusKnownMalicious,
					Name:   "Test Virus",
					Family: "TestVirus",
					Source: "synthetic provenance",
				},
			},
		},
	}
	candidates, err := RecordScanResult(store, result, created)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("got %d candidates, want member only", len(candidates))
	}
	if candidates[0].SampleSHA256 != memberSHA || candidates[0].BootblockSHA256 != bootSHA {
		t.Fatalf("candidate did not preserve member identity: %+v", candidates[0])
	}
}

func TestRecordScanResultIgnoresNonInfected(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "signatures"))
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := RecordScanResult(store, scanner.Result{Verdict: "unknown"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Fatalf("unexpected candidates: %+v", candidates)
	}
}
