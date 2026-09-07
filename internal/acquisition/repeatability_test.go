package acquisition

import (
	"strings"
	"testing"
	"time"
)

func validEvidence(hash string) Evidence {
	now := time.Now().UTC()
	return Evidence{
		Method:       "physical-floppy",
		Tool:         "greaseweazle",
		ToolVersion:  "gw 1.23",
		Format:       "adf",
		OutputName:   "disk.adf",
		OutputSHA256: hash,
		OutputSize:   901120,
		Command:      []string{"gw", "read"},
		StartedAt:    now,
		FinishedAt:   now,
	}
}

func TestCompareReadsInsufficient(t *testing.T) {
	r, err := CompareReads([]Evidence{validEvidence(strings.Repeat("a", 64))})
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != RepeatabilityInsufficient || r.ReadCount != 1 || r.UniqueHashes != 1 {
		t.Fatalf("repeatability=%+v", r)
	}
}

func TestCompareReadsReproducible(t *testing.T) {
	hash := strings.Repeat("a", 64)
	r, err := CompareReads([]Evidence{validEvidence(hash), validEvidence(hash), validEvidence(hash)})
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != RepeatabilityReproducible || r.ReadCount != 3 || r.UniqueHashes != 1 || r.Hashes[hash] != 3 {
		t.Fatalf("repeatability=%+v", r)
	}
}

func TestCompareReadsDivergent(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	r, err := CompareReads([]Evidence{validEvidence(a), validEvidence(b), validEvidence(a)})
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != RepeatabilityDivergent || r.UniqueHashes != 2 || r.Hashes[a] != 2 || r.Hashes[b] != 1 {
		t.Fatalf("repeatability=%+v", r)
	}
}

func TestCompareReadsRejectsInvalidEvidence(t *testing.T) {
	_, err := CompareReads([]Evidence{validEvidence("bad")})
	if err == nil {
		t.Fatal("expected validation error")
	}
}
