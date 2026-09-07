package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/engineevidence"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/signaturefactory"
)

func TestClamAVEvidenceCompleted(t *testing.T) {
	evidence := clamAVEvidence(signaturefactory.ClamAVScanResult{
		Verdict:            "infected",
		DetectionName:      "AAA.Test",
		EngineVersion:      "1.4.2",
		SignatureDBVersion: "27777",
		RawResult:          "/controlled/file: AAA.Test FOUND",
	}, string(make([]byte, 64)), nil)
	// Replace the deliberately invalid placeholder with a real lowercase SHA.
	evidence.InputSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := evidence.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if evidence.Kind != engineevidence.KindClamAV || evidence.DatabaseVersion != "27777" || evidence.RawEvidenceSHA256 == "" {
		t.Fatalf("unexpected evidence: %#v", evidence)
	}
}

func TestScanForDaemonKeepsNativeSuccessWhenClamAVUnavailable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(path, []byte("AAA synthetic input"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AAA_CLAMSCAN", filepath.Join(dir, "missing-clamscan"))

	result, err := scanForDaemon(path)
	if err != nil {
		t.Fatalf("scanForDaemon: %v", err)
	}
	if len(result.EngineResults) != 2 {
		t.Fatalf("engine results=%d want=2", len(result.EngineResults))
	}
	if result.EngineResults[0].EngineID != "aaa-native" || result.EngineResults[0].Status != engineevidence.StatusCompleted {
		t.Fatalf("native evidence=%#v", result.EngineResults[0])
	}
	if result.EngineResults[1].EngineID != "clamav" || result.EngineResults[1].Status != engineevidence.StatusError {
		t.Fatalf("ClamAV evidence=%#v", result.EngineResults[1])
	}
	for _, evidence := range result.EngineResults {
		if err := evidence.Validate(); err != nil {
			t.Fatalf("invalid engine evidence %#v: %v", evidence, err)
		}
	}
}
