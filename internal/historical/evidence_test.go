package historical

import (
	"strings"
	"testing"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/engineevidence"
)

func TestEngineEvidencePreservesHistoricalAttribution(t *testing.T) {
	started := time.Unix(100, 0).UTC()
	finished := time.Unix(101, 0).UTC()
	r := Result{
		EngineID:            "virusz-iii",
		EngineName:          "VirusZ III",
		EngineVersion:       "1.04b",
		OSProfile:           OS31,
		ScannerBinarySHA256: strings.Repeat("a", 64),
		SignatureDatabaseID: "xvs-33.49",
		Verdict:             VerdictInfected,
		DetectionName:       "Synthetic.Test",
		RawExit:             "completed",
		RawLog:              []byte("FOUND Synthetic.Test"),
		InputSHA256:         strings.Repeat("b", 64),
		StartedAt:           started,
		FinishedAt:          finished,
	}
	r.SealRawLog()

	evidence := EngineEvidence(r, engineevidence.Component{
		Kind:    "xvs-library",
		Name:    "xvs.library",
		Version: "33.49",
		SHA256:  strings.Repeat("c", 64),
	})
	if err := evidence.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if evidence.EngineID != r.EngineID || evidence.OSProfile != string(OS31) {
		t.Fatalf("identity lost: %#v", evidence)
	}
	if evidence.RawEvidenceSHA256 != r.RawLogSHA256 {
		t.Fatalf("raw log hash=%q want=%q", evidence.RawEvidenceSHA256, r.RawLogSHA256)
	}
	if len(evidence.Components) != 1 || evidence.Components[0].Version != "33.49" {
		t.Fatalf("support components lost: %#v", evidence.Components)
	}
}
