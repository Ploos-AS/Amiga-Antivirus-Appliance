package scanhistory

import (
	"strings"
	"testing"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/daemon"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/engineevidence"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
)

func TestEngineEvidenceSurvivesHistoryReplay(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0).UTC()
	job := daemon.Job{
		ID:          "engine-evidence-job",
		Path:        "/data/aaa/incoming/sample",
		State:       daemon.StateSucceeded,
		SubmittedAt: now,
		FinishedAt:  &now,
		Result: &scanner.Result{
			SHA256:  strings.Repeat("a", 64),
			Verdict: "unknown",
			EngineResults: []engineevidence.Result{{
				Kind:          engineevidence.KindNative,
				EngineID:      "aaa-native",
				EngineName:    "AAA native analyzer",
				EngineVersion: "0.6.0-dev",
				Status:        engineevidence.StatusCompleted,
				Verdict:       "unknown",
				InputSHA256:   strings.Repeat("a", 64),
			}},
		},
	}
	if err := store.Record(job); err != nil {
		t.Fatal(err)
	}
	jobs, err := store.LoadLatest()
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].Result == nil || len(jobs[0].Result.EngineResults) != 1 {
		t.Fatalf("replayed job lost engine evidence: %#v", jobs)
	}
	got := jobs[0].Result.EngineResults[0]
	if got.EngineID != "aaa-native" || got.EngineVersion != "0.6.0-dev" {
		t.Fatalf("replayed engine evidence=%#v", got)
	}
}
