package scanhistory

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/daemon"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
)

func TestRecordAndReplayLatestState(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	submitted := time.Date(2026, 9, 7, 6, 0, 0, 0, time.UTC)
	started := submitted.Add(time.Second)
	finished := submitted.Add(2 * time.Second)
	pending := daemon.Job{ID: "job-1", Path: "sample.adf", State: daemon.StatePending, SubmittedAt: submitted}
	running := pending
	running.State = daemon.StateRunning
	running.StartedAt = &started
	completed := running
	completed.State = daemon.StateSucceeded
	completed.FinishedAt = &finished
	completed.Result = &scanner.Result{Name: "sample.adf", SHA256: "abc", Verdict: "unknown"}

	for _, job := range []daemon.Job{pending, running, completed} {
		if err := store.Record(job); err != nil {
			t.Fatal(err)
		}
	}

	jobs, err := store.LoadLatest()
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("got %d jobs, want 1", len(jobs))
	}
	if jobs[0].State != daemon.StateSucceeded || jobs[0].Result == nil {
		t.Fatalf("unexpected replayed job: %#v", jobs[0])
	}
	if jobs[0].FinishedAt == nil || !jobs[0].FinishedAt.Equal(finished) {
		t.Fatalf("unexpected finish time: %#v", jobs[0].FinishedAt)
	}
}

func TestReplayOrdersNewestFirst(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	old := daemon.Job{ID: "old", Path: "old.adf", State: daemon.StateSucceeded, SubmittedAt: time.Unix(1, 0).UTC()}
	newer := daemon.Job{ID: "new", Path: "new.adf", State: daemon.StateSucceeded, SubmittedAt: time.Unix(2, 0).UTC()}
	if err := store.Record(old); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(newer); err != nil {
		t.Fatal(err)
	}
	jobs, err := store.LoadLatest()
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 || jobs[0].ID != "new" || jobs[1].ID != "old" {
		t.Fatalf("unexpected replay order: %#v", jobs)
	}
}

func TestReplayRejectsCorruptRecord(t *testing.T) {
	root := t.TempDir()
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, journalName), []byte("{not-json}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadLatest(); err == nil {
		t.Fatal("corrupt journal was accepted")
	}
}

func TestNewRequiresStateRoot(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatal("empty state root accepted")
	}
}
