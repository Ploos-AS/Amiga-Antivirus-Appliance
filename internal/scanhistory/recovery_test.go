package scanhistory

import (
	"strings"
	"testing"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/daemon"
)

func TestRecoverInterruptedClosesActiveJobs(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	submitted := time.Date(2026, 9, 7, 7, 30, 0, 0, time.UTC)
	started := submitted.Add(time.Second)
	jobs := []daemon.Job{
		{ID: "pending", Path: "pending.adf", State: daemon.StatePending, SubmittedAt: submitted},
		{ID: "running", Path: "running.adf", State: daemon.StateRunning, SubmittedAt: submitted.Add(time.Second), StartedAt: &started},
		{ID: "done", Path: "done.adf", State: daemon.StateSucceeded, SubmittedAt: submitted.Add(2 * time.Second)},
	}
	for _, job := range jobs {
		if err := store.Record(job); err != nil {
			t.Fatal(err)
		}
	}

	recovered, err := store.RecoverInterrupted()
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 3 {
		t.Fatalf("got %d jobs, want 3", len(recovered))
	}

	latest, err := store.LoadLatest()
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]daemon.Job, len(latest))
	for _, job := range latest {
		byID[job.ID] = job
	}
	for _, id := range []string{"pending", "running"} {
		job := byID[id]
		if job.State != daemon.StateCanceled || job.FinishedAt == nil {
			t.Fatalf("%s not recovered to terminal state: %#v", id, job)
		}
		if !strings.Contains(job.Error, "restarted") {
			t.Fatalf("%s missing restart reason: %#v", id, job)
		}
	}
	if byID["done"].State != daemon.StateSucceeded {
		t.Fatalf("completed job changed: %#v", byID["done"])
	}
}
