package daemon

import (
	"testing"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
)

type recordingRecorder struct {
	jobs []Job
}

func (r *recordingRecorder) Record(job Job) error {
	r.jobs = append(r.jobs, job)
	return nil
}

func TestFullQueuePersistsTerminalRejection(t *testing.T) {
	recorder := new(recordingRecorder)
	m, err := NewWithRecorder(1, 1, func(string) (scanner.Result, error) {
		return scanner.Result{}, nil
	}, recorder)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Submit("one.adf"); err != nil {
		t.Fatal(err)
	}
	rejected, err := m.Submit("two.adf")
	if err == nil {
		t.Fatal("second submit succeeded with a full queue")
	}
	if rejected.State != StateCanceled || rejected.FinishedAt == nil {
		t.Fatalf("rejected job is not terminal: %#v", rejected)
	}
	if rejected.Error != "scan queue is full" {
		t.Fatalf("rejected error = %q", rejected.Error)
	}
	if len(recorder.jobs) != 3 {
		t.Fatalf("recorded %d snapshots, want 3", len(recorder.jobs))
	}
	last := recorder.jobs[len(recorder.jobs)-1]
	if last.ID != rejected.ID || last.State != StateCanceled {
		t.Fatalf("last persisted snapshot = %#v", last)
	}
}
