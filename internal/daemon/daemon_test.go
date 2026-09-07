package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
)

func TestJobLifecycleSucceeded(t *testing.T) {
	m, err := New(1, 2, func(path string) (scanner.Result, error) {
		return scanner.Result{Name: path, Verdict: "unknown"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()

	job, err := m.Submit("sample.adf")
	if err != nil {
		t.Fatal(err)
	}

	final := waitForTerminal(t, m, job.ID)
	if final.State != StateSucceeded {
		t.Fatalf("state = %q, want %q", final.State, StateSucceeded)
	}
	if final.Result == nil || final.Result.Name != "sample.adf" {
		t.Fatalf("unexpected result: %#v", final.Result)
	}
	if final.StartedAt == nil || final.FinishedAt == nil {
		t.Fatalf("terminal job missing timestamps: %#v", final)
	}

	cancel()
	<-done
}

func TestJobLifecycleFailed(t *testing.T) {
	m, err := New(1, 1, func(string) (scanner.Result, error) {
		return scanner.Result{}, errors.New("scanner exploded")
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()

	job, err := m.Submit("bad.adf")
	if err != nil {
		t.Fatal(err)
	}
	final := waitForTerminal(t, m, job.ID)
	if final.State != StateFailed || final.Error != "scanner exploded" {
		t.Fatalf("unexpected failed job: %#v", final)
	}

	cancel()
	<-done
}

func TestQueueIsBounded(t *testing.T) {
	m, err := New(1, 1, func(string) (scanner.Result, error) {
		return scanner.Result{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Submit("one.adf"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Submit("two.adf"); err == nil {
		t.Fatal("second submit succeeded with a full queue")
	}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	if _, err := New(0, 1, scanner.ScanFile); err == nil {
		t.Fatal("zero workers accepted")
	}
	if _, err := New(1, 0, scanner.ScanFile); err == nil {
		t.Fatal("zero queue depth accepted")
	}
	if _, err := New(1, 1, nil); err == nil {
		t.Fatal("nil scan function accepted")
	}
}

func waitForTerminal(t *testing.T, m *Manager, id string) Job {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		job, ok := m.Job(id)
		if !ok {
			t.Fatalf("job %s disappeared", id)
		}
		if job.State == StateSucceeded || job.State == StateFailed || job.State == StateCanceled {
			return job
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("job %s did not reach terminal state", id)
	return Job{}
}
