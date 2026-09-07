package dropfolder

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatcherPollSubmitsStableSnapshotOnce(t *testing.T) {
	drop := t.TempDir()
	incoming := t.TempDir()
	source := filepath.Join(drop, "disk.adf")
	if err := os.WriteFile(source, []byte("stable payload"), 0o640); err != nil {
		t.Fatal(err)
	}

	var submitted []string
	w := Watcher{
		Root:         drop,
		IncomingRoot: incoming,
		PollInterval: time.Second,
		StableFor:    2 * time.Second,
		MaxBytes:     1024,
		Submit: func(path string) error {
			submitted = append(submitted, path)
			return nil
		},
	}
	observed := make(map[string]observation)
	t0 := time.Unix(1000, 0).UTC()
	if err := w.poll(t0, observed, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.poll(t0.Add(time.Second), observed, nil); err != nil {
		t.Fatal(err)
	}
	if len(submitted) != 0 {
		t.Fatalf("submitted before stability window: %v", submitted)
	}
	if err := w.poll(t0.Add(2*time.Second), observed, nil); err != nil {
		t.Fatal(err)
	}
	if len(submitted) != 1 {
		t.Fatalf("submissions=%d want=1", len(submitted))
	}
	if filepath.Dir(submitted[0]) != incoming {
		t.Fatalf("submitted live drop path: %s", submitted[0])
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("source should remain: %v", err)
	}
	if err := w.poll(t0.Add(10*time.Second), observed, nil); err != nil {
		t.Fatal(err)
	}
	if len(submitted) != 1 {
		t.Fatalf("stable source resubmitted: %d", len(submitted))
	}
}

func TestWatcherPollResetsWhenFileChanges(t *testing.T) {
	drop := t.TempDir()
	incoming := t.TempDir()
	source := filepath.Join(drop, "archive.lha")
	if err := os.WriteFile(source, []byte("one"), 0o640); err != nil {
		t.Fatal(err)
	}

	submits := 0
	w := Watcher{Root: drop, IncomingRoot: incoming, PollInterval: time.Second, StableFor: 2 * time.Second, MaxBytes: 1024, Submit: func(string) error { submits++; return nil }}
	observed := make(map[string]observation)
	t0 := time.Unix(2000, 0).UTC()
	if err := w.poll(t0, observed, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("changed payload"), 0o640); err != nil {
		t.Fatal(err)
	}
	changedTime := time.Unix(3000, 0)
	if err := os.Chtimes(source, changedTime, changedTime); err != nil {
		t.Fatal(err)
	}
	if err := w.poll(t0.Add(2*time.Second), observed, nil); err != nil {
		t.Fatal(err)
	}
	if submits != 0 {
		t.Fatalf("changed file submitted too early: %d", submits)
	}
	if err := w.poll(t0.Add(4*time.Second), observed, nil); err != nil {
		t.Fatal(err)
	}
	if submits != 1 {
		t.Fatalf("submits=%d want=1", submits)
	}
}

func TestWatcherPollRetriesTransientSubmitFailure(t *testing.T) {
	drop := t.TempDir()
	incoming := t.TempDir()
	if err := os.WriteFile(filepath.Join(drop, "sample.adf"), []byte("payload"), 0o640); err != nil {
		t.Fatal(err)
	}

	attempts := 0
	w := Watcher{Root: drop, IncomingRoot: incoming, PollInterval: time.Second, StableFor: time.Second, MaxBytes: 1024, Submit: func(string) error {
		attempts++
		if attempts == 1 {
			return errors.New("queue full")
		}
		return nil
	}}
	observed := make(map[string]observation)
	t0 := time.Unix(4000, 0).UTC()
	if err := w.poll(t0, observed, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.poll(t0.Add(time.Second), observed, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.poll(t0.Add(2*time.Second), observed, nil); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("attempts=%d want=2", attempts)
	}
}

func TestWatcherReceiptsPreventRestartResubmitUntilSourceRemoved(t *testing.T) {
	drop := t.TempDir()
	incoming := t.TempDir()
	receiptPath := filepath.Join(t.TempDir(), "drop-ingest.json")
	source := filepath.Join(drop, "disk.adf")
	if err := os.WriteFile(source, []byte("same payload"), 0o640); err != nil {
		t.Fatal(err)
	}

	submits := 0
	w := Watcher{Root: drop, IncomingRoot: incoming, PollInterval: time.Second, StableFor: time.Second, MaxBytes: 1024, Submit: func(string) error { submits++; return nil }}
	store, err := OpenReceiptStore(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(5000, 0).UTC()
	observed := make(map[string]observation)
	if err := w.poll(t0, observed, store); err != nil {
		t.Fatal(err)
	}
	if err := w.poll(t0.Add(time.Second), observed, store); err != nil {
		t.Fatal(err)
	}
	if submits != 1 {
		t.Fatalf("initial submits=%d want=1", submits)
	}

	store, err = OpenReceiptStore(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	observed = make(map[string]observation)
	if err := w.poll(t0.Add(2*time.Second), observed, store); err != nil {
		t.Fatal(err)
	}
	if err := w.poll(t0.Add(3*time.Second), observed, store); err != nil {
		t.Fatal(err)
	}
	if submits != 1 {
		t.Fatalf("unchanged source resubmitted after restart: %d", submits)
	}

	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := w.poll(t0.Add(4*time.Second), observed, store); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("same payload"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := w.poll(t0.Add(5*time.Second), observed, store); err != nil {
		t.Fatal(err)
	}
	if err := w.poll(t0.Add(6*time.Second), observed, store); err != nil {
		t.Fatal(err)
	}
	if submits != 2 {
		t.Fatalf("re-dropped source submits=%d want=2", submits)
	}
}

func TestWatcherValidation(t *testing.T) {
	w := Watcher{Root: "/same", IncomingRoot: "/same", PollInterval: time.Second, StableFor: time.Second, MaxBytes: 1, Submit: func(string) error { return nil }}
	if err := w.validate(); err == nil {
		t.Fatal("expected equal root validation failure")
	}
}
