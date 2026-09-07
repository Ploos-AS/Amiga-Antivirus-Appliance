package dropfolder

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

// SubmitFunc queues an immutable staged snapshot for scanning.
type SubmitFunc func(path string) error

// Watcher polls an externally writable drop directory and submits stable files.
type Watcher struct {
	Root         string
	IncomingRoot string
	PollInterval time.Duration
	StableFor    time.Duration
	MaxBytes     int64
	Submit       SubmitFunc
}

type observation struct {
	candidate Candidate
	firstSeen time.Time
	handled   bool
}

// Run watches until ctx is canceled. Source files are never removed or scanned live.
func (w Watcher) Run(ctx context.Context) error {
	if err := w.validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(w.Root, 0o750); err != nil {
		return fmt.Errorf("create drop root: %w", err)
	}

	observed := make(map[string]observation)
	ticker := time.NewTicker(w.PollInterval)
	defer ticker.Stop()

	if err := w.poll(time.Now().UTC(), observed); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			if err := w.poll(now.UTC(), observed); err != nil {
				return err
			}
		}
	}
}

func (w Watcher) poll(now time.Time, observed map[string]observation) error {
	entries, err := os.ReadDir(w.Root)
	if err != nil {
		return fmt.Errorf("read drop root: %w", err)
	}
	present := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		candidate, ok, err := Observe(w.Root, name)
		if err != nil {
			return fmt.Errorf("observe drop file %q: %w", name, err)
		}
		if !ok {
			continue
		}
		present[name] = struct{}{}

		previous, exists := observed[name]
		if !exists || !Stable(previous.candidate, candidate) {
			observed[name] = observation{candidate: candidate, firstSeen: now}
			continue
		}
		if previous.handled || now.Sub(previous.firstSeen) < w.StableFor {
			continue
		}

		snapshot, err := Stage(candidate, w.IncomingRoot, w.MaxBytes)
		if err != nil {
			// A concurrent writer can legitimately change the file between observation
			// and staging. Re-observe it on the next poll instead of terminating AAA.
			if errors.Is(err, os.ErrNotExist) || err.Error() == "drop file changed before staging" || err.Error() == "drop file changed while staging" {
				delete(observed, name)
				continue
			}
			return fmt.Errorf("stage drop file %q: %w", name, err)
		}
		if err := w.Submit(snapshot.Path); err != nil {
			// Keep the observation unhandled so a transient full queue is retried.
			continue
		}
		previous.handled = true
		observed[name] = previous
	}

	for name := range observed {
		if _, ok := present[name]; !ok {
			delete(observed, name)
		}
	}
	return nil
}

func (w Watcher) validate() error {
	if w.Root == "" || w.IncomingRoot == "" {
		return errors.New("drop root and incoming root are required")
	}
	if w.Root == w.IncomingRoot {
		return errors.New("drop root and incoming root must differ")
	}
	if w.PollInterval <= 0 {
		return errors.New("poll interval must be positive")
	}
	if w.StableFor <= 0 {
		return errors.New("stable duration must be positive")
	}
	if w.MaxBytes < 1 {
		return errors.New("max bytes must be at least 1")
	}
	if w.Submit == nil {
		return errors.New("submit function is required")
	}
	return nil
}
