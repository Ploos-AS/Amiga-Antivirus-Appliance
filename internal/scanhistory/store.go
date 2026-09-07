package scanhistory

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/daemon"
)

const journalName = "scan-history.jsonl"

// Store is an append-only JSONL journal for daemon job state transitions.
// Append-only storage keeps M9.1 dependency-free and makes interrupted writes
// detectable during replay without requiring CGO or a database driver.
type Store struct {
	mu   sync.Mutex
	path string
}

// New creates the state directory if needed and returns a journal store.
func New(root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("state root is required")
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("create state root: %w", err)
	}
	return &Store{path: filepath.Join(root, journalName)}, nil
}

// Record appends one complete job snapshot and fsyncs it before returning.
func (s *Store) Record(job daemon.Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("open scan history: %w", err)
	}
	enc := json.NewEncoder(f)
	if err := enc.Encode(job); err != nil {
		_ = f.Close()
		return fmt.Errorf("append scan history: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync scan history: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close scan history: %w", err)
	}
	return nil
}

// LoadLatest replays the journal and returns the last valid snapshot for each
// job. A malformed non-empty record is an error rather than silently dropping
// history. Results are ordered by submission time, newest first.
func (s *Store) LoadLatest() ([]daemon.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open scan history: %w", err)
	}
	defer f.Close()

	latest := make(map[string]daemon.Job)
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 16*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		if len(scanner.Bytes()) == 0 {
			continue
		}
		var job daemon.Job
		if err := json.Unmarshal(scanner.Bytes(), &job); err != nil {
			return nil, fmt.Errorf("decode scan history line %d: %w", line, err)
		}
		if job.ID == "" {
			return nil, fmt.Errorf("decode scan history line %d: missing job id", line)
		}
		latest[job.ID] = job
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read scan history: %w", err)
	}

	jobs := make([]daemon.Job, 0, len(latest))
	for _, job := range latest {
		jobs = append(jobs, job)
	}
	sort.Slice(jobs, func(i, j int) bool {
		return jobs[i].SubmittedAt.After(jobs[j].SubmittedAt)
	})
	return jobs, nil
}

// RecoverInterrupted closes jobs that cannot still be running after a daemon
// restart. The recovery is itself appended to the journal so later replay and
// API clients see an explicit terminal state rather than stale activity.
func (s *Store) RecoverInterrupted() ([]daemon.Job, error) {
	jobs, err := s.LoadLatest()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	for i := range jobs {
		if jobs[i].State != daemon.StatePending && jobs[i].State != daemon.StateRunning {
			continue
		}
		jobs[i].State = daemon.StateCanceled
		jobs[i].FinishedAt = &now
		jobs[i].Error = "daemon restarted before scan completed"
		if err := s.Record(jobs[i]); err != nil {
			return nil, fmt.Errorf("recover interrupted scan %s: %w", jobs[i].ID, err)
		}
	}
	return jobs, nil
}

// Path returns the journal path for diagnostics and qualification.
func (s *Store) Path() string {
	return s.path
}
