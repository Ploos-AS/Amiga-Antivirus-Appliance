package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
)

// State describes the lifecycle state of a daemon scan job.
type State string

const (
	StatePending   State = "pending"
	StateRunning   State = "running"
	StateSucceeded State = "succeeded"
	StateFailed    State = "failed"
	StateCanceled  State = "canceled"
)

// Job is the daemon representation of one submitted scan.
type Job struct {
	ID          string          `json:"id"`
	Path        string          `json:"path"`
	State       State           `json:"state"`
	SubmittedAt time.Time       `json:"submitted_at"`
	StartedAt   *time.Time      `json:"started_at,omitempty"`
	FinishedAt  *time.Time      `json:"finished_at,omitempty"`
	Result      *scanner.Result `json:"result,omitempty"`
	Error       string          `json:"error,omitempty"`
}

// ScanFunc is the scanner boundary used by the daemon worker pool.
type ScanFunc func(path string) (scanner.Result, error)

// Recorder persists job snapshots as the lifecycle advances.
type Recorder interface {
	Record(Job) error
}

// Manager owns the bounded worker pool and job lifecycle.
type Manager struct {
	workers  int
	scan     ScanFunc
	recorder Recorder
	queue    chan string
	errors   chan error

	mu   sync.RWMutex
	jobs map[string]Job
}

// New creates an in-memory daemon manager.
func New(workers, queueDepth int, scan ScanFunc) (*Manager, error) {
	return NewWithRecorder(workers, queueDepth, scan, nil)
}

// NewWithRecorder creates a daemon manager with optional persistent history.
func NewWithRecorder(workers, queueDepth int, scan ScanFunc, recorder Recorder) (*Manager, error) {
	if workers < 1 {
		return nil, errors.New("workers must be at least 1")
	}
	if queueDepth < 1 {
		return nil, errors.New("queue depth must be at least 1")
	}
	if scan == nil {
		return nil, errors.New("scan function is required")
	}
	return &Manager{
		workers:  workers,
		scan:     scan,
		recorder: recorder,
		queue:    make(chan string, queueDepth),
		errors:   make(chan error, 1),
		jobs:     make(map[string]Job),
	}, nil
}

// Submit registers a scan job and places it on the bounded queue.
func (m *Manager) Submit(path string) (Job, error) {
	if path == "" {
		return Job{}, errors.New("scan path is required")
	}
	id, err := newJobID()
	if err != nil {
		return Job{}, fmt.Errorf("generate job id: %w", err)
	}
	job := Job{
		ID:          id,
		Path:        path,
		State:       StatePending,
		SubmittedAt: time.Now().UTC(),
	}

	m.mu.Lock()
	m.jobs[id] = job
	m.mu.Unlock()
	if err := m.record(job); err != nil {
		m.mu.Lock()
		delete(m.jobs, id)
		m.mu.Unlock()
		return Job{}, err
	}

	select {
	case m.queue <- id:
		return job, nil
	default:
		finished := time.Now().UTC()
		job.State = StateCanceled
		job.FinishedAt = &finished
		job.Error = "scan queue is full"
		m.mu.Lock()
		m.jobs[id] = job
		m.mu.Unlock()
		if err := m.record(job); err != nil {
			m.reportError(err)
			return job, fmt.Errorf("scan queue is full; persist rejected scan: %w", err)
		}
		return job, errors.New("scan queue is full")
	}
}

// Job returns a snapshot of one job.
func (m *Manager) Job(id string) (Job, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	job, ok := m.jobs[id]
	return job, ok
}

// Run executes workers until ctx is canceled or persistent history fails.
func (m *Manager) Run(ctx context.Context) error {
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < m.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.worker(workerCtx)
		}()
	}

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-m.errors:
		cancel()
	}
	wg.Wait()
	m.cancelPending()
	return runErr
}

func (m *Manager) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-m.queue:
			m.execute(id)
		}
	}
}

func (m *Manager) execute(id string) {
	started := time.Now().UTC()
	m.mu.Lock()
	job, ok := m.jobs[id]
	if !ok || job.State != StatePending {
		m.mu.Unlock()
		return
	}
	job.State = StateRunning
	job.StartedAt = &started
	m.jobs[id] = job
	m.mu.Unlock()
	if err := m.record(job); err != nil {
		m.reportError(err)
		return
	}

	result, err := m.scan(job.Path)
	finished := time.Now().UTC()

	m.mu.Lock()
	job = m.jobs[id]
	job.FinishedAt = &finished
	if err != nil {
		job.State = StateFailed
		job.Error = err.Error()
	} else {
		job.State = StateSucceeded
		job.Result = &result
	}
	m.jobs[id] = job
	m.mu.Unlock()
	if err := m.record(job); err != nil {
		m.reportError(err)
	}
}

func (m *Manager) cancelPending() {
	now := time.Now().UTC()
	var canceled []Job
	m.mu.Lock()
	for id, job := range m.jobs {
		if job.State != StatePending {
			continue
		}
		job.State = StateCanceled
		job.FinishedAt = &now
		m.jobs[id] = job
		canceled = append(canceled, job)
	}
	m.mu.Unlock()
	for _, job := range canceled {
		if err := m.record(job); err != nil {
			m.reportError(err)
		}
	}
}

func (m *Manager) record(job Job) error {
	if m.recorder == nil {
		return nil
	}
	if err := m.recorder.Record(job); err != nil {
		return fmt.Errorf("persist scan history: %w", err)
	}
	return nil
}

func (m *Manager) reportError(err error) {
	select {
	case m.errors <- err:
	default:
	}
}

func newJobID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
