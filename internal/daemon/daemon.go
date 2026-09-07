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

// Job is the in-memory M9.0 representation of one submitted scan.
// Persistent history is introduced separately in M9.1.
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

// Manager owns the bounded worker pool and in-memory job lifecycle.
type Manager struct {
	workers int
	scan    ScanFunc
	queue   chan string

	mu   sync.RWMutex
	jobs map[string]Job
}

// New creates a daemon manager. The queue is deliberately bounded to avoid
// unbounded memory growth before M9 adds the network-facing submission API.
func New(workers, queueDepth int, scan ScanFunc) (*Manager, error) {
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
		workers: workers,
		scan:    scan,
		queue:   make(chan string, queueDepth),
		jobs:    make(map[string]Job),
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

	select {
	case m.queue <- id:
		return job, nil
	default:
		m.mu.Lock()
		delete(m.jobs, id)
		m.mu.Unlock()
		return Job{}, errors.New("scan queue is full")
	}
}

// Job returns a snapshot of one job.
func (m *Manager) Job(id string) (Job, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	job, ok := m.jobs[id]
	return job, ok
}

// Run executes workers until ctx is canceled, then marks work which never
// started as canceled and returns after all active workers have stopped.
func (m *Manager) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < m.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.worker(ctx)
		}()
	}

	<-ctx.Done()
	wg.Wait()
	m.cancelPending()
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

	result, err := m.scan(job.Path)
	finished := time.Now().UTC()

	m.mu.Lock()
	defer m.mu.Unlock()
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
}

func (m *Manager) cancelPending() {
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, job := range m.jobs {
		if job.State != StatePending {
			continue
		}
		job.State = StateCanceled
		job.FinishedAt = &now
		m.jobs[id] = job
	}
}

func newJobID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
