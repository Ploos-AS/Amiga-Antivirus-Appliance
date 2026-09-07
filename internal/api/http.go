package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/daemon"
)

// HistoryReader supplies the latest persisted snapshot for each scan job.
type HistoryReader interface {
	LoadLatest() ([]daemon.Job, error)
}

// Handler exposes the read-only M9.2 HTTP API.
type Handler struct {
	history HistoryReader
	version string
}

// NewHandler creates the read-only API handler.
func NewHandler(history HistoryReader, version string) http.Handler {
	return &Handler{history: history, version: version}
}

type errorResponse struct {
	Error string `json:"error"`
}

type healthResponse struct {
	Status string `json:"status"`
}

type versionResponse struct {
	Version    string `json:"version"`
	APIVersion string `json:"api_version"`
}

type scanResponse struct {
	ID          string       `json:"id"`
	State       daemon.State `json:"state"`
	SubmittedAt time.Time    `json:"submitted_at"`
	StartedAt   *time.Time   `json:"started_at,omitempty"`
	FinishedAt  *time.Time   `json:"finished_at,omitempty"`
	Error       string       `json:"error,omitempty"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}

	switch r.URL.Path {
	case "/healthz":
		writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
	case "/version":
		writeJSON(w, http.StatusOK, versionResponse{Version: h.version, APIVersion: "v1"})
	case "/api/v1/scans":
		h.listScans(w)
	default:
		h.scanRoute(w, r.URL.Path)
	}
}

func (h *Handler) listScans(w http.ResponseWriter) {
	jobs, err := h.history.LoadLatest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "scan history unavailable"})
		return
	}
	out := make([]scanResponse, 0, len(jobs))
	for _, job := range jobs {
		out = append(out, summarize(job))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) scanRoute(w http.ResponseWriter, path string) {
	const prefix = "/api/v1/scans/"
	if !strings.HasPrefix(path, prefix) {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "not found"})
		return
	}
	rest := strings.TrimPrefix(path, prefix)
	if rest == "" || strings.Contains(rest, "//") {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "not found"})
		return
	}

	id := rest
	results := false
	if strings.HasSuffix(rest, "/results") {
		id = strings.TrimSuffix(rest, "/results")
		results = true
	}
	if id == "" || strings.Contains(id, "/") {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "not found"})
		return
	}

	job, err := h.findJob(id)
	if errors.Is(err, errNotFound) {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "scan not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "scan history unavailable"})
		return
	}

	if results {
		if job.Result == nil {
			writeJSON(w, http.StatusConflict, errorResponse{Error: "scan result not available"})
			return
		}
		writeJSON(w, http.StatusOK, job.Result)
		return
	}
	writeJSON(w, http.StatusOK, summarize(job))
}

var errNotFound = errors.New("scan not found")

func (h *Handler) findJob(id string) (daemon.Job, error) {
	jobs, err := h.history.LoadLatest()
	if err != nil {
		return daemon.Job{}, err
	}
	for _, job := range jobs {
		if job.ID == id {
			return job, nil
		}
	}
	return daemon.Job{}, errNotFound
}

func summarize(job daemon.Job) scanResponse {
	return scanResponse{
		ID:          job.ID,
		State:       job.State,
		SubmittedAt: job.SubmittedAt,
		StartedAt:   job.StartedAt,
		FinishedAt:  job.FinishedAt,
		Error:       job.Error,
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
