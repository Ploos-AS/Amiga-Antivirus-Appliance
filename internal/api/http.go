package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/daemon"
)

const defaultMaxUploadBytes int64 = 256 * 1024 * 1024

type HistoryReader interface {
	LoadLatest() ([]daemon.Job, error)
}

type Submitter interface {
	Submit(path string) (daemon.Job, error)
}

type SubmissionConfig struct {
	Submitter      Submitter
	IncomingRoot   string
	MaxUploadBytes int64
}

type Handler struct {
	history        HistoryReader
	version        string
	submitter      Submitter
	incomingRoot   string
	maxUploadBytes int64
}

func NewHandler(history HistoryReader, version string) http.Handler {
	return &Handler{history: history, version: version}
}

func NewHandlerWithSubmission(history HistoryReader, version string, cfg SubmissionConfig) http.Handler {
	limit := cfg.MaxUploadBytes
	if limit <= 0 {
		limit = defaultMaxUploadBytes
	}
	return &Handler{
		history:        history,
		version:        version,
		submitter:      cfg.Submitter,
		incomingRoot:   cfg.IncomingRoot,
		maxUploadBytes: limit,
	}
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

type submitResponse struct {
	ID        string       `json:"id"`
	State     daemon.State `json:"state"`
	SHA256    string       `json:"sha256"`
	Size      int64        `json:"size"`
	Duplicate bool         `json:"duplicate"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

	if r.URL.Path == "/api/v1/scans" && r.Method == http.MethodPost && h.submissionEnabled() {
		h.submitScan(w, r)
		return
	}
	if r.Method != http.MethodGet {
		allow := http.MethodGet
		if r.URL.Path == "/api/v1/scans" && h.submissionEnabled() {
			allow += ", " + http.MethodPost
		}
		w.Header().Set("Allow", allow)
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

func (h *Handler) submissionEnabled() bool {
	return h.submitter != nil && h.incomingRoot != ""
}

func (h *Handler) submitScan(w http.ResponseWriter, r *http.Request) {
	contentType := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])
	if contentType != "" && contentType != "application/octet-stream" {
		writeJSON(w, http.StatusUnsupportedMediaType, errorResponse{Error: "unsupported content type"})
		return
	}

	name, err := safeUploadName(r.Header.Get("X-AAA-Filename"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid upload filename"})
		return
	}
	if r.ContentLength > h.maxUploadBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse{Error: "upload too large"})
		return
	}
	if err := os.MkdirAll(h.incomingRoot, 0o750); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "incoming storage unavailable"})
		return
	}

	tmp, err := os.CreateTemp(h.incomingRoot, ".upload-*")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "incoming storage unavailable"})
		return
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		_ = tmp.Close()
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()

	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, hash), io.LimitReader(r.Body, h.maxUploadBytes+1))
	if copyErr != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "upload failed"})
		return
	}
	if n > h.maxUploadBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse{Error: "upload too large"})
		return
	}
	if n == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "empty upload"})
		return
	}
	if err := tmp.Sync(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "incoming storage unavailable"})
		return
	}
	if err := tmp.Close(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "incoming storage unavailable"})
		return
	}

	digest := hex.EncodeToString(hash.Sum(nil))
	target := filepath.Join(h.incomingRoot, digest+"-"+name)
	duplicate := false
	if err := os.Link(tmpPath, target); err != nil {
		if errors.Is(err, os.ErrExist) {
			duplicate = true
		} else {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "incoming storage unavailable"})
			return
		}
	}
	if err := os.Remove(tmpPath); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "incoming storage unavailable"})
		return
	}
	removeTemp = false

	job, err := h.submitter.Submit(target)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "scan queue unavailable"})
		return
	}
	writeJSON(w, http.StatusAccepted, submitResponse{
		ID:        job.ID,
		State:     job.State,
		SHA256:    digest,
		Size:      n,
		Duplicate: duplicate,
	})
}

func safeUploadName(value string) (string, error) {
	name := strings.TrimSpace(value)
	if name == "" {
		return "upload.bin", nil
	}
	if len(name) > 255 || name == "." || name == ".." || strings.ContainsAny(name, `/\\`) || filepath.Base(name) != name {
		return "", fmt.Errorf("unsafe filename")
	}
	return name, nil
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
