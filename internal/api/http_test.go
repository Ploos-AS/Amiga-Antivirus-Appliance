package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/daemon"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
)

type fakeHistory struct {
	jobs []daemon.Job
	err  error
}

func (f fakeHistory) LoadLatest() ([]daemon.Job, error) {
	return f.jobs, f.err
}

func TestHealthAndVersion(t *testing.T) {
	h := NewHandler(fakeHistory{}, "0.6.0-dev")

	for _, tc := range []struct {
		path string
		want string
	}{
		{path: "/healthz", want: `"status":"ok"`},
		{path: "/version", want: `"api_version":"v1"`},
	} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status=%d", tc.path, w.Code)
		}
		if !strings.Contains(w.Body.String(), tc.want) {
			t.Fatalf("%s: body=%s", tc.path, w.Body.String())
		}
	}
}

func TestListAndGetScan(t *testing.T) {
	now := time.Date(2026, 9, 7, 7, 0, 0, 0, time.UTC)
	result := scanner.Result{SHA256: strings.Repeat("a", 64), Format: "adf", Verdict: "clean"}
	jobs := []daemon.Job{{
		ID:          "scan-1",
		Path:        "/private/incoming/sample.adf",
		State:       daemon.StateSucceeded,
		SubmittedAt: now,
		Result:      &result,
	}}
	h := NewHandler(fakeHistory{jobs: jobs}, "test")

	r := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "/private/incoming") {
		t.Fatalf("list leaked host path: %s", w.Body.String())
	}

	r = httptest.NewRequest(http.MethodGet, "/api/v1/scans/scan-1", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"succeeded"`) {
		t.Fatalf("get status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestResultsAndMissingResult(t *testing.T) {
	result := scanner.Result{SHA256: strings.Repeat("b", 64), Format: "adf", Verdict: "infected"}
	h := NewHandler(fakeHistory{jobs: []daemon.Job{
		{ID: "done", State: daemon.StateSucceeded, SubmittedAt: time.Now().UTC(), Result: &result},
		{ID: "pending", State: daemon.StatePending, SubmittedAt: time.Now().UTC()},
	}}, "test")

	r := httptest.NewRequest(http.MethodGet, "/api/v1/scans/done/results", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("results status=%d body=%s", w.Code, w.Body.String())
	}
	var got scanner.Result
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Verdict != "infected" {
		t.Fatalf("verdict=%q", got.Verdict)
	}

	r = httptest.NewRequest(http.MethodGet, "/api/v1/scans/pending/results", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("pending results status=%d", w.Code)
	}
}

func TestReadOnlyAndHistoryFailure(t *testing.T) {
	h := NewHandler(fakeHistory{err: errors.New("broken journal")}, "test")

	r := httptest.NewRequest(http.MethodPost, "/api/v1/scans", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("post status=%d allow=%q", w.Code, w.Header().Get("Allow"))
	}

	r = httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("history failure status=%d", w.Code)
	}
}

func TestUnknownScanIs404(t *testing.T) {
	h := NewHandler(fakeHistory{}, "test")
	r := httptest.NewRequest(http.MethodGet, "/api/v1/scans/missing", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}
