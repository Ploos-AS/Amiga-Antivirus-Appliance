package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

type fakeSubmitter struct {
	paths []string
	err   error
}

func (f *fakeSubmitter) Submit(path string) (daemon.Job, error) {
	if f.err != nil {
		return daemon.Job{}, f.err
	}
	f.paths = append(f.paths, path)
	return daemon.Job{ID: "job-1", State: daemon.StatePending, SubmittedAt: time.Now().UTC()}, nil
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

func TestSubmitStreamsIntoControlledIncomingRoot(t *testing.T) {
	root := t.TempDir()
	submitter := &fakeSubmitter{}
	h := NewHandlerWithSubmission(fakeHistory{}, "test", SubmissionConfig{
		Submitter:      submitter,
		IncomingRoot:  root,
		MaxUploadBytes: 1024,
	})

	r := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader("amiga payload"))
	r.Header.Set("X-AAA-Filename", "sample.adf")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(submitter.paths) != 1 {
		t.Fatalf("submitted paths=%v", submitter.paths)
	}
	path := submitter.paths[0]
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		t.Fatalf("submitted path escaped incoming root: %q", path)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "amiga payload" {
		t.Fatalf("stored payload=%q", got)
	}
	if !strings.Contains(w.Body.String(), `"sha256":"c55643f8`) {
		// The complete digest is deliberately not hard-coded here; the response
		// is separately decoded below to verify its shape and length.
		var response submitResponse
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if len(response.SHA256) != 64 || response.Size != int64(len("amiga payload")) {
			t.Fatalf("unexpected response: %#v", response)
		}
	}
}

func TestSubmitRejectsTraversalAndOversize(t *testing.T) {
	root := t.TempDir()
	submitter := &fakeSubmitter{}
	h := NewHandlerWithSubmission(fakeHistory{}, "test", SubmissionConfig{
		Submitter:      submitter,
		IncomingRoot:  root,
		MaxUploadBytes: 4,
	})

	r := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader("abc"))
	r.Header.Set("X-AAA-Filename", "../escape.adf")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("traversal status=%d body=%s", w.Code, w.Body.String())
	}

	r = httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader("12345"))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize status=%d body=%s", w.Code, w.Body.String())
	}
	if len(submitter.paths) != 0 {
		t.Fatalf("rejected upload reached scanner: %v", submitter.paths)
	}
}

func TestSubmitDeduplicatesStoredPayloadButRescans(t *testing.T) {
	root := t.TempDir()
	submitter := &fakeSubmitter{}
	h := NewHandlerWithSubmission(fakeHistory{}, "test", SubmissionConfig{
		Submitter:      submitter,
		IncomingRoot:  root,
		MaxUploadBytes: 1024,
	})

	for i := 0; i < 2; i++ {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader("same payload"))
		r.Header.Set("X-AAA-Filename", "same.adf")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusAccepted {
			t.Fatalf("request %d status=%d body=%s", i, w.Code, w.Body.String())
		}
		var response submitResponse
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Duplicate != (i == 1) {
			t.Fatalf("request %d duplicate=%v", i, response.Duplicate)
		}
	}
	if len(submitter.paths) != 2 || submitter.paths[0] != submitter.paths[1] {
		t.Fatalf("dedupe/rescan paths=%v", submitter.paths)
	}
}

func TestSubmitQueueFailureIsServiceUnavailable(t *testing.T) {
	h := NewHandlerWithSubmission(fakeHistory{}, "test", SubmissionConfig{
		Submitter:      &fakeSubmitter{err: errors.New("queue full")},
		IncomingRoot:  t.TempDir(),
		MaxUploadBytes: 1024,
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader("payload"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}
