package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	h := NewHandler(fakeHistory{}, "test")
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	for name, want := range map[string]string{
		"Cache-Control":         "no-store",
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := w.Header().Get(name); got != want {
			t.Fatalf("%s=%q, want %q", name, got, want)
		}
	}
	if got := w.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'none'") {
		t.Fatalf("unexpected CSP: %q", got)
	}
}

func TestSubmitRejectsUnsupportedContentType(t *testing.T) {
	submitter := &fakeSubmitter{}
	h := NewHandlerWithSubmission(fakeHistory{}, "test", SubmissionConfig{
		Submitter:      submitter,
		IncomingRoot:  t.TempDir(),
		MaxUploadBytes: 1024,
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader("payload"))
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(submitter.paths) != 0 {
		t.Fatalf("unsupported upload reached scanner: %v", submitter.paths)
	}
}

func TestSubmitAcceptsOctetStreamContentType(t *testing.T) {
	submitter := &fakeSubmitter{}
	h := NewHandlerWithSubmission(fakeHistory{}, "test", SubmissionConfig{
		Submitter:      submitter,
		IncomingRoot:  t.TempDir(),
		MaxUploadBytes: 1024,
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader("payload"))
	r.Header.Set("Content-Type", "application/octet-stream")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}
