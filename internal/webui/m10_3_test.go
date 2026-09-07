package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestM103EngineEvidenceClientContract(t *testing.T) {
	h := New(nil)
	r := httptest.NewRequest(http.MethodGet, "/ui/app.js", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"engine_results",
		"AAA Native",
		"ClamAV",
		"Historical Amiga",
		"Support components",
		"database_version",
		"os_profile",
		"binary_sha256",
		"raw_evidence_sha256",
		"Engine disagreement",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("app.js missing M10.3 contract marker %q", want)
		}
	}
}

func TestM103EngineEvidenceStyles(t *testing.T) {
	h := New(nil)
	r := httptest.NewRequest(http.MethodGet, "/ui/style.css", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{".engine-grid", ".engine-card", ".components", ".warning"} {
		if !strings.Contains(body, want) {
			t.Fatalf("style.css missing M10.3 selector %q", want)
		}
	}
}
