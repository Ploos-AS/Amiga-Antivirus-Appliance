package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStructuredResultClientContract(t *testing.T) {
	h := New(nil)
	r := httptest.NewRequest(http.MethodGet, "/ui/app.js", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	body := w.Body.String()
	for _, marker := range []string{
		"renderResult",
		"bootblock_match",
		"member_results",
		"filesystem",
		"hunk",
		"preservation_image",
		"Additional attributed evidence",
		"Raw API result",
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("app.js missing structured-result marker %q", marker)
		}
	}
}

func TestResultPanelIsStructuredContainer(t *testing.T) {
	h := New(nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `id="result"`) || strings.Contains(body, `<pre id="result">`) {
		t.Fatalf("result panel did not migrate from raw-only preformatted output")
	}
}
