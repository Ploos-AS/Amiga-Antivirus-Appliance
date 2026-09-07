package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIndexAndAssets(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("UI route delegated to API: %s", r.URL.Path)
	})
	h := New(api)

	for _, tc := range []struct {
		path        string
		contentType string
		contains    string
	}{
		{path: "/", contentType: "text/html", contains: "Amiga AntiVirus Appliance"},
		{path: "/ui/app.js", contentType: "text/javascript", contains: "/api/v1/scans"},
		{path: "/ui/style.css", contentType: "text/css", contains: ".panel"},
	} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s status=%d", tc.path, w.Code)
		}
		if !strings.HasPrefix(w.Header().Get("Content-Type"), tc.contentType) {
			t.Fatalf("%s content-type=%q", tc.path, w.Header().Get("Content-Type"))
		}
		if !strings.Contains(w.Body.String(), tc.contains) {
			t.Fatalf("%s body missing %q", tc.path, tc.contains)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := New(nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	for name, want := range map[string]string{
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := w.Header().Get(name); got != want {
			t.Fatalf("%s=%q want=%q", name, got, want)
		}
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "connect-src 'self'") {
		t.Fatalf("unexpected CSP: %q", csp)
	}
}

func TestDelegatesAPIRoutes(t *testing.T) {
	called := false
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	h := New(api)
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !called || w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "ok") {
		t.Fatalf("API delegation failed: called=%v status=%d body=%s", called, w.Code, w.Body.String())
	}
}

func TestUIRejectsWriteMethods(t *testing.T) {
	h := New(nil)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", w.Code)
	}
	if w.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("Allow=%q", w.Header().Get("Allow"))
	}
}
