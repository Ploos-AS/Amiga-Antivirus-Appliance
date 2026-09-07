package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestM104OperationalDashboardAssets(t *testing.T) {
	h := New(nil)

	for _, tc := range []struct {
		path     string
		contains []string
	}{
		{
			path: "/",
			contains: []string{
				`aria-label="Operational dashboard"`,
				`id="metric-active"`,
				`id="metric-infected"`,
				`id="engine-health"`,
			},
		},
		{
			path: "/ui/app.js",
			contains: []string{
				`function updateDashboard(jobs)`,
				`function renderEngineHealth(done)`,
				`engine_results`,
				`metric-engine-errors`,
			},
		},
	} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s status=%d", tc.path, w.Code)
		}
		for _, want := range tc.contains {
			if !strings.Contains(w.Body.String(), want) {
				t.Errorf("%s missing %q", tc.path, want)
			}
		}
	}
}
