package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/daemon"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/engineevidence"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
)

func TestResultsDoNotExposeHostPath(t *testing.T) {
	incoming := "/data/aaa/incoming/0123456789abcdef-sample.adf"
	result := scanner.Result{
		Path:    incoming,
		Name:    "sample.adf",
		SHA256:  strings.Repeat("a", 64),
		Format:  "adf",
		Verdict: "unknown",
		EngineResults: []engineevidence.Result{{
			Kind:          engineevidence.KindNative,
			EngineID:      "aaa-native",
			EngineName:    "AAA native",
			EngineVersion: "test",
			Status:        engineevidence.StatusCompleted,
			Verdict:       "unknown",
			InputSHA256:   strings.Repeat("a", 64),
		}},
	}
	job := daemon.Job{ID: "done", State: daemon.StateSucceeded, SubmittedAt: time.Now().UTC(), Result: &result}
	h := NewHandler(fakeHistory{jobs: []daemon.Job{job}}, "test")

	r := httptest.NewRequest(http.MethodGet, "/api/v1/scans/done/results", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, `"path"`) {
		t.Fatalf("result response exposed path field: %s", body)
	}
	if strings.Contains(body, incoming) || strings.Contains(body, "/data/aaa/incoming") {
		t.Fatalf("result response exposed incoming host path: %s", body)
	}
	if !strings.Contains(body, `"engine_results"`) || !strings.Contains(body, `"aaa-native"`) {
		t.Fatalf("result response lost engine evidence: %s", body)
	}
	if !strings.Contains(body, `"sha256":"`+strings.Repeat("a", 64)+`"`) || !strings.Contains(body, `"verdict":"unknown"`) {
		t.Fatalf("result response lost normal scan fields: %s", body)
	}
}
