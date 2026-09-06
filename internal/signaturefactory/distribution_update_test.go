package signaturefactory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverDistributionReleaseSelectsNewestNewerVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[
{"tag_name":"signatures-v1.2.0","draft":false,"prerelease":false,"assets":[{"name":"aaa-signatures-1.2.0.tar.gz","browser_download_url":"`+"http://"+r.Host+`/1.2.0"}]},
{"tag_name":"signatures-v2.0.0","draft":false,"prerelease":false,"assets":[{"name":"aaa-signatures-2.0.0.tar.gz","browser_download_url":"`+"http://"+r.Host+`/2.0.0"}]},
{"tag_name":"signatures-vbogus","draft":false,"prerelease":false,"assets":[]}
]`)
	}))
	defer server.Close()
	current := &DistributionInstallState{Schema: DistributionInstallStateSchema, Version: "1.1.9", ManifestSHA256: strings.Repeat("0", 64)}
	candidate, err := DiscoverDistributionRelease(context.Background(), server.URL, current)
	if err != nil { t.Fatal(err) }
	if candidate == nil || candidate.Version != "2.0.0" { t.Fatalf("unexpected candidate: %#v", candidate) }
}

func TestDiscoverDistributionReleaseNoUpdate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"tag_name":"signatures-v1.0.0","draft":false,"prerelease":false,"assets":[{"name":"aaa-signatures-1.0.0.tar.gz","browser_download_url":"`+"http://"+r.Host+`/a"}]}]`)
	}))
	defer server.Close()
	current := &DistributionInstallState{Schema: 1, Version: "1.0.0", ManifestSHA256: strings.Repeat("0", 64)}
	candidate, err := DiscoverDistributionRelease(context.Background(), server.URL, current)
	if err != nil { t.Fatal(err) }
	if candidate != nil { t.Fatalf("expected no update, got %#v", candidate) }
}

func TestDownloadDistributionArchiveBoundedAndChecksDigest(t *testing.T) {
	body := []byte("signed-archive-fixture")
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
	defer server.Close()
	root := t.TempDir()
	output := filepath.Join(root, "aaa-signatures-1.2.3.tar.gz")
	got, err := DownloadDistributionArchive(context.Background(), server.URL, "1.2.3", output, digest)
	if err != nil { t.Fatal(err) }
	if got != digest { t.Fatalf("digest=%s want %s", got, digest) }
	data, err := os.ReadFile(output); if err != nil { t.Fatal(err) }
	if string(data) != string(body) { t.Fatal("download content changed") }
}

func TestDownloadDistributionArchiveChecksumFailureLeavesNoOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "bad") }))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "aaa-signatures-1.2.3.tar.gz")
	_, err := DownloadDistributionArchive(context.Background(), server.URL, "1.2.3", output, strings.Repeat("0", 64))
	if err == nil { t.Fatal("expected checksum failure") }
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) { t.Fatalf("output survived failure: %v", statErr) }
}

func TestDistributionUpdateRejectsFileScheme(t *testing.T) {
	if _, err := DiscoverDistributionRelease(context.Background(), "file:///tmp/releases.json", nil); err == nil { t.Fatal("expected file scheme rejection") }
}
