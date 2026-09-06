package signaturefactory

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestM75SyntheticReleaseUpdateLifecycle(t *testing.T) {
	store := t.TempDir()
	generated := filepath.Join(store, "generated")
	mustWriteLifecycleFile(t, filepath.Join(generated, "aaa", "bootblocks.json"), []byte("{\"schema\":1,\"signatures\":[]}\n"))
	mustWriteLifecycleFile(t, filepath.Join(generated, "clamav", "aaa.hsb"), []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:512:AAA.Synthetic\n"))

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	trusted, err := NewTrustedDistributionKeys(hex.EncodeToString(publicKey))
	if err != nil {
		t.Fatal(err)
	}

	bundle := filepath.Join(t.TempDir(), "bundle")
	createdAt := time.Date(2026, 9, 6, 7, 30, 0, 0, time.UTC)
	if _, err := BuildDistributionBundle(store, bundle, "1.2.3", createdAt); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SignDistributionBundle(bundle, privateKey); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyDistributionBundle(bundle, trusted); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(t.TempDir(), DistributionArchivePrefix+"1.2.3"+DistributionArchiveSuffix)
	_, archiveDigest, err := BuildDistributionReleaseArchive(bundle, archive, trusted)
	if err != nil {
		t.Fatal(err)
	}
	archiveBytes, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases":
			fmt.Fprintf(w, `[{"tag_name":"signatures-v1.2.3","draft":false,"prerelease":false,"assets":[{"name":"aaa-signatures-1.2.3.tar.gz","browser_download_url":"http://%s/archive"}]}]`, r.Host)
		case "/archive":
			_, _ = w.Write(archiveBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	candidate, err := DiscoverDistributionRelease(context.Background(), server.URL+"/releases", nil)
	if err != nil {
		t.Fatal(err)
	}
	if candidate == nil || candidate.Version != "1.2.3" {
		t.Fatalf("unexpected candidate: %#v", candidate)
	}

	downloaded := filepath.Join(t.TempDir(), DistributionArchivePrefix+candidate.Version+DistributionArchiveSuffix)
	gotDigest, err := DownloadDistributionArchive(context.Background(), candidate.ArchiveURL, candidate.Version, downloaded, archiveDigest)
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != archiveDigest {
		t.Fatalf("download digest=%s want %s", gotDigest, archiveDigest)
	}

	extracted := filepath.Join(t.TempDir(), "extracted")
	extractedManifest, err := ExtractDistributionReleaseArchive(downloaded, extracted)
	if err != nil {
		t.Fatal(err)
	}
	if extractedManifest.Version != "1.2.3" {
		t.Fatalf("extracted version=%s", extractedManifest.Version)
	}
	manifest, identity, err := VerifyDistributionBundle(extracted, trusted)
	if err != nil {
		t.Fatal(err)
	}
	state, err := InstallDistributionBundle(extracted, store, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != manifest.Version || state.ManifestSHA256 != identity {
		t.Fatalf("installed state mismatch: %#v", state)
	}
	active, have, err := ReadDistributionInstallState(store)
	if err != nil || !have {
		t.Fatalf("active state missing: have=%v err=%v", have, err)
	}
	if active != state {
		t.Fatalf("active state=%#v want %#v", active, state)
	}
}

func TestM75FailedUpdatePreservesActiveDistribution(t *testing.T) {
	store := t.TempDir()
	generated := filepath.Join(store, "generated")
	mustWriteLifecycleFile(t, filepath.Join(generated, "aaa", "bootblocks.json"), []byte("{}\n"))
	mustWriteLifecycleFile(t, filepath.Join(generated, "clamav", "aaa.hsb"), []byte("fixture\n"))
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	trusted, err := NewTrustedDistributionKeys(hex.EncodeToString(publicKey))
	if err != nil {
		t.Fatal(err)
	}

	bundle := filepath.Join(t.TempDir(), "bundle")
	if _, err := BuildDistributionBundle(store, bundle, "1.0.0", time.Date(2026, 9, 6, 7, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SignDistributionBundle(bundle, privateKey); err != nil {
		t.Fatal(err)
	}
	before, err := InstallDistributionBundle(bundle, store, trusted)
	if err != nil {
		t.Fatal(err)
	}

	bad := filepath.Join(t.TempDir(), DistributionArchivePrefix+"2.0.0"+DistributionArchiveSuffix)
	if err := os.WriteFile(bad, []byte("not-a-release-archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractDistributionReleaseArchive(bad, filepath.Join(t.TempDir(), "bad")); err == nil {
		t.Fatal("expected corrupt archive rejection")
	}
	after, have, err := ReadDistributionInstallState(store)
	if err != nil || !have {
		t.Fatalf("active state missing after failure: have=%v err=%v", have, err)
	}
	if after != before {
		t.Fatalf("failed update changed active state: before=%#v after=%#v", before, after)
	}
}

func mustWriteLifecycleFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
}
