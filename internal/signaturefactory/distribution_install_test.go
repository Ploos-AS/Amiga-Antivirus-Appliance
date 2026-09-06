package signaturefactory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallDistributionBundleStagesVerifiesAndActivates(t *testing.T) {
	bundleRoot, manifest, trusted, _ := writeDistributionBundleFixture(t)
	storeRoot := filepath.Join(t.TempDir(), "signatures")

	state, err := InstallDistributionBundle(bundleRoot, storeRoot, trusted)
	if err != nil {
		t.Fatalf("install bundle: %v", err)
	}
	wantIdentity, err := manifest.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != manifest.Version || state.ManifestSHA256 != wantIdentity {
		t.Fatalf("unexpected install state: %+v", state)
	}

	currentBytes, err := os.ReadFile(filepath.Join(storeRoot, DistributionStateFilename))
	if err != nil {
		t.Fatal(err)
	}
	current, err := DecodeDistributionInstallStateStrict(currentBytes)
	if err != nil {
		t.Fatalf("decode current state: %v", err)
	}
	if current != state {
		t.Fatalf("current state differs: got %+v want %+v", current, state)
	}

	installedRoot := filepath.Join(storeRoot, "distributions", manifest.Version)
	installed, identity, err := VerifyDistributionBundle(installedRoot, trusted)
	if err != nil {
		t.Fatalf("verify installed bundle: %v", err)
	}
	if installed.Version != manifest.Version || identity != wantIdentity {
		t.Fatalf("installed bundle differs: version=%q identity=%q", installed.Version, identity)
	}
}

func TestInstallDistributionBundleExactReinstallIsIdempotent(t *testing.T) {
	bundleRoot, _, trusted, _ := writeDistributionBundleFixture(t)
	storeRoot := filepath.Join(t.TempDir(), "signatures")
	first, err := InstallDistributionBundle(bundleRoot, storeRoot, trusted)
	if err != nil {
		t.Fatal(err)
	}
	currentPath := filepath.Join(storeRoot, DistributionStateFilename)
	before, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatal(err)
	}

	second, err := InstallDistributionBundle(bundleRoot, storeRoot, trusted)
	if err != nil {
		t.Fatalf("exact reinstall: %v", err)
	}
	after, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || string(before) != string(after) {
		t.Fatalf("exact reinstall changed active state: first=%+v second=%+v", first, second)
	}
}

func TestInstallDistributionBundleRejectsDowngradeAndPreservesCurrent(t *testing.T) {
	bundleRoot, manifest, trusted, privateKey := writeDistributionBundleFixture(t)
	storeRoot := filepath.Join(t.TempDir(), "signatures")

	manifest.Version = "2.0.0"
	resignDistributionBundleManifest(t, bundleRoot, &manifest, privateKey)
	active, err := InstallDistributionBundle(bundleRoot, storeRoot, trusted)
	if err != nil {
		t.Fatalf("install newer release: %v", err)
	}
	currentPath := filepath.Join(storeRoot, DistributionStateFilename)
	before, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatal(err)
	}

	manifest.Version = "1.9.9"
	resignDistributionBundleManifest(t, bundleRoot, &manifest, privateKey)
	if _, err := InstallDistributionBundle(bundleRoot, storeRoot, trusted); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("expected downgrade rejection, got %v", err)
	}
	after, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("downgrade attempt changed current state")
	}
	decoded, err := DecodeDistributionInstallStateStrict(after)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != active {
		t.Fatalf("active state changed after downgrade rejection: got %+v want %+v", decoded, active)
	}
}

func TestInstallDistributionBundleRejectsSameVersionDifferentIdentity(t *testing.T) {
	bundleRoot, manifest, trusted, privateKey := writeDistributionBundleFixture(t)
	storeRoot := filepath.Join(t.TempDir(), "signatures")
	first, err := InstallDistributionBundle(bundleRoot, storeRoot, trusted)
	if err != nil {
		t.Fatal(err)
	}
	currentPath := filepath.Join(storeRoot, DistributionStateFilename)
	before, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatal(err)
	}

	changedPayload := []byte("changed bootblock database\n")
	if err := os.WriteFile(filepath.Join(bundleRoot, "aaa", "bootblocks.json"), changedPayload, 0o640); err != nil {
		t.Fatal(err)
	}
	setPayloadFixtureMetadata(t, &manifest, DistributionTargetAAABootblocks, changedPayload)
	resignDistributionBundleManifest(t, bundleRoot, &manifest, privateKey)
	if _, err := InstallDistributionBundle(bundleRoot, storeRoot, trusted); err == nil || !strings.Contains(err.Error(), "different manifest identity") {
		t.Fatalf("expected same-version identity rejection, got %v", err)
	}
	after, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("same-version conflict changed current state")
	}
	current, err := DecodeDistributionInstallStateStrict(after)
	if err != nil {
		t.Fatal(err)
	}
	if current != first {
		t.Fatalf("current state changed after same-version conflict: got %+v want %+v", current, first)
	}
}

func TestInstallDistributionBundleRejectsCorruptExistingVersionWithoutActivation(t *testing.T) {
	bundleRoot, manifest, trusted, privateKey := writeDistributionBundleFixture(t)
	storeRoot := filepath.Join(t.TempDir(), "signatures")
	if _, err := InstallDistributionBundle(bundleRoot, storeRoot, trusted); err != nil {
		t.Fatal(err)
	}
	currentPath := filepath.Join(storeRoot, DistributionStateFilename)
	before, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatal(err)
	}

	manifest.Version = "1.2.4"
	resignDistributionBundleManifest(t, bundleRoot, &manifest, privateKey)
	badRoot := filepath.Join(storeRoot, "distributions", manifest.Version)
	if err := os.MkdirAll(badRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badRoot, DistributionManifestFilename), []byte("not a manifest\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallDistributionBundle(bundleRoot, storeRoot, trusted); err == nil || !strings.Contains(err.Error(), "verify existing distribution") {
		t.Fatalf("expected corrupt existing version rejection, got %v", err)
	}
	after, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("corrupt existing version changed current state")
	}
}

func TestDecodeDistributionInstallStateStrictRejectsNonCanonicalUnknownAndTrailing(t *testing.T) {
	state := DistributionInstallState{
		Schema:         DistributionInstallStateSchema,
		Version:        "1.2.3",
		ManifestSHA256: strings.Repeat("ab", 32),
	}
	canonical, err := state.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDistributionInstallStateStrict(canonical); err != nil {
		t.Fatalf("canonical state rejected: %v", err)
	}
	if _, err := DecodeDistributionInstallStateStrict(append([]byte(" "), canonical...)); err == nil {
		t.Fatal("expected non-canonical state rejection")
	}
	unknown := []byte(`{"schema":1,"version":"1.2.3","manifest_sha256":"` + strings.Repeat("ab", 32) + `","unknown":true}` + "\n")
	if _, err := DecodeDistributionInstallStateStrict(unknown); err == nil {
		t.Fatal("expected unknown field rejection")
	}
	trailing := append(append([]byte(nil), canonical...), []byte("{}")...)
	if _, err := DecodeDistributionInstallStateStrict(trailing); err == nil {
		t.Fatal("expected trailing data rejection")
	}
}
