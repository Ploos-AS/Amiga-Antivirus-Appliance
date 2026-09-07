package evidencebundle

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validEntry(name string, kind Kind, data []byte) Entry {
	return Entry{Name: name, Kind: kind, SHA256: digest(data), Size: int64(len(data))}
}

func TestBuildCanonicalizesAndMarshalsDeterministically(t *testing.T) {
	created := time.Date(2026, 9, 8, 0, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
	entries := []Entry{
		validEntry("reports/scan.json", KindScanReport, []byte("scan")),
		validEntry("artifacts/disk.adf", KindArtifact, []byte("disk")),
	}
	rels := []Relationship{{From: "reports/scan.json", To: "artifacts/disk.adf", Type: "describes"}}
	m, err := Build("0.13.0-dev", created, "case 1", entries, rels)
	if err != nil {
		t.Fatal(err)
	}
	if m.Entries[0].Name != "artifacts/disk.adf" || m.CreatedAt.Location() != time.UTC {
		t.Fatalf("manifest was not canonicalized: %+v", m)
	}
	first, err := m.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("deterministic serialization changed between calls")
	}
	if !strings.HasSuffix(string(first), "\n") {
		t.Fatal("canonical manifest must end with newline")
	}
	if strings.Index(string(first), "artifacts/disk.adf") > strings.Index(string(first), "reports/scan.json") {
		t.Fatal("entries are not serialized in canonical name order")
	}
}

func TestValidateRejectsUnsafeNamesDuplicatesAndUnsupportedKinds(t *testing.T) {
	base := validEntry("evidence/a.bin", KindArtifact, []byte("x"))
	for _, name := range []string{"/etc/passwd", "../escape", "evidence/../escape", "evidence\\a.bin", "evidence//a.bin", " ./a"} {
		e := base
		e.Name = name
		if err := e.Validate(); err == nil {
			t.Fatalf("unsafe name %q was accepted", name)
		}
	}

	badKind := base
	badKind.Kind = Kind("unknown")
	if err := badKind.Validate(); err == nil {
		t.Fatal("unsupported kind was accepted")
	}

	m := Manifest{Schema: Schema, CreatedAt: time.Now().UTC(), AAAVersion: "test", Entries: []Entry{base, base}}
	if err := m.Validate(); err == nil {
		t.Fatal("duplicate entry name was accepted")
	}
}

func TestValidateRejectsBadHashSizeSchemaAndRelationships(t *testing.T) {
	entry := validEntry("artifact.bin", KindArtifact, []byte("data"))

	badHash := entry
	badHash.SHA256 = strings.Repeat("A", 64)
	if err := badHash.Validate(); err == nil {
		t.Fatal("uppercase hash was accepted")
	}

	badSize := entry
	badSize.Size = -1
	if err := badSize.Validate(); err == nil {
		t.Fatal("negative size was accepted")
	}

	m := Manifest{Schema: "aaa-evidence-bundle-v99", CreatedAt: time.Now().UTC(), AAAVersion: "test", Entries: []Entry{entry}}
	if err := m.Validate(); err == nil {
		t.Fatal("unsupported schema was accepted")
	}

	m.Schema = Schema
	m.Relationships = []Relationship{{From: "artifact.bin", To: "missing.json", Type: "describes"}}
	if err := m.Validate(); err == nil {
		t.Fatal("relationship to missing entry was accepted")
	}
}

func TestVerifyFilesAcceptsExactBytesAndRejectsTampering(t *testing.T) {
	root := t.TempDir()
	artifact := []byte("amiga evidence")
	report := []byte(`{"verdict":"unknown"}`)
	if err := os.MkdirAll(filepath.Join(root, "artifacts"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "reports"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "artifacts", "disk.adf"), artifact, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "reports", "scan.json"), report, 0o640); err != nil {
		t.Fatal(err)
	}
	m, err := Build("test", time.Now().UTC(), "", []Entry{
		validEntry("artifacts/disk.adf", KindArtifact, artifact),
		validEntry("reports/scan.json", KindScanReport, report),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.VerifyFiles(root); err != nil {
		t.Fatalf("valid evidence failed verification: %v", err)
	}

	if err := os.WriteFile(filepath.Join(root, "reports", "scan.json"), []byte(`{"verdict":"clean"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := m.VerifyFiles(root); err == nil {
		t.Fatal("tampered evidence was accepted")
	}
}

func TestVerifyFilesRejectsMissingAndSymlinkEntries(t *testing.T) {
	root := t.TempDir()
	data := []byte("same")
	entry := validEntry("artifact.bin", KindArtifact, data)
	m, err := Build("test", time.Now().UTC(), "", []Entry{entry}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.VerifyFiles(root); err == nil {
		t.Fatal("missing entry was accepted")
	}

	target := filepath.Join(root, "target.bin")
	if err := os.WriteFile(target, data, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "artifact.bin")); err != nil {
		t.Fatal(err)
	}
	if err := m.VerifyFiles(root); err == nil {
		t.Fatal("symlink evidence entry was accepted")
	}
}

func TestManifestDoesNotNeedOrSerializeHostPaths(t *testing.T) {
	entry := validEntry("artifacts/disk.adf", KindArtifact, []byte("disk"))
	m, err := Build("test", time.Now().UTC(), "", []Entry{entry}, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := m.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "/data/aaa/") || strings.Contains(string(data), `"path"`) {
		t.Fatalf("portable manifest leaked a host path field: %s", data)
	}
}

func TestNoSCPToADFDerivationIsInferred(t *testing.T) {
	flux := validEntry("acquisition/disk.scp", KindRawFlux, []byte("flux"))
	adf := validEntry("acquisition/disk.read-01.adf", KindArtifact, []byte("adf"))
	m, err := Build("test", time.Now().UTC(), "", []Entry{flux, adf}, []Relationship{
		{From: flux.Name, To: adf.Name, Type: "same-operator-session; no SCP-to-ADF derivation asserted"},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := m.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "no SCP-to-ADF derivation asserted") {
		t.Fatalf("explicit no-derivation relationship was lost: %s", data)
	}
}
