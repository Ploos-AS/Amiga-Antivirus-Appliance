package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidencebundle"
)

func TestRunEvidenceCreateAndVerify(t *testing.T) {
	root := t.TempDir()
	artifactDir := filepath.Join(root, "artifacts")
	if err := os.MkdirAll(artifactDir, 0o750); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(artifactDir, "disk.adf")
	if err := os.WriteFile(artifact, []byte("amiga evidence"), 0o640); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "evidence.json")
	created := time.Date(2026, 9, 8, 1, 0, 0, 0, time.UTC)
	var createOut bytes.Buffer
	if err := runEvidenceCreate([]string{
		"--output", manifestPath,
		"--note", "drawer A",
		"--entry", "artifact:artifacts/disk.adf:" + artifact,
	}, &createOut, &bytes.Buffer{}, func() time.Time { return created }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(createOut.String(), "manifest-sha256=") {
		t.Fatalf("create output=%q", createOut.String())
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest evidencebundle.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != evidencebundle.Schema || manifest.CreatedAt != created || len(manifest.Entries) != 1 {
		t.Fatalf("manifest=%+v", manifest)
	}
	if strings.Contains(string(data), root) || strings.Contains(string(data), `"path"`) {
		t.Fatalf("portable manifest leaked host path: %s", data)
	}

	var verifyOut bytes.Buffer
	if err := runEvidenceVerify([]string{manifestPath}, &verifyOut, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verifyOut.String(), "verified evidence manifest") {
		t.Fatalf("verify output=%q", verifyOut.String())
	}
}

func TestRunEvidenceCreateIsWriteOnce(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(source, []byte("sample"), 0o640); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte("keep"), 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceCreate([]string{"--output", manifestPath, "--entry", "artifact:sample.bin:" + source}, &bytes.Buffer{}, &bytes.Buffer{}, time.Now); err == nil {
		t.Fatal("existing manifest was overwritten")
	}
	after, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("existing manifest changed: before=%q after=%q", before, after)
	}
}

func TestRunEvidenceVerifyDetectsTampering(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(source, []byte("original"), 0o640); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	if err := runEvidenceCreate([]string{"--output", manifestPath, "--entry", "artifact:sample.bin:" + source}, &bytes.Buffer{}, &bytes.Buffer{}, time.Now); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("tampered"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceVerify([]string{manifestPath}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("tampered evidence verified")
	}
}

func TestEvidenceEntryRejectsUnsafePortableNameAndSymlinkSource(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.bin")
	if err := os.WriteFile(target, []byte("data"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := evidenceEntryFromSpec("artifact:../escape:" + target); err == nil {
		t.Fatal("unsafe portable name accepted")
	}
	link := filepath.Join(root, "link.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := evidenceEntryFromSpec("artifact:artifact.bin:" + link); err == nil {
		t.Fatal("symlink source accepted")
	}
}

func TestReadEvidenceManifestRejectsUnknownFieldsAndOversize(t *testing.T) {
	root := t.TempDir()
	unknown := filepath.Join(root, "unknown.json")
	if err := os.WriteFile(unknown, []byte(`{"schema":"aaa-evidence-bundle-v1","created_at":"2026-09-08T00:00:00Z","aaa_version":"test","entries":[],"surprise":true}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readEvidenceManifest(unknown); err == nil {
		t.Fatal("unknown manifest field accepted")
	}

	oversize := filepath.Join(root, "oversize.json")
	if err := os.WriteFile(oversize, bytes.Repeat([]byte("x"), maxEvidenceManifestBytes+1), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readEvidenceManifest(oversize); err == nil {
		t.Fatal("oversize manifest accepted")
	}
}

func TestReadEvidenceManifestRejectsTrailingJSON(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "trailing.json")
	data := `{"schema":"aaa-evidence-bundle-v1","created_at":"2026-09-08T00:00:00Z","aaa_version":"test","entries":[{"name":"a","kind":"artifact","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":0}]} {}`
	if err := os.WriteFile(path, []byte(data), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readEvidenceManifest(path); err == nil {
		t.Fatal("trailing JSON data accepted")
	}
}

func TestRunEvidencePackAndVerifyBundle(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "artifacts"), 0o750); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(root, "artifacts", "disk.adf")
	if err := os.WriteFile(artifact, []byte("amiga evidence"), 0o640); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "case.json")
	if err := runEvidenceCreate([]string{
		"--output", manifestPath,
		"--entry", "artifact:artifacts/disk.adf:" + artifact,
	}, &bytes.Buffer{}, &bytes.Buffer{}, time.Now); err != nil {
		t.Fatal(err)
	}

	bundlePath := filepath.Join(t.TempDir(), "case.aaa-evidence.zip")
	var packOut bytes.Buffer
	if err := runEvidencePack([]string{
		"--manifest", manifestPath,
		"--root", root,
		"--output", bundlePath,
	}, &packOut, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(packOut.String(), "packed evidence bundle") || !strings.Contains(packOut.String(), "sha256=") {
		t.Fatalf("pack output=%q", packOut.String())
	}

	var verifyOut bytes.Buffer
	if err := runEvidenceVerifyBundle([]string{bundlePath}, &verifyOut, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verifyOut.String(), "verified evidence bundle") || !strings.Contains(verifyOut.String(), "entries=1") {
		t.Fatalf("verify-bundle output=%q", verifyOut.String())
	}
}

func TestRunEvidencePackIsWriteOnce(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(source, []byte("sample"), 0o640); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	if err := runEvidenceCreate([]string{"--output", manifestPath, "--entry", "artifact:sample.bin:" + source}, &bytes.Buffer{}, &bytes.Buffer{}, time.Now); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(t.TempDir(), "bundle.zip")
	if err := os.WriteFile(bundle, []byte("keep"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := runEvidencePack([]string{"--manifest", manifestPath, "--root", root, "--output", bundle}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("existing bundle was overwritten")
	}
	got, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep" {
		t.Fatalf("existing bundle changed: %q", got)
	}
}
