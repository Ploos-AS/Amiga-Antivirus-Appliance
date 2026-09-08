package evidencebundle

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func archiveDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func testArchiveManifest(t *testing.T, root string) Manifest {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "artifacts"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "reports"), 0o750); err != nil {
		t.Fatal(err)
	}
	artifact := []byte("amiga-disk")
	report := []byte(`{"verdict":"unknown"}`)
	if err := os.WriteFile(filepath.Join(root, "artifacts", "disk.adf"), artifact, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "reports", "scan.json"), report, 0o640); err != nil {
		t.Fatal(err)
	}
	m, err := Build("test", time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC), "drawer A", []Entry{
		{Name: "reports/scan.json", Kind: KindScanReport, SHA256: archiveDigest(report), Size: int64(len(report))},
		{Name: "artifacts/disk.adf", Kind: KindArtifact, SHA256: archiveDigest(artifact), Size: int64(len(artifact))},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCreateAndVerifyArchive(t *testing.T) {
	root := t.TempDir()
	manifest := testArchiveManifest(t, root)
	archive := filepath.Join(t.TempDir(), "case.aaa-evidence.zip")
	if err := CreateArchive(manifest, root, archive); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyArchive(archive)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Schema != Schema || len(verified.Entries) != 2 || verified.Note != "drawer A" {
		t.Fatalf("verified manifest=%+v", verified)
	}

	zr, err := zip.OpenReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	want := []string{"manifest.json", "artifacts/disk.adf", "reports/scan.json"}
	if len(zr.File) != len(want) {
		t.Fatalf("archive entries=%d", len(zr.File))
	}
	for i, name := range want {
		if zr.File[i].Name != name {
			t.Fatalf("entry %d=%q want %q", i, zr.File[i].Name, name)
		}
		if zr.File[i].Method != zip.Store {
			t.Fatalf("entry %q compressed unexpectedly", name)
		}
	}
}

func TestCreateArchiveDeterministicAndWriteOnce(t *testing.T) {
	root := t.TempDir()
	manifest := testArchiveManifest(t, root)
	first := filepath.Join(t.TempDir(), "a.zip")
	second := filepath.Join(t.TempDir(), "b.zip")
	if err := CreateArchive(manifest, root, first); err != nil {
		t.Fatal(err)
	}
	if err := CreateArchive(manifest, root, second); err != nil {
		t.Fatal(err)
	}
	a, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("same evidence produced different archive bytes")
	}
	if err := CreateArchive(manifest, root, first); err == nil {
		t.Fatal("existing archive was overwritten")
	}
}

func TestVerifyArchiveRejectsTamperedAndExtraMembers(t *testing.T) {
	root := t.TempDir()
	manifest := testArchiveManifest(t, root)
	archive := filepath.Join(t.TempDir(), "case.zip")
	if err := CreateArchive(manifest, root, archive); err != nil {
		t.Fatal(err)
	}

	bad := filepath.Join(t.TempDir(), "bad.zip")
	f, err := os.OpenFile(bad, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	manifestBytes, err := manifest.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeArchiveBytes(zw, ArchiveManifestName, manifestBytes); err != nil {
		t.Fatal(err)
	}
	if err := writeArchiveBytes(zw, "artifacts/disk.adf", []byte("tampered!")); err != nil {
		t.Fatal(err)
	}
	if err := writeArchiveBytes(zw, "reports/scan.json", []byte(`{"verdict":"unknown"}`)); err != nil {
		t.Fatal(err)
	}
	if err := writeArchiveBytes(zw, "extra.txt", []byte("extra")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyArchive(bad); err == nil {
		t.Fatal("archive with undeclared extra/tampered data verified")
	}
}

func TestVerifyArchiveRejectsUnsafeCompressedAndDuplicateMembers(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(*testing.T, *zip.Writer)
	}{
		{name: "unsafe path", make: func(t *testing.T, zw *zip.Writer) {
			t.Helper()
			if err := writeArchiveBytes(zw, "../escape", []byte("x")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "duplicate manifest", make: func(t *testing.T, zw *zip.Writer) {
			t.Helper()
			if err := writeArchiveBytes(zw, ArchiveManifestName, []byte("{}")); err != nil {
				t.Fatal(err)
			}
			if err := writeArchiveBytes(zw, ArchiveManifestName, []byte("{}")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "compressed", make: func(t *testing.T, zw *zip.Writer) {
			t.Helper()
			h := &zip.FileHeader{Name: "x.bin", Method: zip.Deflate}
			h.SetMode(0o640)
			w, err := zw.CreateHeader(h)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bad.zip")
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
			if err != nil {
				t.Fatal(err)
			}
			zw := zip.NewWriter(f)
			tc.make(t, zw)
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyArchive(path); err == nil {
				t.Fatal("unsafe archive verified")
			}
		})
	}
}

func TestCreateArchiveRejectsReservedManifestEntryAndSymlinkSource(t *testing.T) {
	root := t.TempDir()
	data := []byte("x")
	if err := os.WriteFile(filepath.Join(root, "target"), data, 0o640); err != nil {
		t.Fatal(err)
	}
	reserved, err := Build("test", time.Now().UTC(), "", []Entry{{Name: ArchiveManifestName, Kind: KindArtifact, SHA256: archiveDigest(data), Size: 1}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := CreateArchive(reserved, root, filepath.Join(t.TempDir(), "reserved.zip")); err == nil {
		t.Fatal("reserved manifest name accepted as evidence entry")
	}

	if err := os.Symlink(filepath.Join(root, "target"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	linked, err := Build("test", time.Now().UTC(), "", []Entry{{Name: "link", Kind: KindArtifact, SHA256: archiveDigest(data), Size: 1}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := CreateArchive(linked, root, filepath.Join(t.TempDir(), "linked.zip")); err == nil {
		t.Fatal("symlink evidence source accepted")
	}
}
