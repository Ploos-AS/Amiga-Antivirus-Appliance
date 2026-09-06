package signaturefactory

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDistributionReleaseArchiveDeterministicAndVerifiable(t *testing.T) {
	bundleRoot, manifest, trusted, _ := writeDistributionBundleFixture(t)
	name := DistributionArchivePrefix + manifest.Version + DistributionArchiveSuffix
	archiveA := filepath.Join(t.TempDir(), name)
	archiveB := filepath.Join(t.TempDir(), name)

	gotManifest, digestA, err := BuildDistributionReleaseArchive(bundleRoot, archiveA, trusted)
	if err != nil {
		t.Fatalf("build first archive: %v", err)
	}
	if gotManifest.Version != manifest.Version {
		t.Fatalf("archive manifest version=%q want %q", gotManifest.Version, manifest.Version)
	}
	_, digestB, err := BuildDistributionReleaseArchive(bundleRoot, archiveB, trusted)
	if err != nil {
		t.Fatalf("build second archive: %v", err)
	}
	dataA, err := os.ReadFile(archiveA)
	if err != nil {
		t.Fatal(err)
	}
	dataB, err := os.ReadFile(archiveB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dataA, dataB) || digestA != digestB {
		t.Fatalf("release archives are not deterministic: %s != %s", digestA, digestB)
	}

	entries := readDistributionArchiveHeaders(t, archiveA)
	want := []string{"aaa/bootblocks.json", "clamav/aaa.hsb", "manifest.json", "manifest.sig"}
	if strings.Join(entries, "\n") != strings.Join(want, "\n") {
		t.Fatalf("archive entries=%v want %v", entries, want)
	}

	checksum, expectedDigest, err := DistributionArchiveChecksumBytes(archiveA)
	if err != nil {
		t.Fatal(err)
	}
	if expectedDigest != digestA {
		t.Fatalf("checksum digest=%q archive digest=%q", expectedDigest, digestA)
	}
	if _, err := VerifyDistributionArchiveChecksum(archiveA, checksum); err != nil {
		t.Fatalf("verify transport checksum: %v", err)
	}

	extracted := filepath.Join(t.TempDir(), "extracted")
	extractedManifest, err := ExtractDistributionReleaseArchive(archiveA, extracted)
	if err != nil {
		t.Fatalf("extract release archive: %v", err)
	}
	if extractedManifest.Version != manifest.Version {
		t.Fatalf("extracted version=%q want %q", extractedManifest.Version, manifest.Version)
	}
	if _, _, err := VerifyDistributionBundle(extracted, trusted); err != nil {
		t.Fatalf("verify extracted M7.4 bundle: %v", err)
	}
}

func TestDistributionReleaseArchiveRejectsUnsafeEntries(t *testing.T) {
	cases := []struct {
		name     string
		entry    string
		typeflag byte
		want     string
	}{
		{name: "traversal", entry: "../manifest.json", typeflag: tar.TypeReg, want: "unsafe"},
		{name: "unexpected", entry: "extra.txt", typeflag: tar.TypeReg, want: "unexpected"},
		{name: "symlink", entry: "manifest.json", typeflag: tar.TypeSymlink, want: "not a regular file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			archivePath := filepath.Join(t.TempDir(), DistributionArchivePrefix+"1.2.3"+DistributionArchiveSuffix)
			writeSyntheticArchive(t, archivePath, []syntheticArchiveEntry{{name: tc.entry, typeflag: tc.typeflag, data: []byte("x")}})
			_, err := ExtractDistributionReleaseArchive(archivePath, filepath.Join(t.TempDir(), "out"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q rejection, got %v", tc.want, err)
			}
		})
	}
}

func TestDistributionReleaseArchiveRejectsDuplicateAndMissingEntries(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), DistributionArchivePrefix+"1.2.3"+DistributionArchiveSuffix)
	writeSyntheticArchive(t, archivePath, []syntheticArchiveEntry{
		{name: "manifest.json", typeflag: tar.TypeReg, data: []byte("{}\n")},
		{name: "manifest.json", typeflag: tar.TypeReg, data: []byte("{}\n")},
	})
	if _, err := ExtractDistributionReleaseArchive(archivePath, filepath.Join(t.TempDir(), "out")); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate rejection, got %v", err)
	}

	archivePath = filepath.Join(t.TempDir(), DistributionArchivePrefix+"1.2.3"+DistributionArchiveSuffix)
	writeSyntheticArchive(t, archivePath, []syntheticArchiveEntry{{name: "manifest.json", typeflag: tar.TypeReg, data: []byte("{}\n")}})
	if _, err := ExtractDistributionReleaseArchive(archivePath, filepath.Join(t.TempDir(), "out")); err == nil || !strings.Contains(err.Error(), "missing required") {
		t.Fatalf("expected missing-entry rejection, got %v", err)
	}
}

func TestDistributionReleaseVersionAgreementAndChecksumFailure(t *testing.T) {
	bundleRoot, manifest, trusted, _ := writeDistributionBundleFixture(t)
	wrongName := filepath.Join(t.TempDir(), DistributionArchivePrefix+"9.9.9"+DistributionArchiveSuffix)
	if _, _, err := BuildDistributionReleaseArchive(bundleRoot, wrongName, trusted); err == nil || !strings.Contains(err.Error(), "filename") {
		t.Fatalf("expected archive/manifest version mismatch, got %v", err)
	}
	if err := ValidateDistributionReleaseVersionAgreement("9.9.9", DistributionArchivePrefix+"9.9.9"+DistributionArchiveSuffix, manifest); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected requested/manifest mismatch, got %v", err)
	}

	archivePath := filepath.Join(t.TempDir(), DistributionArchivePrefix+manifest.Version+DistributionArchiveSuffix)
	if _, _, err := BuildDistributionReleaseArchive(bundleRoot, archivePath, trusted); err != nil {
		t.Fatal(err)
	}
	checksum, _, err := DistributionArchiveChecksumBytes(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if checksum[0] == '0' {
		checksum[0] = '1'
	} else {
		checksum[0] = '0'
	}
	if _, err := VerifyDistributionArchiveChecksum(archivePath, checksum); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected checksum mismatch, got %v", err)
	}
}

func TestDistributionArchiveChecksumStrictFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), DistributionArchivePrefix+"1.2.3"+DistributionArchiveSuffix)
	data := []byte("archive")
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	for _, bad := range [][]byte{
		[]byte(digest + "  " + filepath.Base(path)),
		[]byte(strings.ToUpper(digest) + "  " + filepath.Base(path) + "\n"),
		[]byte(digest + "  wrong.tar.gz\n"),
		[]byte(digest + " " + filepath.Base(path) + "\n"),
	} {
		if _, err := VerifyDistributionArchiveChecksum(path, bad); err == nil {
			t.Fatalf("expected strict checksum rejection for %q", bad)
		}
	}
}

func readDistributionArchiveHeaders(t *testing.T, path string) []string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var names []string
	for {
		header, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		names = append(names, header.Name)
		if header.Mode != 0o644 || header.Uid != 0 || header.Gid != 0 {
			t.Fatalf("non-normalized header for %q: mode=%o uid=%d gid=%d", header.Name, header.Mode, header.Uid, header.Gid)
		}
	}
	return names
}

type syntheticArchiveEntry struct {
	name     string
	typeflag byte
	data     []byte
}

func writeSyntheticArchive(t *testing.T, path string, entries []syntheticArchiveEntry) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	gz.Header.ModTime = time.Unix(0, 0).UTC()
	tr := tar.NewWriter(gz)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Typeflag: entry.typeflag, Mode: 0o644, ModTime: time.Unix(0, 0).UTC()}
		if entry.typeflag == tar.TypeReg || entry.typeflag == tar.TypeRegA {
			header.Size = int64(len(entry.data))
		}
		if entry.typeflag == tar.TypeSymlink {
			header.Linkname = "target"
		}
		if err := tr.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := tr.Write(entry.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
