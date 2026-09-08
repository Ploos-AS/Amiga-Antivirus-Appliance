package evidencebundle

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	ArchiveManifestName      = "manifest.json"
	maxArchiveManifestBytes  = 4 << 20
	maxArchiveEntries        = 4096
)

var archiveTimestamp = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

// CreateArchive writes a deterministic, write-once ZIP transport containing the
// canonical manifest and exactly the evidence files named by it under root.
func CreateArchive(manifest Manifest, root, output string) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	if len(manifest.Entries) > maxArchiveEntries {
		return fmt.Errorf("too many evidence entries: %d", len(manifest.Entries))
	}
	for _, entry := range manifest.Entries {
		if entry.Name == ArchiveManifestName {
			return fmt.Errorf("evidence entry name %q is reserved", ArchiveManifestName)
		}
	}

	manifestBytes, err := manifest.MarshalDeterministic()
	if err != nil {
		return err
	}
	if len(manifestBytes) > maxArchiveManifestBytes {
		return errors.New("canonical manifest exceeds 4 MiB limit")
	}

	// Re-decode the canonical bytes so archive entry order exactly follows the
	// canonical manifest rather than caller-provided slice order.
	canonical, err := decodeManifestStrict(manifestBytes)
	if err != nil {
		return err
	}
	if err := canonical.VerifyFiles(root); err != nil {
		return err
	}

	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = f.Close()
		if remove {
			_ = os.Remove(output)
		}
	}()

	zw := zip.NewWriter(f)
	if err := writeArchiveBytes(zw, ArchiveManifestName, manifestBytes); err != nil {
		_ = zw.Close()
		return err
	}
	for _, entry := range canonical.Entries {
		path := filepath.Join(root, filepath.FromSlash(entry.Name))
		if err := writeArchiveFile(zw, entry, path); err != nil {
			_ = zw.Close()
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}

// VerifyArchive validates one portable evidence ZIP entirely offline and
// returns the canonical manifest. Nothing is extracted or executed.
func VerifyArchive(path string) (Manifest, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Manifest{}, err
	}
	if !info.Mode().IsRegular() {
		return Manifest{}, errors.New("evidence archive must be a regular file")
	}

	zr, err := zip.OpenReader(path)
	if err != nil {
		return Manifest{}, err
	}
	defer zr.Close()
	if len(zr.File) < 2 || len(zr.File) > maxArchiveEntries+1 {
		return Manifest{}, fmt.Errorf("unexpected archive entry count: %d", len(zr.File))
	}

	files := make(map[string]*zip.File, len(zr.File))
	for _, zf := range zr.File {
		if err := validateArchiveMember(zf); err != nil {
			return Manifest{}, err
		}
		if _, exists := files[zf.Name]; exists {
			return Manifest{}, fmt.Errorf("duplicate archive member %q", zf.Name)
		}
		files[zf.Name] = zf
	}

	manifestFile, ok := files[ArchiveManifestName]
	if !ok {
		return Manifest{}, errors.New("archive is missing manifest.json")
	}
	if manifestFile.UncompressedSize64 > maxArchiveManifestBytes {
		return Manifest{}, errors.New("archive manifest exceeds 4 MiB limit")
	}
	manifestBytes, err := readZipMemberBounded(manifestFile, int64(maxArchiveManifestBytes))
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	manifest, err := decodeManifestStrict(manifestBytes)
	if err != nil {
		return Manifest{}, err
	}
	if len(manifest.Entries)+1 != len(files) {
		return Manifest{}, errors.New("archive contains files not declared by manifest")
	}

	for _, entry := range manifest.Entries {
		zf, ok := files[entry.Name]
		if !ok {
			return Manifest{}, fmt.Errorf("archive is missing declared entry %q", entry.Name)
		}
		if zf.UncompressedSize64 != uint64(entry.Size) {
			return Manifest{}, fmt.Errorf("verify %q: size mismatch", entry.Name)
		}
		r, err := zf.Open()
		if err != nil {
			return Manifest{}, fmt.Errorf("verify %q: %w", entry.Name, err)
		}
		h := sha256.New()
		n, copyErr := io.Copy(h, io.LimitReader(r, entry.Size+1))
		closeErr := r.Close()
		if copyErr != nil {
			return Manifest{}, fmt.Errorf("verify %q: %w", entry.Name, copyErr)
		}
		if closeErr != nil {
			return Manifest{}, fmt.Errorf("verify %q: %w", entry.Name, closeErr)
		}
		if n != entry.Size {
			return Manifest{}, fmt.Errorf("verify %q: size mismatch", entry.Name)
		}
		if hex.EncodeToString(h.Sum(nil)) != entry.SHA256 {
			return Manifest{}, fmt.Errorf("verify %q: SHA-256 mismatch", entry.Name)
		}
	}
	return manifest, nil
}

func writeArchiveBytes(zw *zip.Writer, name string, data []byte) error {
	header := &zip.FileHeader{Name: name, Method: zip.Store}
	header.SetMode(0o640)
	header.Modified = archiveTimestamp
	w, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func writeArchiveFile(zw *zip.Writer, entry Entry, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	opened, err := f.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return fmt.Errorf("%q must remain the same regular file while opened", entry.Name)
	}
	if opened.Size() != entry.Size {
		return fmt.Errorf("%q changed size before archiving", entry.Name)
	}

	header := &zip.FileHeader{Name: entry.Name, Method: zip.Store}
	header.SetMode(0o640)
	header.Modified = archiveTimestamp
	w, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), f)
	if err != nil {
		return err
	}
	finished, err := f.Stat()
	if err != nil {
		return err
	}
	if n != entry.Size || finished.Size() != opened.Size() || !finished.ModTime().Equal(opened.ModTime()) {
		return fmt.Errorf("%q changed while archiving", entry.Name)
	}
	if hex.EncodeToString(h.Sum(nil)) != entry.SHA256 {
		return fmt.Errorf("%q SHA-256 no longer matches manifest", entry.Name)
	}
	return nil
}

func validateArchiveMember(zf *zip.File) error {
	name := zf.Name
	if name == ArchiveManifestName {
		// Reserved manifest name is the sole archive path outside evidence entries.
	} else if err := validatePortableName(name); err != nil {
		return fmt.Errorf("unsafe archive member %q: %w", name, err)
	}
	if strings.HasSuffix(name, "/") || zf.FileInfo().IsDir() {
		return fmt.Errorf("archive directories are forbidden: %q", name)
	}
	if !zf.FileInfo().Mode().IsRegular() {
		return fmt.Errorf("archive member is not a regular file: %q", name)
	}
	if zf.Method != zip.Store {
		return fmt.Errorf("archive member %q uses unsupported compression method %d", name, zf.Method)
	}
	return nil
}

func readZipMemberBounded(zf *zip.File, limit int64) ([]byte, error) {
	r, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("member exceeds size limit")
	}
	return data, nil
}

func decodeManifestStrict(data []byte) (Manifest, error) {
	var manifest Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return Manifest{}, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Manifest{}, errors.New("manifest contains trailing JSON data")
		}
		return Manifest{}, err
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// SortedEntries returns a copy in canonical name order. It is useful to callers
// that need deterministic presentation without mutating the manifest.
func (m Manifest) SortedEntries() []Entry {
	entries := append([]Entry(nil), m.Entries...)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Name == entries[j].Name {
			return entries[i].Kind < entries[j].Kind
		}
		return entries[i].Name < entries[j].Name
	})
	return entries
}
