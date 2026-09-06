package signaturefactory

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	DistributionArchivePrefix          = "aaa-signatures-"
	DistributionArchiveSuffix          = ".tar.gz"
	DistributionArchiveChecksumSuffix  = ".sha256"
	maxDistributionArchiveEntryBytes   = int64(64 << 20)
	maxDistributionArchiveExpandedSize = int64(128 << 20)
)

var distributionArchivePaths = []string{
	"aaa/bootblocks.json",
	"clamav/aaa.hsb",
	DistributionManifestFilename,
	DistributionSignatureFilename,
}

// BuildDistributionReleaseArchive verifies a signed M7.4 bundle and packages
// exactly its four logical files into a deterministic tar.gz transport archive.
func BuildDistributionReleaseArchive(bundleRoot, outputPath string, trusted *TrustedDistributionKeys) (DistributionManifest, string, error) {
	if outputPath == "" {
		return DistributionManifest{}, "", errors.New("distribution archive output is required")
	}
	manifest, _, err := VerifyDistributionBundle(bundleRoot, trusted)
	if err != nil {
		return DistributionManifest{}, "", err
	}
	if err := ValidateDistributionReleaseVersionAgreement(manifest.Version, outputPath, manifest); err != nil {
		return DistributionManifest{}, "", err
	}
	if _, err := os.Lstat(outputPath); err == nil {
		return DistributionManifest{}, "", errors.New("distribution archive output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return DistributionManifest{}, "", fmt.Errorf("stat distribution archive output: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o750); err != nil {
		return DistributionManifest{}, "", fmt.Errorf("create distribution archive parent: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(outputPath), ".distribution-archive-*.tmp")
	if err != nil {
		return DistributionManifest{}, "", err
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		_ = tmp.Close()
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()

	gzipWriter, err := gzip.NewWriterLevel(tmp, gzip.BestCompression)
	if err != nil {
		return DistributionManifest{}, "", err
	}
	releaseTime := manifest.CreatedAt.UTC().Truncate(time.Second)
	gzipWriter.Header.ModTime = releaseTime
	gzipWriter.Header.OS = 255
	gzipWriter.Header.Name = ""
	gzipWriter.Header.Comment = ""
	tarWriter := tar.NewWriter(gzipWriter)

	for _, relative := range distributionArchivePaths {
		fullPath, err := secureDistributionPath(bundleRoot, relative)
		if err != nil {
			return DistributionManifest{}, "", err
		}
		file, err := os.Open(fullPath)
		if err != nil {
			return DistributionManifest{}, "", err
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return DistributionManifest{}, "", err
		}
		if !info.Mode().IsRegular() {
			_ = file.Close()
			return DistributionManifest{}, "", fmt.Errorf("distribution archive entry %q must be a regular file", relative)
		}
		header := &tar.Header{
			Name:       relative,
			Mode:       0o644,
			Size:       info.Size(),
			ModTime:    releaseTime,
			Typeflag:   tar.TypeReg,
			Uid:        0,
			Gid:        0,
			Uname:      "",
			Gname:      "",
			AccessTime: time.Time{},
			ChangeTime: time.Time{},
			Format:     tar.FormatUSTAR,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			_ = file.Close()
			return DistributionManifest{}, "", err
		}
		if _, err := io.Copy(tarWriter, file); err != nil {
			_ = file.Close()
			return DistributionManifest{}, "", err
		}
		if err := file.Close(); err != nil {
			return DistributionManifest{}, "", err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return DistributionManifest{}, "", err
	}
	if err := gzipWriter.Close(); err != nil {
		return DistributionManifest{}, "", err
	}
	if err := tmp.Sync(); err != nil {
		return DistributionManifest{}, "", err
	}
	if err := tmp.Close(); err != nil {
		return DistributionManifest{}, "", err
	}
	if err := os.Rename(tmpPath, outputPath); err != nil {
		return DistributionManifest{}, "", err
	}
	keep = true
	if err := syncDirectory(filepath.Dir(outputPath)); err != nil {
		return DistributionManifest{}, "", err
	}
	digest, _, err := regularFileSHA256(outputPath)
	if err != nil {
		return DistributionManifest{}, "", err
	}
	return manifest, digest, nil
}

// ExtractDistributionReleaseArchive extracts an archive into a fresh directory,
// accepting exactly the M7.4 logical files and rejecting unsafe archive entries.
func ExtractDistributionReleaseArchive(archivePath, outputRoot string) (DistributionManifest, error) {
	if archivePath == "" || outputRoot == "" {
		return DistributionManifest{}, errors.New("distribution archive path and extraction root are required")
	}
	if _, err := os.Lstat(outputRoot); err == nil {
		return DistributionManifest{}, errors.New("distribution extraction root already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return DistributionManifest{}, fmt.Errorf("stat distribution extraction root: %w", err)
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return DistributionManifest{}, err
	}
	defer archive.Close()
	info, err := archive.Stat()
	if err != nil {
		return DistributionManifest{}, err
	}
	if !info.Mode().IsRegular() {
		return DistributionManifest{}, errors.New("distribution archive must be a regular file")
	}
	gzipReader, err := gzip.NewReader(bufio.NewReader(archive))
	if err != nil {
		return DistributionManifest{}, fmt.Errorf("open distribution gzip stream: %w", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)

	if err := os.MkdirAll(outputRoot, 0o750); err != nil {
		return DistributionManifest{}, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(outputRoot)
		}
	}()

	allowed := make(map[string]struct{}, len(distributionArchivePaths))
	for _, path := range distributionArchivePaths {
		allowed[path] = struct{}{}
	}
	seen := make(map[string]struct{}, len(allowed))
	var expanded int64
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return DistributionManifest{}, fmt.Errorf("read distribution archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return DistributionManifest{}, fmt.Errorf("distribution archive entry %q is not a regular file", header.Name)
		}
		if err := validateDistributionArchivePath(header.Name); err != nil {
			return DistributionManifest{}, err
		}
		if _, ok := allowed[header.Name]; !ok {
			return DistributionManifest{}, fmt.Errorf("unexpected distribution archive entry %q", header.Name)
		}
		if _, ok := seen[header.Name]; ok {
			return DistributionManifest{}, fmt.Errorf("duplicate distribution archive entry %q", header.Name)
		}
		seen[header.Name] = struct{}{}
		if header.Size < 0 || header.Size > maxDistributionArchiveEntryBytes {
			return DistributionManifest{}, fmt.Errorf("distribution archive entry %q exceeds size limit", header.Name)
		}
		if expanded > maxDistributionArchiveExpandedSize-header.Size {
			return DistributionManifest{}, errors.New("distribution archive exceeds expanded-size limit")
		}
		expanded += header.Size

		destination := filepath.Join(outputRoot, filepath.FromSlash(header.Name))
		if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
			return DistributionManifest{}, err
		}
		file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
		if err != nil {
			return DistributionManifest{}, err
		}
		written, copyErr := io.CopyN(file, tarReader, header.Size)
		syncErr := file.Sync()
		closeErr := file.Close()
		if copyErr != nil {
			return DistributionManifest{}, copyErr
		}
		if written != header.Size {
			return DistributionManifest{}, fmt.Errorf("distribution archive entry %q size mismatch", header.Name)
		}
		if syncErr != nil {
			return DistributionManifest{}, syncErr
		}
		if closeErr != nil {
			return DistributionManifest{}, closeErr
		}
	}
	if len(seen) != len(allowed) {
		return DistributionManifest{}, errors.New("distribution archive is missing required entries")
	}

	manifestBytes, err := readDistributionMetadataFile(outputRoot, DistributionManifestFilename, maxDistributionManifestBytes)
	if err != nil {
		return DistributionManifest{}, err
	}
	manifest, err := DecodeDistributionManifestStrict(manifestBytes)
	if err != nil {
		return DistributionManifest{}, err
	}
	if err := ValidateDistributionReleaseVersionAgreement(manifest.Version, archivePath, manifest); err != nil {
		return DistributionManifest{}, err
	}
	complete = true
	return manifest, nil
}

// ValidateDistributionReleaseVersionAgreement requires the requested version,
// archive filename, and signed-manifest version to match exactly.
func ValidateDistributionReleaseVersionAgreement(version, archivePath string, manifest DistributionManifest) error {
	if _, err := ParseReleaseVersion(version); err != nil {
		return err
	}
	if manifest.Version != version {
		return fmt.Errorf("distribution manifest version %q does not match requested version %q", manifest.Version, version)
	}
	wantName := DistributionArchivePrefix + version + DistributionArchiveSuffix
	if filepath.Base(archivePath) != wantName {
		return fmt.Errorf("distribution archive filename must be %q", wantName)
	}
	return nil
}

// DistributionArchiveSHA256 returns the lowercase SHA-256 identity of a regular
// transport archive.
func DistributionArchiveSHA256(archivePath string) (string, error) {
	digest, _, err := regularFileSHA256(archivePath)
	return digest, err
}

// DistributionArchiveChecksumBytes returns a conventional strict checksum line.
func DistributionArchiveChecksumBytes(archivePath string) ([]byte, string, error) {
	digest, err := DistributionArchiveSHA256(archivePath)
	if err != nil {
		return nil, "", err
	}
	line := digest + "  " + filepath.Base(archivePath) + "\n"
	return []byte(line), digest, nil
}

// VerifyDistributionArchiveChecksum verifies an exact lowercase SHA-256 checksum
// line for the supplied archive.
func VerifyDistributionArchiveChecksum(archivePath string, checksum []byte) (string, error) {
	if len(checksum) == 0 || checksum[len(checksum)-1] != '\n' || bytesCount(checksum, '\n') != 1 {
		return "", errors.New("distribution archive checksum must contain exactly one line")
	}
	line := string(checksum[:len(checksum)-1])
	parts := strings.Split(line, "  ")
	if len(parts) != 2 || len(parts[0]) != sha256.Size*2 || parts[1] != filepath.Base(archivePath) {
		return "", errors.New("distribution archive checksum line is malformed")
	}
	if strings.ToLower(parts[0]) != parts[0] {
		return "", errors.New("distribution archive checksum must be lowercase hexadecimal")
	}
	if _, err := hex.DecodeString(parts[0]); err != nil {
		return "", errors.New("distribution archive checksum must be lowercase hexadecimal")
	}
	actual, err := DistributionArchiveSHA256(archivePath)
	if err != nil {
		return "", err
	}
	if actual != parts[0] {
		return "", fmt.Errorf("distribution archive sha256 mismatch: got %s want %s", actual, parts[0])
	}
	return actual, nil
}

func validateDistributionArchivePath(name string) error {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return errors.New("distribution archive path must be relative and slash-separated")
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("distribution archive path contains unsafe segment")
		}
	}
	return nil
}

func regularFileSHA256(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() {
		return "", 0, errors.New("path must be a regular file")
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), written, nil
}

func bytesCount(data []byte, value byte) int {
	count := 0
	for _, b := range data {
		if b == value {
			count++
		}
	}
	return count
}
