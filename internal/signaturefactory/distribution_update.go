package signaturefactory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const MaxDistributionDownloadBytes = int64(32 << 20)

var DistributionHTTPTimeout = 30 * time.Second

type DistributionReleaseCandidate struct {
	Version     string
	ArchiveURL  string
	ChecksumURL string
}

type githubRelease struct {
	TagName    string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// ReadDistributionInstallState returns the active M7.4 state without mutating it.
func ReadDistributionInstallState(storeRoot string) (DistributionInstallState, bool, error) {
	if storeRoot == "" {
		return DistributionInstallState{}, false, errors.New("distribution store root is required")
	}
	return readDistributionInstallState(filepath.Join(storeRoot, DistributionStateFilename))
}

// DiscoverDistributionRelease queries GitHub-compatible release JSON and selects
// the newest well-formed signature release newer than the active version.
func DiscoverDistributionRelease(ctx context.Context, sourceURL string, current *DistributionInstallState) (*DistributionReleaseCandidate, error) {
	parsed, err := safeHTTPURL(sourceURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := distributionHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("query distribution releases: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("query distribution releases: http status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 2<<20 {
		return nil, errors.New("distribution release metadata exceeds size limit")
	}
	var releases []githubRelease
	if err := json.Unmarshal(data, &releases); err != nil {
		return nil, fmt.Errorf("decode distribution release metadata: %w", err)
	}
	var currentVersion ReleaseVersion
	if current != nil {
		if err := current.Validate(); err != nil {
			return nil, err
		}
		currentVersion, err = ParseReleaseVersion(current.Version)
		if err != nil {
			return nil, err
		}
	}
	var best *DistributionReleaseCandidate
	var bestVersion ReleaseVersion
	for _, release := range releases {
		if release.Draft || release.Prerelease || !strings.HasPrefix(release.TagName, "signatures-v") {
			continue
		}
		version := strings.TrimPrefix(release.TagName, "signatures-v")
		parsedVersion, err := ParseReleaseVersion(version)
		if err != nil {
			continue
		}
		if current != nil && parsedVersion.Compare(currentVersion) <= 0 {
			continue
		}
		archiveName := DistributionArchivePrefix + version + DistributionArchiveSuffix
		checksumName := archiveName + DistributionArchiveChecksumSuffix
		candidate := DistributionReleaseCandidate{Version: version}
		for _, asset := range release.Assets {
			switch asset.Name {
			case archiveName:
				candidate.ArchiveURL = asset.BrowserDownloadURL
			case checksumName:
				candidate.ChecksumURL = asset.BrowserDownloadURL
			}
		}
		if candidate.ArchiveURL == "" {
			continue
		}
		if _, err := safeHTTPURL(candidate.ArchiveURL); err != nil {
			continue
		}
		if candidate.ChecksumURL != "" {
			if _, err := safeHTTPURL(candidate.ChecksumURL); err != nil {
				continue
			}
		}
		if best == nil || parsedVersion.Compare(bestVersion) > 0 {
			copy := candidate
			best = &copy
			bestVersion = parsedVersion
		}
	}
	return best, nil
}

// DownloadDistributionArchive downloads into a temporary file, bounds bytes and
// time, fsyncs, optionally checks transport SHA-256, then atomically renames.
func DownloadDistributionArchive(ctx context.Context, archiveURL, version, outputPath, expectedSHA256 string) (string, error) {
	if _, err := ParseReleaseVersion(version); err != nil {
		return "", err
	}
	wantName := DistributionArchivePrefix + version + DistributionArchiveSuffix
	if filepath.Base(outputPath) != wantName {
		return "", fmt.Errorf("distribution download filename must be %q", wantName)
	}
	parsed, err := safeHTTPURL(archiveURL)
	if err != nil {
		return "", err
	}
	if expectedSHA256 != "" && !validSHA256(expectedSHA256) {
		return "", errors.New("expected distribution archive sha256 must be lowercase sha256")
	}
	if _, err := os.Lstat(outputPath); err == nil {
		return "", errors.New("distribution download output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o750); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := distributionHTTPClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("download distribution archive: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("download distribution archive: http status %d", resp.StatusCode)
	}
	if resp.ContentLength > MaxDistributionDownloadBytes {
		return "", errors.New("distribution archive exceeds download size limit")
	}
	tmp, err := os.CreateTemp(filepath.Dir(outputPath), ".distribution-download-*.tmp")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		_ = tmp.Close()
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()
	written, err := io.Copy(tmp, io.LimitReader(resp.Body, MaxDistributionDownloadBytes+1))
	if err != nil {
		return "", err
	}
	if written > MaxDistributionDownloadBytes {
		return "", errors.New("distribution archive exceeds download size limit")
	}
	if err := tmp.Sync(); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	digest, err := DistributionArchiveSHA256(tmpPath)
	if err != nil {
		return "", err
	}
	if expectedSHA256 != "" && digest != expectedSHA256 {
		return "", fmt.Errorf("distribution archive sha256 mismatch: got %s want %s", digest, expectedSHA256)
	}
	if err := os.Rename(tmpPath, outputPath); err != nil {
		return "", err
	}
	keep = true
	if err := syncDirectory(filepath.Dir(outputPath)); err != nil {
		return "", err
	}
	return digest, nil
}

func distributionHTTPClient() *http.Client {
	return &http.Client{
		Timeout: DistributionHTTPTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many distribution HTTP redirects")
			}
			_, err := safeHTTPURL(req.URL.String())
			return err
		},
	}
}

func safeHTTPURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, errors.New("distribution source must use http or https")
	}
	if parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("distribution source URL is invalid")
	}
	return parsed, nil
}
