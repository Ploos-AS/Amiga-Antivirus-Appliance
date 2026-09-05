package signaturefactory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const DistributionSchemaVersion = 1

type DistributionTarget string

const (
	DistributionTargetAAABootblocks DistributionTarget = "aaa-bootblocks"
	DistributionTargetClamAVHashes  DistributionTarget = "clamav-hashes"
)

var releaseVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

type ReleaseVersion struct {
	Major uint64
	Minor uint64
	Patch uint64
}

func ParseReleaseVersion(value string) (ReleaseVersion, error) {
	matches := releaseVersionPattern.FindStringSubmatch(value)
	if matches == nil {
		return ReleaseVersion{}, fmt.Errorf("invalid release version %q", value)
	}
	parts := make([]uint64, 3)
	for i := range parts {
		parsed, err := strconv.ParseUint(matches[i+1], 10, 64)
		if err != nil {
			return ReleaseVersion{}, fmt.Errorf("invalid release version %q: %w", value, err)
		}
		parts[i] = parsed
	}
	return ReleaseVersion{Major: parts[0], Minor: parts[1], Patch: parts[2]}, nil
}

func (v ReleaseVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func (v ReleaseVersion) Compare(other ReleaseVersion) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}
	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}
	return 0
}

type DistributionPayload struct {
	Target DistributionTarget `json:"target"`
	Path   string             `json:"path"`
	SHA256 string             `json:"sha256"`
	Size   int64              `json:"size"`
}

type DistributionManifest struct {
	Schema      int                   `json:"schema"`
	Version     string                `json:"version"`
	CreatedAt   time.Time             `json:"created_at"`
	SignerKeyID string                `json:"signer_key_id"`
	Payloads    []DistributionPayload `json:"payloads"`
}

func (m DistributionManifest) Validate() error {
	if m.Schema != DistributionSchemaVersion {
		return fmt.Errorf("unsupported distribution schema %d", m.Schema)
	}
	if _, err := ParseReleaseVersion(m.Version); err != nil {
		return err
	}
	if m.CreatedAt.IsZero() {
		return errors.New("distribution created_at is required")
	}
	_, offset := m.CreatedAt.Zone()
	if offset != 0 {
		return errors.New("distribution created_at must be UTC")
	}
	if !validSHA256(m.SignerKeyID) {
		return errors.New("distribution signer_key_id must be a lowercase sha256")
	}
	if len(m.Payloads) == 0 {
		return errors.New("distribution payloads are required")
	}

	seenTargets := make(map[DistributionTarget]struct{}, len(m.Payloads))
	seenPaths := make(map[string]struct{}, len(m.Payloads))
	seenHashes := make(map[string]struct{}, len(m.Payloads))
	for i, payload := range m.Payloads {
		if err := payload.Validate(); err != nil {
			return fmt.Errorf("distribution payload %d: %w", i, err)
		}
		if _, ok := seenTargets[payload.Target]; ok {
			return fmt.Errorf("duplicate distribution target %q", payload.Target)
		}
		seenTargets[payload.Target] = struct{}{}
		if _, ok := seenPaths[payload.Path]; ok {
			return fmt.Errorf("duplicate distribution path %q", payload.Path)
		}
		seenPaths[payload.Path] = struct{}{}
		if _, ok := seenHashes[payload.SHA256]; ok {
			return fmt.Errorf("duplicate distribution payload sha256 %s", payload.SHA256)
		}
		seenHashes[payload.SHA256] = struct{}{}
	}
	return nil
}

func (p DistributionPayload) Validate() error {
	switch p.Target {
	case DistributionTargetAAABootblocks:
		if p.Path != "aaa/bootblocks.json" {
			return fmt.Errorf("target %q requires path aaa/bootblocks.json", p.Target)
		}
	case DistributionTargetClamAVHashes:
		if p.Path != "clamav/aaa.hsb" {
			return fmt.Errorf("target %q requires path clamav/aaa.hsb", p.Target)
		}
	default:
		return fmt.Errorf("unsupported distribution target %q", p.Target)
	}
	if err := validateDistributionPath(p.Path); err != nil {
		return err
	}
	if !validSHA256(p.SHA256) {
		return errors.New("payload sha256 must be a lowercase sha256")
	}
	if p.Size < 0 {
		return errors.New("payload size cannot be negative")
	}
	return nil
}

func validateDistributionPath(value string) error {
	if value == "" {
		return errors.New("payload path is required")
	}
	if strings.Contains(value, "\\") {
		return errors.New("payload path must use slash separators")
	}
	if strings.HasPrefix(value, "/") || path.IsAbs(value) {
		return errors.New("payload path must be relative")
	}
	segments := strings.Split(value, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("payload path contains unsafe segment")
		}
	}
	if path.Clean(value) != value {
		return errors.New("payload path is not canonical")
	}
	return nil
}

func (m DistributionManifest) CanonicalBytes() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	canonical := m
	canonical.CreatedAt = canonical.CreatedAt.UTC()
	canonical.Payloads = append([]DistributionPayload(nil), m.Payloads...)
	sort.Slice(canonical.Payloads, func(i, j int) bool {
		if canonical.Payloads[i].Target == canonical.Payloads[j].Target {
			return canonical.Payloads[i].Path < canonical.Payloads[j].Path
		}
		return canonical.Payloads[i].Target < canonical.Payloads[j].Target
	})
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("encode distribution manifest: %w", err)
	}
	return append(encoded, '\n'), nil
}

func (m DistributionManifest) SHA256() (string, error) {
	encoded, err := m.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func DecodeDistributionManifestStrict(data []byte) (DistributionManifest, error) {
	var manifest DistributionManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return DistributionManifest{}, fmt.Errorf("decode distribution manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return DistributionManifest{}, errors.New("decode distribution manifest: trailing data")
		}
		return DistributionManifest{}, fmt.Errorf("decode distribution manifest trailing data: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return DistributionManifest{}, err
	}
	return manifest, nil
}
