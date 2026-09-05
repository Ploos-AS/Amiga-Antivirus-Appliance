package preservation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const (
	IPFDecodeTimeout         = 15 * time.Second
	MaxDerivedSectorImage    = 32 * 1024 * 1024
	maxIPFMetadataLine       = 64 * 1024
	maxIPFHelperStderr       = 64 * 1024
	ipfHelperProtocolVersion = 1
)

type DerivedSectorImage struct {
	Size                  int64  `json:"size"`
	SHA256                string `json:"sha256"`
	LosslessForSectorScan bool   `json:"lossless_for_sector_scan"`
}

type Analysis struct {
	Format             string              `json:"format"`
	Decoder            string              `json:"decoder"`
	DecoderVersion     string              `json:"decoder_version,omitempty"`
	Platform           string              `json:"platform,omitempty"`
	Tracks             int                 `json:"tracks,omitempty"`
	DerivedSectorImage *DerivedSectorImage `json:"derived_sector_image,omitempty"`
}

type ipfHelperHeader struct {
	Schema                int    `json:"schema"`
	Format                string `json:"format"`
	Decoder               string `json:"decoder"`
	DecoderVersion        string `json:"decoder_version,omitempty"`
	Platform              string `json:"platform,omitempty"`
	Tracks                int    `json:"tracks,omitempty"`
	DerivedSize           int64  `json:"derived_size"`
	LosslessForSectorScan bool   `json:"lossless_for_sector_scan"`
}

// DecodeIPF sends an IPF image to an optional, separately installed helper.
// The helper path is supplied by AAA_IPF_HELPER. AAA never shells the value or
// writes submitted/derived image bytes to a host extraction path.
func DecodeIPF(data []byte) ([]byte, *Analysis, error) {
	helper := os.Getenv("AAA_IPF_HELPER")
	if helper == "" {
		return nil, nil, fmt.Errorf("IPF helper is not configured; set AAA_IPF_HELPER")
	}
	return decodeIPFWithExecutable(data, helper, IPFDecodeTimeout)
}

// Helper protocol: stdout is one UTF-8 JSON header line followed immediately
// by optional raw derived sector-image bytes. The header must declare format
// "ipf", protocol schema 1, derived_size, and whether the derived view is
// lossless for sector scanning. The raw payload is bounded before acceptance.
func decodeIPFWithExecutable(data []byte, executable string, timeout time.Duration) ([]byte, *Analysis, error) {
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("empty IPF candidate")
	}
	if executable == "" {
		return nil, nil, fmt.Errorf("IPF helper executable is not configured")
	}
	if timeout <= 0 {
		return nil, nil, fmt.Errorf("invalid IPF helper timeout")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	stdout := &cappedBuffer{limit: int64(maxIPFMetadataLine) + MaxDerivedSectorImage + 1}
	stderr := &cappedBuffer{limit: maxIPFHelperStderr}
	cmd := exec.CommandContext(ctx, executable)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = os.Environ()

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, nil, fmt.Errorf("IPF helper exceeded %s timeout", timeout)
	}
	if stdout.exceeded {
		return nil, nil, fmt.Errorf("IPF helper output exceeds safety limit")
	}
	if err != nil {
		if stderr.Len() > 0 {
			return nil, nil, fmt.Errorf("IPF helper failed: %w: %s", err, stderr.String())
		}
		return nil, nil, fmt.Errorf("IPF helper failed: %w", err)
	}

	output := stdout.Bytes()
	newline := bytes.IndexByte(output, '\n')
	if newline < 0 {
		return nil, nil, fmt.Errorf("IPF helper produced no metadata line")
	}
	if newline == 0 || newline > maxIPFMetadataLine {
		return nil, nil, fmt.Errorf("invalid IPF helper metadata length")
	}

	var header ipfHelperHeader
	if err := json.Unmarshal(output[:newline], &header); err != nil {
		return nil, nil, fmt.Errorf("invalid IPF helper metadata: %w", err)
	}
	if header.Schema != ipfHelperProtocolVersion {
		return nil, nil, fmt.Errorf("unsupported IPF helper schema %d", header.Schema)
	}
	if header.Format != "ipf" {
		return nil, nil, fmt.Errorf("helper did not confirm IPF format")
	}
	if header.Decoder == "" {
		return nil, nil, fmt.Errorf("IPF helper omitted decoder identity")
	}
	if header.Tracks < 0 {
		return nil, nil, fmt.Errorf("invalid IPF track count %d", header.Tracks)
	}
	if header.DerivedSize < 0 || header.DerivedSize > MaxDerivedSectorImage {
		return nil, nil, fmt.Errorf("invalid IPF derived size %d", header.DerivedSize)
	}

	derived := append([]byte(nil), output[newline+1:]...)
	if int64(len(derived)) != header.DerivedSize {
		return nil, nil, fmt.Errorf("IPF helper derived-size mismatch: declared %d, emitted %d", header.DerivedSize, len(derived))
	}
	if header.LosslessForSectorScan && len(derived) == 0 {
		return nil, nil, fmt.Errorf("IPF helper declared lossless sector view without data")
	}
	if !header.LosslessForSectorScan && len(derived) != 0 {
		return nil, nil, fmt.Errorf("IPF helper emitted sector data without declaring a lossless sector view")
	}

	analysis := &Analysis{
		Format:         "ipf",
		Decoder:        header.Decoder,
		DecoderVersion: header.DecoderVersion,
		Platform:       header.Platform,
		Tracks:         header.Tracks,
	}
	if len(derived) > 0 {
		sum := sha256.Sum256(derived)
		analysis.DerivedSectorImage = &DerivedSectorImage{
			Size:                  int64(len(derived)),
			SHA256:                hex.EncodeToString(sum[:]),
			LosslessForSectorScan: true,
		}
	}
	return derived, analysis, nil
}

type cappedBuffer struct {
	bytes.Buffer
	limit    int64
	exceeded bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - int64(b.Len())
	if remaining <= 0 {
		b.exceeded = true
		return 0, fmt.Errorf("buffer limit exceeded")
	}
	if int64(len(p)) > remaining {
		_, _ = b.Buffer.Write(p[:remaining])
		b.exceeded = true
		return int(remaining), fmt.Errorf("buffer limit exceeded")
	}
	return b.Buffer.Write(p)
}
