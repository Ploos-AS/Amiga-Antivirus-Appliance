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
	FDIDecodeTimeout         = 15 * time.Second
	maxFDIMetadataLine       = 64 * 1024
	maxFDIHelperStderr       = 64 * 1024
	fdiHelperProtocolVersion = 1
)

type fdiHelperHeader struct {
	Schema                int    `json:"schema"`
	Format                string `json:"format"`
	Decoder               string `json:"decoder"`
	DecoderVersion        string `json:"decoder_version,omitempty"`
	Platform              string `json:"platform,omitempty"`
	Tracks                int    `json:"tracks,omitempty"`
	DerivedSize           int64  `json:"derived_size"`
	LosslessForSectorScan bool   `json:"lossless_for_sector_scan"`
}

// DecodeFDI sends an FDI image to an optional, separately installed helper.
// The helper path is supplied by AAA_FDI_HELPER. AAA never shells the value or
// writes submitted/derived image bytes to a host extraction path.
func DecodeFDI(data []byte) ([]byte, *Analysis, error) {
	helper := os.Getenv("AAA_FDI_HELPER")
	if helper == "" {
		return nil, nil, fmt.Errorf("FDI helper is not configured; set AAA_FDI_HELPER")
	}
	return decodeFDIWithExecutable(data, helper, FDIDecodeTimeout)
}

// Helper protocol: stdout is one UTF-8 JSON header line followed immediately
// by optional raw derived sector-image bytes. The helper must positively
// confirm format "fdi" before AAA accepts the result.
func decodeFDIWithExecutable(data []byte, executable string, timeout time.Duration) ([]byte, *Analysis, error) {
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("empty FDI candidate")
	}
	if executable == "" {
		return nil, nil, fmt.Errorf("FDI helper executable is not configured")
	}
	if timeout <= 0 {
		return nil, nil, fmt.Errorf("invalid FDI helper timeout")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	stdout := &cappedBuffer{limit: int64(maxFDIMetadataLine) + MaxDerivedSectorImage + 1}
	stderr := &cappedBuffer{limit: maxFDIHelperStderr}
	cmd := exec.CommandContext(ctx, executable)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = os.Environ()

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, nil, fmt.Errorf("FDI helper exceeded %s timeout", timeout)
	}
	if stdout.exceeded {
		return nil, nil, fmt.Errorf("FDI helper output exceeds safety limit")
	}
	if err != nil {
		if stderr.Len() > 0 {
			return nil, nil, fmt.Errorf("FDI helper failed: %w: %s", err, stderr.String())
		}
		return nil, nil, fmt.Errorf("FDI helper failed: %w", err)
	}

	output := stdout.Bytes()
	newline := bytes.IndexByte(output, '\n')
	if newline < 0 {
		return nil, nil, fmt.Errorf("FDI helper produced no metadata line")
	}
	if newline == 0 || newline > maxFDIMetadataLine {
		return nil, nil, fmt.Errorf("invalid FDI helper metadata length")
	}

	var header fdiHelperHeader
	if err := json.Unmarshal(output[:newline], &header); err != nil {
		return nil, nil, fmt.Errorf("invalid FDI helper metadata: %w", err)
	}
	if header.Schema != fdiHelperProtocolVersion {
		return nil, nil, fmt.Errorf("unsupported FDI helper schema %d", header.Schema)
	}
	if header.Format != "fdi" {
		return nil, nil, fmt.Errorf("helper did not confirm FDI format")
	}
	if header.Decoder == "" {
		return nil, nil, fmt.Errorf("FDI helper omitted decoder identity")
	}
	if header.Tracks < 0 {
		return nil, nil, fmt.Errorf("invalid FDI track count %d", header.Tracks)
	}
	if header.DerivedSize < 0 || header.DerivedSize > MaxDerivedSectorImage {
		return nil, nil, fmt.Errorf("invalid FDI derived size %d", header.DerivedSize)
	}

	derived := append([]byte(nil), output[newline+1:]...)
	if int64(len(derived)) != header.DerivedSize {
		return nil, nil, fmt.Errorf("FDI helper derived-size mismatch: declared %d, emitted %d", header.DerivedSize, len(derived))
	}
	if header.LosslessForSectorScan && len(derived) == 0 {
		return nil, nil, fmt.Errorf("FDI helper declared lossless sector view without data")
	}
	if !header.LosslessForSectorScan && len(derived) != 0 {
		return nil, nil, fmt.Errorf("FDI helper emitted sector data without declaring a lossless sector view")
	}

	analysis := &Analysis{
		Format:         "fdi",
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
