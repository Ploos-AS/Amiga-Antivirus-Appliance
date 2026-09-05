package archive

import (
	"bytes"
	"compress/gzip"
	"testing"
)

func TestDecodeADZ(t *testing.T) {
	payload := []byte("DOS\x01synthetic-adf")
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	got, analysis, err := DecodeADZ(compressed.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("decoded payload mismatch: %q", got)
	}
	if analysis.Format != "adz" || analysis.ExpandedSize != int64(len(payload)) || len(analysis.Members) != 1 {
		t.Fatalf("unexpected analysis: %+v", analysis)
	}
	if len(analysis.Members[0].SHA256) != 64 {
		t.Fatalf("missing member hash: %+v", analysis.Members[0])
	}
}

func TestDecodeADZRejectsInvalidGzip(t *testing.T) {
	if _, _, err := DecodeADZ([]byte("not-gzip")); err == nil {
		t.Fatal("expected invalid gzip error")
	}
}
