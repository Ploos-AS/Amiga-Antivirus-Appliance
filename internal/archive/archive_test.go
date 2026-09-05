package archive

import (
	"archive/zip"
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

func TestDecodeZIP(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("C/tool")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("hello amiga")
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	members, analysis, err := DecodeZIP(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if analysis.Format != "zip" || analysis.ExpandedSize != int64(len(payload)) || len(analysis.Members) != 1 {
		t.Fatalf("unexpected analysis: %+v", analysis)
	}
	if len(members) != 1 || members[0].Name != "C/tool" || !bytes.Equal(members[0].Data, payload) {
		t.Fatalf("unexpected expanded members: %+v", members)
	}
	if len(analysis.Members[0].SHA256) != 64 {
		t.Fatalf("missing ZIP member hash: %+v", analysis.Members[0])
	}
}

func TestDecodeZIPRejectsInvalid(t *testing.T) {
	if _, _, err := DecodeZIP([]byte("not-zip")); err == nil {
		t.Fatal("expected invalid ZIP error")
	}
}
