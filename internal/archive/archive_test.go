package archive

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
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

func TestDecodeLHAStoredMember(t *testing.T) {
	payload := []byte("hello amiga")
	data := makeLH0Archive("C/tool", payload)
	members, analysis, err := DecodeLHA(data)
	if err != nil {
		t.Fatal(err)
	}
	if analysis.Format != "lha" || analysis.ExpandedSize != int64(len(payload)) || len(analysis.Members) != 1 {
		t.Fatalf("unexpected LHA analysis: %+v", analysis)
	}
	if len(members) != 1 || members[0].Name != "C/tool" || !bytes.Equal(members[0].Data, payload) {
		t.Fatalf("unexpected LHA member: %+v", members)
	}
	if len(analysis.Members[0].SHA256) != 64 {
		t.Fatalf("missing LHA member hash: %+v", analysis.Members[0])
	}
}

func TestDecodeLHARejectsInvalid(t *testing.T) {
	if _, _, err := DecodeLHA([]byte("not-lha")); err == nil {
		t.Fatal("expected invalid LHA error")
	}
}

func makeLH0Archive(name string, payload []byte) []byte {
	nameBytes := []byte(name)
	headerSize := len(nameBytes) + 22
	header := make([]byte, 0, headerSize+2)
	header = append(header, byte(headerSize), 0)
	header = append(header, []byte("-lh0-")...)
	var word [4]byte
	binary.LittleEndian.PutUint32(word[:], uint32(len(payload)))
	header = append(header, word[:]...)
	header = append(header, word[:]...)
	header = append(header, 0, 0, 0, 0)
	header = append(header, 0x20, 0, byte(len(nameBytes)))
	header = append(header, nameBytes...)
	crc := crc16IBM(payload)
	header = append(header, byte(crc), byte(crc>>8))
	var sum byte
	for _, b := range header[2:] {
		sum += b
	}
	header[1] = sum
	return append(append(header, payload...), 0)
}

func crc16IBM(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xa001
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}
