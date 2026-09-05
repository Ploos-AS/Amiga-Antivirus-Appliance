package hunk

import (
	"encoding/binary"
	"testing"
)

func TestAnalyzeExecutableHunks(t *testing.T) {
	words := []uint32{
		HUNK_HEADER,
		0,
		2, 0, 1,
		2, 1,
		HUNK_CODE, 2, 0x4e714e71, 0x4e754e75, HUNK_END,
		HUNK_DATA, 1, 0x12345678, HUNK_END,
		HUNK_BSS, 3, HUNK_END,
	}
	data := encode(words)
	got := Analyze(data)
	if !got.Recognized {
		t.Fatal("expected recognized hunk executable")
	}
	if got.FirstHunk != 0 || got.LastHunk != 1 {
		t.Fatalf("unexpected range: %+v", got)
	}
	if got.HunkCount != 3 || got.CodeBytes != 8 || got.DataBytes != 4 || got.BSSBytes != 12 {
		t.Fatalf("unexpected analysis: %+v", got)
	}
	if len(got.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %+v", got.Warnings)
	}
}

func TestAnalyzeNonHunk(t *testing.T) {
	got := Analyze([]byte("hello"))
	if got.Recognized {
		t.Fatal("plain data must not be recognized as Hunk")
	}
}

func TestAnalyzeTruncatedHunk(t *testing.T) {
	data := encode([]uint32{HUNK_HEADER, 0, 1, 0, 0, 1, HUNK_CODE, 3, 0x12345678})
	got := Analyze(data)
	if !got.Recognized || len(got.Warnings) == 0 {
		t.Fatalf("expected recognized but malformed hunk: %+v", got)
	}
}

func encode(words []uint32) []byte {
	data := make([]byte, len(words)*4)
	for i, w := range words {
		binary.BigEndian.PutUint32(data[i*4:], w)
	}
	return data
}
