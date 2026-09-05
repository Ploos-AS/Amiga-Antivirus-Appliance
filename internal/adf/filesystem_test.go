package adf

import (
	"encoding/binary"
	"testing"
)

func TestAnalyzeFilesystemEnumeratesFilesAndDirectories(t *testing.T) {
	image := make([]byte, DDSize)
	copy(image[:3], []byte("DOS"))
	image[3] = 1
	binary.BigEndian.PutUint32(image[8:12], 880)

	root := image[880*blockSize : 881*blockSize]
	putWord(root, 0, primaryHeaderType)
	putWord(root, 3, maxHashTableWords)
	putWord(root, 6, 100)
	putWord(root, secondaryTypeWord, uint32(secondaryRoot))

	file := image[100*blockSize : 101*blockSize]
	putWord(file, 0, primaryHeaderType)
	putName(file, "VirusZ")
	putWord(file, hashChainWord, 101)
	putWord(file, secondaryTypeWord, 0xfffffffd)

	dir := image[101*blockSize : 102*blockSize]
	putWord(dir, 0, primaryHeaderType)
	putWord(dir, 3, maxHashTableWords)
	putWord(dir, 6, 102)
	putName(dir, "Tools")
	putWord(dir, secondaryTypeWord, uint32(secondaryDirectory))

	nested := image[102*blockSize : 103*blockSize]
	putWord(nested, 0, primaryHeaderType)
	putName(nested, "Scanner")
	putWord(nested, secondaryTypeWord, 0xfffffffd)

	got, err := AnalyzeFilesystemBytes(image)
	if err != nil {
		t.Fatal(err)
	}
	if !got.RootBlockValid {
		t.Fatalf("root block not valid: %+v", got)
	}
	if got.FileCount != 2 || got.DirectoryCount != 1 {
		t.Fatalf("unexpected counts: %+v", got)
	}
	if len(got.Entries) != 3 {
		t.Fatalf("unexpected entries: %+v", got.Entries)
	}
	if got.Entries[0].Path != "VirusZ" || got.Entries[0].Type != "file" {
		t.Fatalf("unexpected first entry: %+v", got.Entries[0])
	}
	if got.Entries[1].Path != "Tools" || got.Entries[1].Type != "directory" {
		t.Fatalf("unexpected directory: %+v", got.Entries[1])
	}
	if got.Entries[2].Path != "Tools/Scanner" || got.Entries[2].Type != "file" {
		t.Fatalf("unexpected nested entry: %+v", got.Entries[2])
	}
}

func TestAnalyzeFilesystemFallsBackToExpectedRoot(t *testing.T) {
	image := make([]byte, DDSize)
	copy(image[:3], []byte("DOS"))
	root := image[880*blockSize : 881*blockSize]
	putWord(root, 0, primaryHeaderType)
	putWord(root, 3, maxHashTableWords)
	putWord(root, secondaryTypeWord, uint32(secondaryRoot))

	got, err := AnalyzeFilesystemBytes(image)
	if err != nil {
		t.Fatal(err)
	}
	if got.RootBlock != 880 || !got.RootBlockValid {
		t.Fatalf("unexpected root analysis: %+v", got)
	}
}

func TestAnalyzeFilesystemReportsCorruptRoot(t *testing.T) {
	image := make([]byte, DDSize)
	copy(image[:3], []byte("DOS"))
	binary.BigEndian.PutUint32(image[8:12], 999999)

	got, err := AnalyzeFilesystemBytes(image)
	if err != nil {
		t.Fatal(err)
	}
	if got.RootBlockValid || len(got.Warnings) == 0 {
		t.Fatalf("expected structural warning: %+v", got)
	}
}

func putWord(block []byte, word int, value uint32) {
	binary.BigEndian.PutUint32(block[word*4:word*4+4], value)
}

func putName(block []byte, name string) {
	block[nameOffset] = byte(len(name))
	copy(block[nameOffset+1:], name)
}
