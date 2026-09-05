package adf

import (
	"encoding/binary"
	"testing"
)

func TestAnalyzeFFSFilePayload(t *testing.T) {
	image := make([]byte, DDSize)
	header := image[100*blockSize : 101*blockSize]
	putWord(header, 0, primaryHeaderType)
	putWord(header, 2, 1)
	putWord(header, fileByteSizeWord, 5)
	putWord(header, fileDataBaseWord+fileDataSlots-1, 200)
	putWord(header, secondaryTypeWord, uint32(int32(secondaryFile)))
	copy(image[200*blockSize:], []byte("hello"))

	got := analyzeFilePayload(image, 100, 1)
	if !got.Complete || got.Size != 5 || got.DataBlocks != 1 {
		t.Fatalf("unexpected payload analysis: %+v", got)
	}
	if got.SHA256 != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("unexpected hash %s", got.SHA256)
	}
}

func TestAnalyzeOFSFilePayload(t *testing.T) {
	image := make([]byte, DDSize)
	header := image[100*blockSize : 101*blockSize]
	putWord(header, 0, primaryHeaderType)
	putWord(header, 2, 1)
	putWord(header, fileByteSizeWord, 5)
	putWord(header, fileDataBaseWord+fileDataSlots-1, 200)
	putWord(header, secondaryTypeWord, uint32(int32(secondaryFile)))

	data := image[200*blockSize : 201*blockSize]
	putWord(data, 0, primaryDataType)
	putWord(data, 1, 100)
	putWord(data, 2, 1)
	putWord(data, 3, 5)
	copy(data[24:], []byte("hello"))

	got := analyzeFilePayload(image, 100, 0)
	if !got.Complete || got.Size != 5 || got.DataBlocks != 1 {
		t.Fatalf("unexpected payload analysis: %+v", got)
	}
	if got.SHA256 != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("unexpected hash %s", got.SHA256)
	}
}

func TestAnalyzeFFSPayloadUsesExtensionBlocks(t *testing.T) {
	image := make([]byte, DDSize)
	header := image[100*blockSize : 101*blockSize]
	putWord(header, 0, primaryHeaderType)
	putWord(header, 2, 1)
	putWord(header, fileByteSizeWord, 517)
	putWord(header, fileDataBaseWord+fileDataSlots-1, 200)
	putWord(header, fileExtensionWord, 150)
	putWord(header, secondaryTypeWord, uint32(int32(secondaryFile)))
	for i := 0; i < blockSize; i++ {
		image[200*blockSize+i] = 'A'
	}

	ext := image[150*blockSize : 151*blockSize]
	putWord(ext, 0, primaryListType)
	putWord(ext, 2, 1)
	putWord(ext, fileDataBaseWord+fileDataSlots-1, 201)
	putWord(ext, secondaryTypeWord, uint32(int32(secondaryFile)))
	copy(image[201*blockSize:], []byte("hello"))

	got := analyzeFilePayload(image, 100, 1)
	if !got.Complete || got.Size != 517 || got.DataBlocks != 2 || got.Warning != "" {
		t.Fatalf("unexpected extension analysis: %+v", got)
	}
}

func TestFilesystemEntryIncludesPayloadHash(t *testing.T) {
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
	putWord(file, 2, 1)
	putWord(file, fileByteSizeWord, 5)
	putWord(file, fileDataBaseWord+fileDataSlots-1, 200)
	putName(file, "sample")
	putWord(file, secondaryTypeWord, uint32(int32(secondaryFile)))
	copy(image[200*blockSize:], []byte("hello"))

	got, err := AnalyzeFilesystemBytes(image)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Payload == nil {
		t.Fatalf("missing payload metadata: %+v", got.Entries)
	}
	if got.Entries[0].Payload.SHA256 != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("unexpected hash: %+v", got.Entries[0].Payload)
	}
}
