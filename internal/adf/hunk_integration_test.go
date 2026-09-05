package adf

import (
	"encoding/binary"
	"testing"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/hunk"
)

func TestFilesystemRecognizesHunkExecutable(t *testing.T) {
	image := make([]byte, DDSize)
	copy(image[:3], []byte("DOS"))
	image[3] = 1
	binary.BigEndian.PutUint32(image[8:12], 880)

	root := image[880*blockSize : 881*blockSize]
	putWord(root, 0, primaryHeaderType)
	putWord(root, 3, maxHashTableWords)
	putWord(root, 6, 100)
	putWord(root, secondaryTypeWord, uint32(secondaryRoot))

	words := []uint32{
		hunk.HUNK_HEADER,
		0,
		1, 0, 0,
		1,
		hunk.HUNK_CODE, 1, 0x4e754e75, hunk.HUNK_END,
	}
	payload := make([]byte, len(words)*4)
	for i, w := range words {
		binary.BigEndian.PutUint32(payload[i*4:], w)
	}

	file := image[100*blockSize : 101*blockSize]
	putWord(file, 0, primaryHeaderType)
	putWord(file, 2, 1)
	putWord(file, fileByteSizeWord, uint32(len(payload)))
	putWord(file, fileDataBaseWord+fileDataSlots-1, 200)
	putName(file, "runme")
	putWord(file, secondaryTypeWord, secondaryFileWord)
	copy(image[200*blockSize:], payload)

	got, err := AnalyzeFilesystemBytes(image)
	if err != nil {
		t.Fatal(err)
	}
	if got.HunkFileCount != 1 || len(got.Entries) != 1 || got.Entries[0].Hunk == nil {
		t.Fatalf("expected one Hunk executable: %+v", got)
	}
	if got.Entries[0].Hunk.CodeBytes != 4 || got.Entries[0].Hunk.HunkCount != 1 {
		t.Fatalf("unexpected Hunk analysis: %+v", got.Entries[0].Hunk)
	}
}
