package adf

import (
	"encoding/binary"
	"fmt"
	"os"
	"path"
)

const (
	blockSize          = 512
	maxHashTableWords  = 72
	nameOffset         = 432
	hashChainWord      = 124
	secondaryTypeWord  = 127
	primaryHeaderType  = 2
	secondaryRoot      = 1
	secondaryDirectory = 2
	secondaryFile      = -3
	maxTraversalDepth  = 64
)

type FilesystemEntry struct {
	Path        string `json:"path"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	HeaderBlock uint32 `json:"header_block"`
}

type FilesystemAnalysis struct {
	RootBlock      uint32            `json:"root_block"`
	RootBlockValid bool              `json:"root_block_valid"`
	FileCount      int               `json:"file_count"`
	DirectoryCount int               `json:"directory_count"`
	Entries        []FilesystemEntry `json:"entries,omitempty"`
	Warnings       []string          `json:"warnings,omitempty"`
}

// AnalyzeFilesystem enumerates OFS/FFS directory and file header blocks without
// extracting file payloads. Corrupt metadata is reported as warnings so the
// preservation scanner can still report the disk rather than silently dropping it.
func AnalyzeFilesystem(pathname string) (*FilesystemAnalysis, error) {
	image, err := os.ReadFile(pathname)
	if err != nil {
		return nil, err
	}
	return AnalyzeFilesystemBytes(image)
}

func AnalyzeFilesystemBytes(image []byte) (*FilesystemAnalysis, error) {
	_, blocks, expectedRoot, err := geometry(int64(len(image)))
	if err != nil {
		return nil, err
	}
	if len(image) < BootBlockSize || string(image[:3]) != "DOS" || image[3] > 7 {
		return nil, fmt.Errorf("not a recognized AmigaDOS ADF")
	}

	root := binary.BigEndian.Uint32(image[8:12])
	if root == 0 {
		root = expectedRoot
	}
	result := &FilesystemAnalysis{RootBlock: root}
	if root >= uint32(blocks) {
		result.Warnings = append(result.Warnings, fmt.Sprintf("root block %d is outside image", root))
		return result, nil
	}

	rootBlock := block(image, root)
	if rootBlock == nil || be32(rootBlock, 0) != primaryHeaderType || int32(be32(rootBlock, secondaryTypeWord)) != secondaryRoot {
		result.Warnings = append(result.Warnings, fmt.Sprintf("block %d is not a valid root header", root))
		return result, nil
	}
	result.RootBlockValid = true

	visited := map[uint32]bool{root: true}
	walkDirectory(image, rootBlock, "", 0, visited, result)
	return result, nil
}

func walkDirectory(image, dirBlock []byte, parent string, depth int, visited map[uint32]bool, result *FilesystemAnalysis) {
	if depth > maxTraversalDepth {
		result.Warnings = append(result.Warnings, "directory traversal depth limit reached")
		return
	}
	hashSize := be32(dirBlock, 3)
	if hashSize == 0 || hashSize > maxHashTableWords {
		result.Warnings = append(result.Warnings, fmt.Sprintf("invalid directory hash table size %d", hashSize))
		return
	}

	for i := uint32(0); i < hashSize; i++ {
		current := be32(dirBlock, int(6+i))
		chainSeen := make(map[uint32]bool)
		for current != 0 {
			if chainSeen[current] {
				result.Warnings = append(result.Warnings, fmt.Sprintf("hash chain loop at block %d", current))
				break
			}
			chainSeen[current] = true

			entryBlock := block(image, current)
			if entryBlock == nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("directory entry block %d is outside image", current))
				break
			}
			next := be32(entryBlock, hashChainWord)
			if be32(entryBlock, 0) != primaryHeaderType {
				result.Warnings = append(result.Warnings, fmt.Sprintf("block %d is not a header block", current))
				current = next
				continue
			}

			name, ok := bstrName(entryBlock)
			if !ok {
				result.Warnings = append(result.Warnings, fmt.Sprintf("block %d has invalid name", current))
				current = next
				continue
			}
			entryPath := path.Join(parent, name)
			secondary := int32(be32(entryBlock, secondaryTypeWord))
			switch secondary {
			case secondaryFile:
				result.Entries = append(result.Entries, FilesystemEntry{Path: entryPath, Name: name, Type: "file", HeaderBlock: current})
				result.FileCount++
			case secondaryDirectory:
				result.Entries = append(result.Entries, FilesystemEntry{Path: entryPath, Name: name, Type: "directory", HeaderBlock: current})
				result.DirectoryCount++
				if visited[current] {
					result.Warnings = append(result.Warnings, fmt.Sprintf("directory loop at block %d", current))
				} else {
					visited[current] = true
					walkDirectory(image, entryBlock, entryPath, depth+1, visited, result)
				}
			default:
				result.Warnings = append(result.Warnings, fmt.Sprintf("block %d has unsupported secondary type %d", current, secondary))
			}
			current = next
		}
	}
}

func block(image []byte, number uint32) []byte {
	off := uint64(number) * blockSize
	end := off + blockSize
	if end > uint64(len(image)) {
		return nil
	}
	return image[off:end]
}

func be32(block []byte, word int) uint32 {
	off := word * 4
	return binary.BigEndian.Uint32(block[off : off+4])
}

func bstrName(block []byte) (string, bool) {
	if len(block) < blockSize {
		return "", false
	}
	n := int(block[nameOffset])
	if n < 1 || n > 30 || nameOffset+1+n > len(block) {
		return "", false
	}
	return string(block[nameOffset+1 : nameOffset+1+n]), true
}
