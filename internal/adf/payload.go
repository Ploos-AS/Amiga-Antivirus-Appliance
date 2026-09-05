package adf

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const (
	fileByteSizeWord  = 81
	fileExtensionWord = 126
	fileDataBaseWord  = 6
	fileDataSlots     = 72
	primaryDataType   = 8
	primaryListType   = 16
)

type FilePayloadAnalysis struct {
	Size       uint32 `json:"size"`
	SHA256     string `json:"sha256,omitempty"`
	DataBlocks int    `json:"data_blocks"`
	Complete   bool   `json:"complete"`
	Warning    string `json:"warning,omitempty"`
}

func analyzeFilePayload(image []byte, headerNumber uint32, dosType uint8) FilePayloadAnalysis {
	header := block(image, headerNumber)
	if header == nil {
		return FilePayloadAnalysis{Warning: fmt.Sprintf("file header block %d is outside image", headerNumber)}
	}

	fileSize := be32(header, fileByteSizeWord)
	result := FilePayloadAnalysis{Size: fileSize}
	if fileSize == 0 {
		sum := sha256.Sum256(nil)
		result.SHA256 = hex.EncodeToString(sum[:])
		result.Complete = true
		return result
	}

	var payload []byte
	current := headerNumber
	seen := make(map[uint32]bool)
	for current != 0 {
		if seen[current] {
			result.Warning = fmt.Sprintf("file extension loop at block %d", current)
			return result
		}
		seen[current] = true

		meta := block(image, current)
		if meta == nil {
			result.Warning = fmt.Sprintf("file metadata block %d is outside image", current)
			return result
		}
		if current == headerNumber {
			if be32(meta, 0) != primaryHeaderType || int32(be32(meta, secondaryTypeWord)) != secondaryFile {
				result.Warning = fmt.Sprintf("block %d is not a file header", current)
				return result
			}
		} else if be32(meta, 0) != primaryListType || int32(be32(meta, secondaryTypeWord)) != secondaryFile {
			result.Warning = fmt.Sprintf("block %d is not a file extension", current)
			return result
		}

		used := int(be32(meta, 2))
		if used < 0 || used > fileDataSlots {
			result.Warning = fmt.Sprintf("file metadata block %d has invalid data block count %d", current, used)
			return result
		}
		for i := 0; i < used; i++ {
			pointerWord := fileDataBaseWord + fileDataSlots - 1 - i
			dataNumber := be32(meta, pointerWord)
			if dataNumber == 0 {
				result.Warning = fmt.Sprintf("file metadata block %d contains a zero data pointer", current)
				return result
			}
			data := block(image, dataNumber)
			if data == nil {
				result.Warning = fmt.Sprintf("file data block %d is outside image", dataNumber)
				return result
			}

			if dosType&1 == 0 { // OFS variants use a 24-byte data-block header.
				if be32(data, 0) != primaryDataType {
					result.Warning = fmt.Sprintf("OFS data block %d has invalid type", dataNumber)
					return result
				}
				n := int(be32(data, 3))
				if n < 0 || n > blockSize-24 {
					result.Warning = fmt.Sprintf("OFS data block %d has invalid payload size %d", dataNumber, n)
					return result
				}
				payload = append(payload, data[24:24+n]...)
			} else { // FFS variants store raw file bytes in the data block.
				payload = append(payload, data...)
			}
			result.DataBlocks++
			if uint32(len(payload)) >= fileSize {
				payload = payload[:fileSize]
				sum := sha256.Sum256(payload)
				result.SHA256 = hex.EncodeToString(sum[:])
				result.Complete = true
				return result
			}
		}

		current = be32(meta, fileExtensionWord)
	}

	result.Warning = fmt.Sprintf("file payload ended after %d bytes, expected %d", len(payload), fileSize)
	return result
}
