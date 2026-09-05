package hunk

import (
	"encoding/binary"
	"fmt"
)

const (
	HUNK_UNIT    = 999
	HUNK_NAME    = 1000
	HUNK_CODE    = 1001
	HUNK_DATA    = 1002
	HUNK_BSS     = 1003
	HUNK_RELOC32 = 1004
	HUNK_RELOC16 = 1005
	HUNK_RELOC8  = 1006
	HUNK_EXT     = 1007
	HUNK_SYMBOL  = 1008
	HUNK_DEBUG   = 1009
	HUNK_END     = 1010
	HUNK_HEADER  = 1011
	HUNK_OVERLAY = 1013
	HUNK_BREAK   = 1014
)

const hunkTypeMask = 0x3fffffff

type Segment struct {
	Type      string `json:"type"`
	Longwords uint32 `json:"longwords"`
	Bytes     uint64 `json:"bytes"`
}

type Analysis struct {
	Recognized bool      `json:"recognized"`
	HunkCount  int       `json:"hunk_count"`
	FirstHunk  uint32    `json:"first_hunk,omitempty"`
	LastHunk   uint32    `json:"last_hunk,omitempty"`
	CodeBytes  uint64    `json:"code_bytes"`
	DataBytes  uint64    `json:"data_bytes"`
	BSSBytes   uint64    `json:"bss_bytes"`
	Segments   []Segment `json:"segments,omitempty"`
	Warnings   []string  `json:"warnings,omitempty"`
}

func Analyze(data []byte) *Analysis {
	result := &Analysis{}
	if len(data) < 4 || word(data, 0) != HUNK_HEADER {
		return result
	}
	result.Recognized = true

	pos := 1
	for {
		if pos >= len(data)/4 {
			result.Warnings = append(result.Warnings, "truncated resident-library name table")
			return result
		}
		nameWords := word(data, pos)
		pos++
		if nameWords == 0 {
			break
		}
		if !advance(&pos, nameWords, data) {
			result.Warnings = append(result.Warnings, "resident-library name extends beyond file")
			return result
		}
	}

	if pos+3 > len(data)/4 {
		result.Warnings = append(result.Warnings, "truncated HUNK_HEADER table")
		return result
	}
	tableSize := word(data, pos)
	result.FirstHunk = word(data, pos+1)
	result.LastHunk = word(data, pos+2)
	pos += 3
	if tableSize == 0 || result.LastHunk < result.FirstHunk || uint64(result.LastHunk-result.FirstHunk)+1 > uint64(tableSize) {
		result.Warnings = append(result.Warnings, "invalid HUNK_HEADER range")
		return result
	}
	if uint64(pos)+uint64(tableSize) > uint64(len(data)/4) {
		result.Warnings = append(result.Warnings, "truncated HUNK_HEADER size table")
		return result
	}
	pos += int(tableSize)

	for pos < len(data)/4 {
		rawType := word(data, pos)
		pos++
		typ := rawType & hunkTypeMask
		switch typ {
		case HUNK_CODE, HUNK_DATA:
			if pos >= len(data)/4 {
				result.Warnings = append(result.Warnings, "truncated hunk length")
				return result
			}
			longwords := word(data, pos) & hunkTypeMask
			pos++
			if !advance(&pos, longwords, data) {
				result.Warnings = append(result.Warnings, fmt.Sprintf("%s payload extends beyond file", typeName(typ)))
				return result
			}
			seg := Segment{Type: typeName(typ), Longwords: longwords, Bytes: uint64(longwords) * 4}
			result.Segments = append(result.Segments, seg)
			result.HunkCount++
			if typ == HUNK_CODE {
				result.CodeBytes += seg.Bytes
			} else {
				result.DataBytes += seg.Bytes
			}
		case HUNK_BSS:
			if pos >= len(data)/4 {
				result.Warnings = append(result.Warnings, "truncated BSS length")
				return result
			}
			longwords := word(data, pos) & hunkTypeMask
			pos++
			seg := Segment{Type: "bss", Longwords: longwords, Bytes: uint64(longwords) * 4}
			result.Segments = append(result.Segments, seg)
			result.HunkCount++
			result.BSSBytes += seg.Bytes
		case HUNK_END:
			// Segment terminator; no payload.
		case HUNK_NAME, HUNK_DEBUG:
			if pos >= len(data)/4 {
				result.Warnings = append(result.Warnings, fmt.Sprintf("truncated %s length", typeName(typ)))
				return result
			}
			n := word(data, pos)
			pos++
			if !advance(&pos, n, data) {
				result.Warnings = append(result.Warnings, fmt.Sprintf("%s payload extends beyond file", typeName(typ)))
				return result
			}
		case HUNK_RELOC32, HUNK_RELOC16, HUNK_RELOC8:
			for {
				if pos >= len(data)/4 {
					result.Warnings = append(result.Warnings, "truncated relocation table")
					return result
				}
				count := word(data, pos)
				pos++
				if count == 0 {
					break
				}
				if pos >= len(data)/4 {
					result.Warnings = append(result.Warnings, "truncated relocation target")
					return result
				}
				pos++ // target hunk number
				if !advance(&pos, count, data) {
					result.Warnings = append(result.Warnings, "relocation offsets extend beyond file")
					return result
				}
			}
		case HUNK_SYMBOL:
			for {
				if pos >= len(data)/4 {
					result.Warnings = append(result.Warnings, "truncated symbol table")
					return result
				}
				nameWords := word(data, pos)
				pos++
				if nameWords == 0 {
					break
				}
				if !advance(&pos, nameWords, data) || pos >= len(data)/4 {
					result.Warnings = append(result.Warnings, "symbol entry extends beyond file")
					return result
				}
				pos++ // symbol value
			}
		case HUNK_UNIT, HUNK_EXT, HUNK_OVERLAY, HUNK_BREAK:
			result.Warnings = append(result.Warnings, fmt.Sprintf("unsupported hunk type %d", typ))
			return result
		default:
			result.Warnings = append(result.Warnings, fmt.Sprintf("unknown hunk type %d", typ))
			return result
		}
	}

	return result
}

func word(data []byte, index int) uint32 {
	off := index * 4
	return binary.BigEndian.Uint32(data[off : off+4])
}

func advance(pos *int, count uint32, data []byte) bool {
	end := uint64(*pos) + uint64(count)
	if end > uint64(len(data)/4) {
		return false
	}
	*pos = int(end)
	return true
}

func typeName(t uint32) string {
	switch t {
	case HUNK_CODE:
		return "code"
	case HUNK_DATA:
		return "data"
	case HUNK_BSS:
		return "bss"
	case HUNK_NAME:
		return "name"
	case HUNK_DEBUG:
		return "debug"
	default:
		return fmt.Sprintf("hunk-%d", t)
	}
}
