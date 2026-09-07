package acquisition

import (
	"errors"
	"sort"
)

const (
	RepeatabilityInsufficient = "insufficient"
	RepeatabilityReproducible = "reproducible"
	RepeatabilityDivergent    = "divergent"
)

// Repeatability summarizes whether multiple physical-media reads produced the same image hash.
type Repeatability struct {
	Status       string              `json:"status"`
	ReadCount    int                 `json:"read_count"`
	UniqueHashes int                 `json:"unique_hashes"`
	Hashes       map[string]int      `json:"hashes"`
	Reads        []RepeatabilityRead `json:"reads"`
}

// RepeatabilityRead binds one read ordinal to its acquisition hash and size.
type RepeatabilityRead struct {
	Read   int    `json:"read"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// CompareReads classifies repeated acquisitions without turning acquisition variance into malware evidence.
func CompareReads(evidence []Evidence) (Repeatability, error) {
	if len(evidence) == 0 {
		return Repeatability{}, errors.New("at least one acquisition is required")
	}

	out := Repeatability{
		ReadCount: len(evidence),
		Hashes:    make(map[string]int),
		Reads:     make([]RepeatabilityRead, 0, len(evidence)),
	}
	for i, e := range evidence {
		if err := e.Validate(); err != nil {
			return Repeatability{}, err
		}
		out.Hashes[e.OutputSHA256]++
		out.Reads = append(out.Reads, RepeatabilityRead{Read: i + 1, SHA256: e.OutputSHA256, Size: e.OutputSize})
	}
	out.UniqueHashes = len(out.Hashes)

	switch {
	case len(evidence) < 2:
		out.Status = RepeatabilityInsufficient
	case len(out.Hashes) == 1:
		out.Status = RepeatabilityReproducible
	default:
		out.Status = RepeatabilityDivergent
	}
	return out, nil
}

// SortedHashes returns stable hash/count pairs for human-readable output.
func (r Repeatability) SortedHashes() []RepeatabilityHash {
	keys := make([]string, 0, len(r.Hashes))
	for hash := range r.Hashes {
		keys = append(keys, hash)
	}
	sort.Strings(keys)
	out := make([]RepeatabilityHash, 0, len(keys))
	for _, hash := range keys {
		out = append(out, RepeatabilityHash{SHA256: hash, Count: r.Hashes[hash]})
	}
	return out
}

// RepeatabilityHash is one stable hash/count pair.
type RepeatabilityHash struct {
	SHA256 string `json:"sha256"`
	Count  int    `json:"count"`
}
