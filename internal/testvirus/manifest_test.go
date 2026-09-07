package testvirus

import (
	"strings"
	"testing"
)

func TestDecodeValidManifest(t *testing.T) {
	const input = `{
  "schema": 1,
  "corpus": "amiga-testvirus",
  "samples": [
    {
      "id": "sample-1",
      "name": "Synthetic Amiga AV test",
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "synthetic": true,
      "source": "qualification fixture",
      "expected_detections": ["test-virus"]
    }
  ]
}`
	m, err := Decode(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Samples) != 1 || !m.Samples[0].Synthetic {
		t.Fatalf("unexpected manifest: %#v", m)
	}
}

func TestRejectsNonSyntheticSample(t *testing.T) {
	const input = `{
  "schema": 1,
  "corpus": "amiga-testvirus",
  "samples": [
    {
      "id": "sample-1",
      "name": "bad classification",
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "synthetic": false,
      "source": "fixture"
    }
  ]
}`
	if _, err := Decode(strings.NewReader(input)); err == nil {
		t.Fatal("non-synthetic sample accepted")
	}
}

func TestRejectsBadSHA256(t *testing.T) {
	m := Manifest{Schema: 1, Corpus: "amiga-testvirus", Samples: []Sample{{
		ID: "bad-sha", Name: "bad sha", SHA256: "xyz", Synthetic: true, Source: "fixture",
	}}}
	if err := m.Validate(); err == nil {
		t.Fatal("bad sha256 accepted")
	}
}

func TestRejectsDuplicateID(t *testing.T) {
	sample := Sample{
		ID: "duplicate", Name: "fixture", SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Synthetic: true, Source: "fixture",
	}
	m := Manifest{Schema: 1, Corpus: "amiga-testvirus", Samples: []Sample{sample, sample}}
	if err := m.Validate(); err == nil {
		t.Fatal("duplicate id accepted")
	}
}
