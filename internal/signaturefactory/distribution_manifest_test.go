package signaturefactory

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestParseReleaseVersionStrictAndNumericComparison(t *testing.T) {
	valid := []string{"0.0.0", "1.2.3", "10.20.300"}
	for _, value := range valid {
		parsed, err := ParseReleaseVersion(value)
		if err != nil {
			t.Fatalf("parse %q: %v", value, err)
		}
		if parsed.String() != value {
			t.Fatalf("version round trip %q -> %q", value, parsed.String())
		}
	}
	invalid := []string{"", "1", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.03", "v1.2.3", "1.2.-1", "1.2.3-alpha"}
	for _, value := range invalid {
		if _, err := ParseReleaseVersion(value); err == nil {
			t.Fatalf("expected %q to fail", value)
		}
	}
	a, _ := ParseReleaseVersion("1.10.0")
	b, _ := ParseReleaseVersion("1.2.99")
	if a.Compare(b) <= 0 {
		t.Fatal("numeric version comparison must not use lexical order")
	}
	if b.Compare(a) >= 0 || a.Compare(a) != 0 {
		t.Fatal("unexpected comparison result")
	}
}

func TestDistributionManifestCanonicalIdentityIsDeterministic(t *testing.T) {
	first := distributionManifestFixture()
	second := distributionManifestFixture()
	second.Payloads[0], second.Payloads[1] = second.Payloads[1], second.Payloads[0]

	firstBytes, err := first.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := second.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(firstBytes) != string(secondBytes) {
		t.Fatalf("canonical bytes differ:\n%s\n%s", firstBytes, secondBytes)
	}
	firstSHA, err := first.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	secondSHA, err := second.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	if firstSHA != secondSHA || len(firstSHA) != 64 {
		t.Fatalf("unexpected manifest identity %q %q", firstSHA, secondSHA)
	}
}

func TestDistributionManifestRejectsUnsafeAndUnsupportedPayloads(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DistributionManifest)
	}{
		{"absolute", func(m *DistributionManifest) { m.Payloads[0].Path = "/aaa/bootblocks.json" }},
		{"traversal", func(m *DistributionManifest) { m.Payloads[0].Path = "aaa/../bootblocks.json" }},
		{"dot", func(m *DistributionManifest) { m.Payloads[0].Path = "aaa/./bootblocks.json" }},
		{"empty segment", func(m *DistributionManifest) { m.Payloads[0].Path = "aaa//bootblocks.json" }},
		{"backslash", func(m *DistributionManifest) { m.Payloads[0].Path = `aaa\bootblocks.json` }},
		{"target path mismatch", func(m *DistributionManifest) { m.Payloads[0].Path = "aaa/bootblocks.json" }},
		{"unknown target", func(m *DistributionManifest) { m.Payloads[0].Target = DistributionTarget("future") }},
		{"bad sha", func(m *DistributionManifest) { m.Payloads[0].SHA256 = strings.Repeat("AA", 32) }},
		{"negative size", func(m *DistributionManifest) { m.Payloads[0].Size = -1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest := distributionManifestFixture()
			tc.mutate(&manifest)
			if err := manifest.Validate(); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
}

func TestDistributionManifestRejectsAmbiguityAndInvalidMetadata(t *testing.T) {
	manifest := distributionManifestFixture()
	manifest.Payloads[1].Target = manifest.Payloads[0].Target
	manifest.Payloads[1].Path = manifest.Payloads[0].Path
	if err := manifest.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate distribution target") {
		t.Fatalf("expected duplicate target failure, got %v", err)
	}

	manifest = distributionManifestFixture()
	manifest.Payloads[1].SHA256 = manifest.Payloads[0].SHA256
	if err := manifest.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate distribution payload sha256") {
		t.Fatalf("expected duplicate payload identity failure, got %v", err)
	}

	manifest = distributionManifestFixture()
	manifest.Version = "01.0.0"
	if err := manifest.Validate(); err == nil {
		t.Fatal("expected invalid version failure")
	}

	manifest = distributionManifestFixture()
	manifest.SignerKeyID = strings.Repeat("AB", 32)
	if err := manifest.Validate(); err == nil {
		t.Fatal("expected invalid signer key id failure")
	}

	manifest = distributionManifestFixture()
	manifest.CreatedAt = time.Date(2026, 9, 5, 21, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
	if err := manifest.Validate(); err == nil {
		t.Fatal("expected non-UTC timestamp failure")
	}
}

func TestDecodeDistributionManifestStrictRejectsUnknownAndTrailingData(t *testing.T) {
	manifest := distributionManifestFixture()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	unknownBase := append([]byte(nil), encoded[:len(encoded)-1]...)
	withUnknown := append(unknownBase, []byte(`,"unknown":true}`)...)
	if _, err := DecodeDistributionManifestStrict(withUnknown); err == nil {
		t.Fatal("expected unknown field to fail")
	}
	withTrailing := append(append([]byte(nil), encoded...), []byte(` {}`)...)
	if _, err := DecodeDistributionManifestStrict(withTrailing); err == nil {
		t.Fatal("expected trailing data to fail")
	}
	decoded, err := DecodeDistributionManifestStrict(encoded)
	if err != nil {
		t.Fatalf("valid manifest should decode: %v", err)
	}
	if decoded.Version != manifest.Version || len(decoded.Payloads) != len(manifest.Payloads) {
		t.Fatalf("unexpected decoded manifest: %+v", decoded)
	}
}

func distributionManifestFixture() DistributionManifest {
	return DistributionManifest{
		Schema:      DistributionSchemaVersion,
		Version:     "1.2.3",
		CreatedAt:   time.Date(2026, 9, 5, 19, 0, 0, 0, time.UTC),
		SignerKeyID: strings.Repeat("ab", 32),
		Payloads: []DistributionPayload{
			{
				Target: DistributionTargetClamAVHashes,
				Path:   "clamav/aaa.hsb",
				SHA256: strings.Repeat("22", 32),
				Size:   123,
			},
			{
				Target: DistributionTargetAAABootblocks,
				Path:   "aaa/bootblocks.json",
				SHA256: strings.Repeat("11", 32),
				Size:   456,
			},
		},
	}
}
