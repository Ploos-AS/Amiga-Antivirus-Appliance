package signaturefactory

import "testing"

func TestIndependentEvidenceSourcesDeduplicatesSharedDatabase(t *testing.T) {
	evidence := []Evidence{
		{
			Type:               "engine-detection",
			Detail:             "frontend-a detected TestVirus",
			SourceEngine:       "frontend-a",
			SourceVersion:      "1.0",
			SignatureDBVersion: "db-42",
			CorrelationKey:     "shared-db:db-42",
		},
		{
			Type:               "engine-detection",
			Detail:             "frontend-b detected TestVirus",
			SourceEngine:       "frontend-b",
			SourceVersion:      "2.0",
			SignatureDBVersion: "db-42",
			CorrelationKey:     "shared-db:db-42",
		},
		{
			Type:           "engine-detection",
			Detail:         "independent engine detected TestVirus",
			SourceEngine:   "independent-engine",
			SourceVersion:  "3.1",
			CorrelationKey: "independent-engine:internal-db-7",
		},
	}

	count, err := IndependentEvidenceSources(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected 2 independent sources, got %d", count)
	}
}

func TestAttributedEvidenceRequiresCorrelationKey(t *testing.T) {
	evidence := Evidence{
		Type:         "engine-detection",
		Detail:       "detected TestVirus",
		SourceEngine: "virusz",
	}
	if err := evidence.Validate(); err == nil {
		t.Fatal("expected attributed evidence without correlation key to fail")
	}
}

func TestUnattributedLifecycleEvidenceRemainsValid(t *testing.T) {
	evidence := Evidence{Type: "lifecycle", Detail: "promoted"}
	if err := evidence.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestIndependentCorrelationKeysAreSorted(t *testing.T) {
	evidence := []Evidence{
		{Type: "engine-detection", Detail: "z", SourceEngine: "z", CorrelationKey: "z-db"},
		{Type: "engine-detection", Detail: "a", SourceEngine: "a", CorrelationKey: "a-db"},
		{Type: "engine-detection", Detail: "a duplicate", SourceEngine: "a2", CorrelationKey: "a-db"},
	}
	keys, err := IndependentCorrelationKeys(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0] != "a-db" || keys[1] != "z-db" {
		t.Fatalf("unexpected keys: %#v", keys)
	}
}
