package support

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIdentifyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xvs.library")
	if err := os.WriteFile(path, []byte("synthetic xvs fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	component, err := IdentifyFile(KindXVS, "xvs.library", "test-fixture", "synthetic-ci", path)
	if err != nil {
		t.Fatal(err)
	}
	if component.SHA256 != "195be21d1f39f23e7d1b769259ce4db4a2af63115870b82a48507a5381a4e1df" {
		t.Fatalf("unexpected SHA-256 %q", component.SHA256)
	}
}

func TestComponentRequiresVersionAndDigest(t *testing.T) {
	component := Component{Kind: KindXVS, Name: "xvs.library"}
	if err := component.Validate(); err == nil {
		t.Fatal("incomplete component accepted")
	}
}

func TestEngineProvenanceRejectsDuplicateKinds(t *testing.T) {
	component := Component{
		Kind:    KindXVS,
		Name:    "xvs.library",
		Version: "33.49",
		SHA256:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	p := EngineProvenance{
		EngineID:      "virusz-iii",
		EngineVersion: "1.04-beta",
		Components:    []Component{component, component},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("duplicate component kind accepted")
	}
}

func TestVirusZBootblocksComponent(t *testing.T) {
	component := Component{
		Kind:    KindVirusZBootblocks,
		Name:    "VirusZ_III.Bootblocks",
		Version: "24.01.2026",
		SHA256:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	if err := component.Validate(); err != nil {
		t.Fatal(err)
	}
}
