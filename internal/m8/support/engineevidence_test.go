package support

import (
	"strings"
	"testing"
)

func TestEngineEvidenceComponentsPreserveIdentity(t *testing.T) {
	components, err := EngineEvidenceComponents([]Component{{
		Kind:    KindXVS,
		Name:    "xvs.library",
		Version: "33.49",
		SHA256:  strings.Repeat("a", 64),
		Source:  "qualified archive",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 1 || components[0].Kind != string(KindXVS) || components[0].Version != "33.49" || components[0].SHA256 != strings.Repeat("a", 64) {
		t.Fatalf("converted component=%#v", components)
	}
}
