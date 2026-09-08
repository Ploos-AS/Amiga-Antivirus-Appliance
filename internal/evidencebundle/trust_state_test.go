package evidencebundle

import (
	"strings"
	"testing"
)

func TestTrustUpdateStateRoundTrip(t *testing.T) {
	state := TrustUpdateState{
		Schema:           TrustUpdateStateSchema,
		Sequence:         42,
		TrustStoreSHA256: strings.Repeat("a", 64),
		TrustStoreFile:   "trust-store-00000000000000000042.json",
		RootKeyID:        strings.Repeat("b", 64),
	}
	data, err := state.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeTrustUpdateStateStrict(data)
	if err != nil {
		t.Fatal(err)
	}
	if got != state {
		t.Fatalf("state mismatch: got=%+v want=%+v", got, state)
	}
}

func TestTrustUpdateStateRejectsFilenameSequenceMismatch(t *testing.T) {
	state := TrustUpdateState{
		Schema:           TrustUpdateStateSchema,
		Sequence:         2,
		TrustStoreSHA256: strings.Repeat("a", 64),
		TrustStoreFile:   "trust-store-00000000000000000001.json",
		RootKeyID:        strings.Repeat("b", 64),
	}
	if err := state.Validate(); err == nil {
		t.Fatal("sequence/filename mismatch accepted")
	}
}

func TestDecodeTrustUpdateStateRejectsUnknownAndTrailingJSON(t *testing.T) {
	base := `{"schema":"aaa-evidence-trust-update-state-v1","sequence":1,"trust_store_sha256":"` + strings.Repeat("a", 64) + `","trust_store_file":"trust-store-00000000000000000001.json","root_key_id":"` + strings.Repeat("b", 64) + `"}`
	unknown := strings.TrimSuffix(base, "}") + `,"extra":true}`
	if _, err := DecodeTrustUpdateStateStrict([]byte(unknown)); err == nil {
		t.Fatal("unknown state field accepted")
	}
	if _, err := DecodeTrustUpdateStateStrict([]byte(base + ` {}`)); err == nil {
		t.Fatal("trailing state JSON accepted")
	}
}
