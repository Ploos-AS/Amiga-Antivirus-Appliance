package signatures

import "testing"

const testHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestParseAndLookup(t *testing.T) {
	data := []byte(`{"schema":1,"entries":[{"sha256":"` + testHash + `","status":"known-malicious","name":"Test Virus","family":"test","source":"unit-test"}]}`)
	db, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	m := db.Lookup(testHash)
	if m == nil || m.Status != StatusKnownMalicious || m.Name != "Test Virus" || m.Source != "unit-test" {
		t.Fatalf("unexpected match: %+v", m)
	}
	if db.Lookup("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff") != nil {
		t.Fatal("unexpected match for unknown hash")
	}
}

func TestParseRejectsMissingProvenance(t *testing.T) {
	data := []byte(`{"schema":1,"entries":[{"sha256":"` + testHash + `","status":"known-clean","name":"Clean","source":""}]}`)
	if _, err := Parse(data); err == nil {
		t.Fatal("expected missing source to fail")
	}
}

func TestParseRejectsDuplicateHash(t *testing.T) {
	entry := `{"sha256":"` + testHash + `","status":"known-clean","name":"Clean","source":"unit-test"}`
	data := []byte(`{"schema":1,"entries":[` + entry + `,` + entry + `]}`)
	if _, err := Parse(data); err == nil {
		t.Fatal("expected duplicate hash to fail")
	}
}

func TestBundledDatabaseValid(t *testing.T) {
	db, err := LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	if db.Schema != 1 {
		t.Fatalf("unexpected schema %d", db.Schema)
	}
}
