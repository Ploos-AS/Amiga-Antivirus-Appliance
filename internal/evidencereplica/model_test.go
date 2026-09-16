package evidencereplica

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

const testSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestBuildReceiptDeterministic(t *testing.T) {
	created := time.Date(2026, 9, 16, 1, 2, 3, 400, time.FixedZone("test", 2*60*60))
	r, err := BuildReceipt(KindEvidenceBundle, testSHA, 123, created, "case 1")
	if err != nil {
		t.Fatal(err)
	}
	if r.CreatedAt != "2026-09-15T23:02:03.0000004Z" {
		t.Fatalf("unexpected canonical created_at: %q", r.CreatedAt)
	}
	if r.ReplicaName != "aaa-replica-v1/objects/sha256/01/"+testSHA {
		t.Fatalf("unexpected replica name: %q", r.ReplicaName)
	}
	a, err := r.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) || len(a) == 0 || a[len(a)-1] != '\n' {
		t.Fatal("receipt encoding is not deterministic LF-terminated JSON")
	}
	decoded, err := DecodeReceiptStrict(a)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != r {
		t.Fatalf("round trip mismatch: %#v != %#v", decoded, r)
	}
}

func TestReceiptRejectsInvalidValues(t *testing.T) {
	base, err := BuildReceipt(KindEvidenceBundle, testSHA, 1, time.Unix(0, 0), "")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*Receipt)
	}{
		{"schema", func(r *Receipt) { r.Schema = "wrong" }},
		{"kind", func(r *Receipt) { r.ObjectKind = "unknown" }},
		{"uppercase sha", func(r *Receipt) { r.SHA256 = strings.ToUpper(testSHA) }},
		{"negative size", func(r *Receipt) { r.Size = -1 }},
		{"absolute name", func(r *Receipt) { r.ReplicaName = "/tmp/object" }},
		{"backslash name", func(r *Receipt) { r.ReplicaName = "aaa-replica-v1\\object" }},
		{"control note", func(r *Receipt) { r.Note = "bad\nnote" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.edit(&r)
			if err := r.Validate(); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
}

func TestDecodeReceiptStrict(t *testing.T) {
	r, err := BuildReceipt(KindLedgerCheckpoint, testSHA, 9, time.Unix(0, 0), "")
	if err != nil {
		t.Fatal(err)
	}
	good, err := r.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	cases := [][]byte{
		bytes.TrimSuffix(good, []byte("\n")),
		append(append([]byte{}, good...), []byte("{}\n")...),
		bytes.Replace(good, []byte("\"schema\":"), []byte("\"unknown\":1,\"schema\":"), 1),
		append([]byte(" "), good...),
	}
	for i, data := range cases {
		if _, err := DecodeReceiptStrict(data); err == nil {
			t.Fatalf("case %d: expected strict decode failure", i)
		}
	}
}
