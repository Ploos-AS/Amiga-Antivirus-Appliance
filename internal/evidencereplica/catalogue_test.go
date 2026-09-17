package evidencereplica

import (
	"strings"
	"testing"
	"time"
)

func TestCatalogueName(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	got, err := CatalogueName(sha)
	if err != nil {
		t.Fatal(err)
	}
	want := "aaa-replica-v1/receipts/sha256/ab/" + sha
	if got != want {
		t.Fatalf("CatalogueName() = %q, want %q", got, want)
	}
}

func TestDecodeCatalogueReceipt(t *testing.T) {
	objectSHA := strings.Repeat("01", 32)
	receipt, err := BuildReceipt(KindEvidenceBundle, objectSHA, 123, time.Unix(0, 0).UTC(), "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := receipt.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	record, err := DecodeCatalogueDocument(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	if record.DocumentType != CatalogueReceipt || record.Schema != Schema || record.ObjectKind != KindEvidenceBundle || record.ObjectSHA256 != objectSHA || record.Complete != nil {
		t.Fatalf("unexpected receipt record: %#v", record)
	}
	if record.SHA256 != CatalogueMetadataSHA(data) || record.Size != int64(len(data)) {
		t.Fatalf("metadata identity mismatch: %#v", record)
	}
}

func TestDecodeCatalogueCompleteSession(t *testing.T) {
	sha := strings.Repeat("02", 32)
	name, err := ObjectName(sha)
	if err != nil {
		t.Fatal(err)
	}
	session, err := BuildSession([]SessionObject{{ObjectKind: KindLedgerCheckpoint, SHA256: sha, Size: 42, ReplicaName: name, Result: ResultReplicated}}, time.Unix(0, 0).UTC(), "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := session.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	record, err := DecodeCatalogueDocument(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	if record.DocumentType != CatalogueSession || record.SessionID != session.SessionID || record.ObjectCount != 1 || record.Complete == nil || !*record.Complete {
		t.Fatalf("unexpected session record: %#v", record)
	}
}

func TestDecodeCatalogueIncompleteSession(t *testing.T) {
	sha := strings.Repeat("03", 32)
	name, err := ObjectName(sha)
	if err != nil {
		t.Fatal(err)
	}
	session, err := BuildSession([]SessionObject{{ObjectKind: KindEvidenceLedger, SHA256: sha, Size: 7, ReplicaName: name, Result: ResultFailed, Error: "destination-conflict"}}, time.Unix(0, 0).UTC(), "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := session.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	record, err := DecodeCatalogueDocument(data)
	if err != nil {
		t.Fatal(err)
	}
	if record.Complete == nil || *record.Complete {
		t.Fatalf("incomplete session reported complete: %#v", record)
	}
}

func TestDecodeCatalogueRejectsUnsupportedDocument(t *testing.T) {
	if _, err := DecodeCatalogueDocument([]byte("{\"schema\":\"unknown\"}\n")); err == nil {
		t.Fatal("expected unsupported document rejection")
	}
}

func TestDecodeCatalogueRejectsNonCanonicalReceipt(t *testing.T) {
	sha := strings.Repeat("04", 32)
	receipt, err := BuildReceipt(KindEvidenceSignature, sha, 9, time.Unix(0, 0).UTC(), "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := receipt.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	data = append([]byte(" "), data...)
	if _, err := DecodeCatalogueDocument(data); err == nil {
		t.Fatal("expected noncanonical document rejection")
	}
}

func TestCatalogueRecordValidateRejectsInvalidShape(t *testing.T) {
	sha := strings.Repeat("05", 32)
	complete := true
	cases := []CatalogueRecord{
		{SHA256: sha, Size: 1, DocumentType: CatalogueReceipt, Schema: Schema, ObjectKind: KindEvidenceBundle, ObjectSHA256: sha, Complete: &complete},
		{SHA256: sha, Size: 1, DocumentType: CatalogueSession, Schema: SessionSchema, SessionID: sha, ObjectCount: 0, Complete: &complete},
		{SHA256: sha, Size: -1, DocumentType: CatalogueReceipt, Schema: Schema, ObjectKind: KindEvidenceBundle, ObjectSHA256: sha},
	}
	for i, record := range cases {
		if err := record.Validate(); err == nil {
			t.Fatalf("case %d: expected validation failure", i)
		}
	}
}
