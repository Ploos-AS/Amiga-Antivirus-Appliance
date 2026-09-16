package evidencereplica

import (
	"strings"
	"testing"
	"time"
)

func sessionTestObject(t *testing.T, kind ObjectKind, sha string, result SessionResult) SessionObject {
	t.Helper()
	name, err := ObjectName(sha)
	if err != nil {
		t.Fatal(err)
	}
	return SessionObject{ObjectKind: kind, SHA256: sha, Size: 123, ReplicaName: name, Result: result}
}

func TestSessionIDIndependentOfOrderAndTime(t *testing.T) {
	a := sessionTestObject(t, KindEvidenceBundle, strings.Repeat("a", 64), ResultReplicated)
	b := sessionTestObject(t, KindLedgerCheckpoint, strings.Repeat("b", 64), ResultAlreadyPresent)
	s1, err := BuildSession([]SessionObject{b, a}, time.Unix(10, 0), "")
	if err != nil { t.Fatal(err) }
	s2, err := BuildSession([]SessionObject{a, b}, time.Unix(20, 0), "")
	if err != nil { t.Fatal(err) }
	if s1.SessionID != s2.SessionID { t.Fatalf("session IDs differ: %s != %s", s1.SessionID, s2.SessionID) }
	if s1.Objects[0].ObjectKind != KindEvidenceBundle { t.Fatalf("objects not sorted: %#v", s1.Objects) }
}

func TestSessionIDIgnoresResults(t *testing.T) {
	a := sessionTestObject(t, KindEvidenceBundle, strings.Repeat("a", 64), ResultReplicated)
	b := a
	b.Result = ResultFailed
	b.Error = "copy-failed"
	id1, err := SessionID([]SessionObject{a})
	if err != nil { t.Fatal(err) }
	id2, err := SessionID([]SessionObject{b})
	if err != nil { t.Fatal(err) }
	if id1 != id2 { t.Fatalf("result changed intent identity") }
}

func TestSessionRejectsDuplicateIntent(t *testing.T) {
	a := sessionTestObject(t, KindEvidenceBundle, strings.Repeat("a", 64), ResultReplicated)
	if _, err := BuildSession([]SessionObject{a, a}, time.Unix(0, 0), ""); err == nil { t.Fatal("expected duplicate rejection") }
}

func TestSessionDeterministicRoundTrip(t *testing.T) {
	a := sessionTestObject(t, KindEvidenceBundle, strings.Repeat("a", 64), ResultReplicated)
	s, err := BuildSession([]SessionObject{a}, time.Unix(0, 0), "operator")
	if err != nil { t.Fatal(err) }
	data, err := s.MarshalDeterministic()
	if err != nil { t.Fatal(err) }
	if len(data) == 0 || data[len(data)-1] != '\n' { t.Fatal("missing LF") }
	decoded, err := DecodeSessionStrict(data)
	if err != nil { t.Fatal(err) }
	if decoded.SessionID != s.SessionID { t.Fatal("round trip changed session ID") }
}

func TestSessionStrictDecodeRejectsUnknownField(t *testing.T) {
	a := sessionTestObject(t, KindEvidenceBundle, strings.Repeat("a", 64), ResultReplicated)
	s, err := BuildSession([]SessionObject{a}, time.Unix(0, 0), "")
	if err != nil { t.Fatal(err) }
	data, err := s.MarshalDeterministic()
	if err != nil { t.Fatal(err) }
	bad := strings.Replace(string(data), "{", "{\"unknown\":true,", 1)
	if _, err := DecodeSessionStrict([]byte(bad)); err == nil { t.Fatal("expected unknown-field rejection") }
}

func TestSessionRejectsNonCanonicalTime(t *testing.T) {
	a := sessionTestObject(t, KindEvidenceBundle, strings.Repeat("a", 64), ResultReplicated)
	s, err := BuildSession([]SessionObject{a}, time.Unix(0, 0), "")
	if err != nil { t.Fatal(err) }
	s.CreatedAt = "1970-01-01T01:00:00+01:00"
	if err := s.Validate(); err == nil { t.Fatal("expected non-UTC timestamp rejection") }
}

func TestSessionFailedObjectRequiresPortableError(t *testing.T) {
	a := sessionTestObject(t, KindEvidenceBundle, strings.Repeat("a", 64), ResultFailed)
	a.Error = "/tmp/source: copy failed"
	id, err := SessionID([]SessionObject{a})
	if err != nil { t.Fatal(err) }
	s := Session{Schema: SessionSchema, CreatedAt: time.Unix(0, 0).UTC().Format(time.RFC3339Nano), SessionID: id, Objects: []SessionObject{a}}
	if err := s.Validate(); err == nil { t.Fatal("expected host-path error rejection") }
}

func TestSessionRejectsUnsortedObjects(t *testing.T) {
	a := sessionTestObject(t, KindEvidenceBundle, strings.Repeat("a", 64), ResultReplicated)
	b := sessionTestObject(t, KindLedgerCheckpoint, strings.Repeat("b", 64), ResultReplicated)
	id, err := SessionID([]SessionObject{a, b})
	if err != nil { t.Fatal(err) }
	s := Session{Schema: SessionSchema, CreatedAt: time.Unix(0, 0).UTC().Format(time.RFC3339Nano), SessionID: id, Objects: []SessionObject{b, a}}
	if err := s.Validate(); err == nil { t.Fatal("expected deterministic-order rejection") }
}
