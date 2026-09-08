package evidenceledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const (
	Schema       = "aaa-evidence-ledger-v1"
	ZeroLinkHash = "0000000000000000000000000000000000000000000000000000000000000000"
)

type Event string

const (
	EventBundleCreated       Event = "bundle-created"
	EventBundleImported      Event = "bundle-imported"
	EventBundleVerified      Event = "bundle-verified"
	EventBundleSigned        Event = "bundle-signed"
	EventTrustStoreInstalled Event = "trust-store-installed"
)

type ObjectKind string

const (
	ObjectEvidenceManifest    ObjectKind = "evidence-manifest"
	ObjectEvidenceBundle      ObjectKind = "evidence-bundle"
	ObjectEvidenceSignature   ObjectKind = "evidence-signature"
	ObjectEvidenceTrustStore  ObjectKind = "evidence-trust-store"
	ObjectEvidenceTrustUpdate ObjectKind = "evidence-trust-update"
)

type Record struct {
	Schema               string     `json:"schema"`
	Sequence             uint64     `json:"sequence"`
	RecordedAt           time.Time  `json:"recorded_at"`
	Event                Event      `json:"event"`
	ObjectSHA256         string     `json:"object_sha256"`
	ObjectKind           ObjectKind `json:"object_kind"`
	PreviousRecordSHA256 string     `json:"previous_record_sha256"`
	RecordSHA256         string     `json:"record_sha256"`
	Note                 string     `json:"note,omitempty"`
}

type Verification struct {
	Records          uint64
	TailSequence     uint64
	TailLineSHA256   string
	TailRecordSHA256 string
}

func BuildRecord(sequence uint64, recordedAt time.Time, event Event, objectKind ObjectKind, objectSHA256 string, previousLine []byte, note string) (Record, error) {
	if sequence == 0 {
		return Record{}, errors.New("ledger sequence must be greater than zero")
	}
	previousHash := ZeroLinkHash
	if sequence == 1 {
		if len(previousLine) != 0 {
			return Record{}, errors.New("first ledger record must not have a previous record")
		}
	} else {
		if len(previousLine) == 0 {
			return Record{}, errors.New("ledger record after sequence 1 requires previous record bytes")
		}
		previousHash = sha256Hex(previousLine)
	}
	if recordedAt.IsZero() {
		return Record{}, errors.New("ledger recorded_at must not be zero")
	}
	recordedAt = recordedAt.UTC()
	record := Record{
		Schema:               Schema,
		Sequence:             sequence,
		RecordedAt:           recordedAt,
		Event:                event,
		ObjectSHA256:         objectSHA256,
		ObjectKind:           objectKind,
		PreviousRecordSHA256: previousHash,
		Note:                 note,
	}
	if err := record.validateFields(); err != nil {
		return Record{}, err
	}
	record.RecordSHA256 = record.statementSHA256()
	return record, nil
}

func (r Record) MarshalDeterministic() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func (r Record) Validate() error {
	if err := r.validateFields(); err != nil {
		return err
	}
	if !isSHA256(r.RecordSHA256) {
		return errors.New("invalid ledger record SHA-256")
	}
	if r.RecordSHA256 != r.statementSHA256() {
		return errors.New("ledger record SHA-256 does not match record statement")
	}
	return nil
}

func (r Record) validateFields() error {
	if r.Schema != Schema {
		return fmt.Errorf("unsupported ledger schema %q", r.Schema)
	}
	if r.Sequence == 0 {
		return errors.New("ledger sequence must be greater than zero")
	}
	if r.RecordedAt.IsZero() {
		return errors.New("ledger recorded_at must not be zero")
	}
	if r.RecordedAt.Location() != time.UTC {
		return errors.New("ledger recorded_at must be UTC")
	}
	if !validEvent(r.Event) {
		return fmt.Errorf("unsupported ledger event %q", r.Event)
	}
	if !validObjectKind(r.ObjectKind) {
		return fmt.Errorf("unsupported ledger object kind %q", r.ObjectKind)
	}
	if !isSHA256(r.ObjectSHA256) {
		return errors.New("invalid ledger object SHA-256")
	}
	if !isSHA256(r.PreviousRecordSHA256) {
		return errors.New("invalid previous ledger record SHA-256")
	}
	if strings.ContainsAny(r.Note, "\x00\r\n") {
		return errors.New("ledger note contains a forbidden control character")
	}
	return nil
}

func (r Record) statementSHA256() string {
	noteHash := sha256Hex([]byte(r.Note))
	statement := Schema + "\n" +
		strconv.FormatUint(r.Sequence, 10) + "\n" +
		r.RecordedAt.Format(time.RFC3339Nano) + "\n" +
		string(r.Event) + "\n" +
		string(r.ObjectKind) + "\n" +
		r.ObjectSHA256 + "\n" +
		r.PreviousRecordSHA256 + "\n" +
		noteHash + "\n"
	return sha256Hex([]byte(statement))
}

func DecodeRecordStrict(line []byte) (Record, error) {
	if len(line) == 0 {
		return Record{}, errors.New("empty ledger record")
	}
	if bytes.ContainsAny(line, "\r\n") {
		return Record{}, errors.New("ledger record input must be one JSON line without line terminator")
	}
	return decodeRecordStrict(line)
}

func Verify(data []byte) (Verification, error) {
	if len(data) == 0 {
		return Verification{}, nil
	}
	if data[len(data)-1] != '\n' {
		return Verification{}, errors.New("ledger has a partial final record")
	}
	lines := bytes.Split(data[:len(data)-1], []byte{'\n'})
	var previousLine []byte
	var result Verification
	for i, line := range lines {
		if len(line) == 0 {
			return Verification{}, fmt.Errorf("ledger record %d is blank", i+1)
		}
		record, err := decodeRecordStrict(line)
		if err != nil {
			return Verification{}, fmt.Errorf("ledger record %d: %w", i+1, err)
		}
		expectedSequence := uint64(i + 1)
		if record.Sequence != expectedSequence {
			return Verification{}, fmt.Errorf("ledger record %d has sequence %d, expected %d", i+1, record.Sequence, expectedSequence)
		}
		expectedPrevious := ZeroLinkHash
		if i > 0 {
			expectedPrevious = sha256Hex(append(append([]byte(nil), previousLine...), '\n'))
		}
		if record.PreviousRecordSHA256 != expectedPrevious {
			return Verification{}, fmt.Errorf("ledger record %d previous-record link mismatch", i+1)
		}
		previousLine = append(previousLine[:0], line...)
		lineWithLF := append(append([]byte(nil), line...), '\n')
		result.Records = expectedSequence
		result.TailSequence = record.Sequence
		result.TailLineSHA256 = sha256Hex(lineWithLF)
		result.TailRecordSHA256 = record.RecordSHA256
	}
	return result, nil
}

func decodeRecordStrict(line []byte) (Record, error) {
	var record Record
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&record); err != nil {
		return Record{}, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Record{}, errors.New("ledger record contains trailing JSON data")
		}
		return Record{}, err
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func validEvent(event Event) bool {
	switch event {
	case EventBundleCreated, EventBundleImported, EventBundleVerified, EventBundleSigned, EventTrustStoreInstalled:
		return true
	default:
		return false
	}
}

func validObjectKind(kind ObjectKind) bool {
	switch kind {
	case ObjectEvidenceManifest, ObjectEvidenceBundle, ObjectEvidenceSignature, ObjectEvidenceTrustStore, ObjectEvidenceTrustUpdate:
		return true
	default:
		return false
	}
}

func isSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
