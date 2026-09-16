package evidencereplica

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

const SessionSchema = "aaa-evidence-replica-session-v1"

type SessionResult string

const (
	ResultReplicated     SessionResult = "replicated"
	ResultAlreadyPresent SessionResult = "already-present"
	ResultFailed         SessionResult = "failed"
)

type SessionObject struct {
	ObjectKind  ObjectKind    `json:"object_kind"`
	SHA256      string        `json:"sha256"`
	Size        int64         `json:"size"`
	ReplicaName string        `json:"replica_name"`
	Result      SessionResult `json:"result"`
	Error       string        `json:"error,omitempty"`
}

type Session struct {
	Schema    string          `json:"schema"`
	CreatedAt string          `json:"created_at"`
	SessionID string          `json:"session_id"`
	Objects   []SessionObject `json:"objects"`
	Note      string          `json:"note,omitempty"`
}

type sessionIntent struct {
	ObjectKind  ObjectKind `json:"object_kind"`
	SHA256      string     `json:"sha256"`
	Size        int64      `json:"size"`
	ReplicaName string     `json:"replica_name"`
}

func BuildSession(objects []SessionObject, created time.Time, note string) (Session, error) {
	ordered := append([]SessionObject(nil), objects...)
	sortSessionObjects(ordered)
	id, err := SessionID(ordered)
	if err != nil {
		return Session{}, err
	}
	s := Session{Schema: SessionSchema, CreatedAt: created.UTC().Format(time.RFC3339Nano), SessionID: id, Objects: ordered, Note: note}
	if err := s.Validate(); err != nil {
		return Session{}, err
	}
	return s, nil
}

func SessionID(objects []SessionObject) (string, error) {
	ordered := append([]SessionObject(nil), objects...)
	sortSessionObjects(ordered)
	intents := make([]sessionIntent, 0, len(ordered))
	for _, object := range ordered {
		if err := validateSessionObjectIntent(object); err != nil {
			return "", err
		}
		intents = append(intents, sessionIntent{ObjectKind: object.ObjectKind, SHA256: object.SHA256, Size: object.Size, ReplicaName: object.ReplicaName})
	}
	if len(intents) == 0 {
		return "", errors.New("replica session must contain at least one object")
	}
	for i := 1; i < len(intents); i++ {
		if intents[i] == intents[i-1] {
			return "", errors.New("replica session contains duplicate intent")
		}
	}
	data, err := json.Marshal(intents)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func (s Session) Validate() error {
	if s.Schema != SessionSchema {
		return fmt.Errorf("unsupported replica session schema %q", s.Schema)
	}
	created, err := time.Parse(time.RFC3339Nano, s.CreatedAt)
	if err != nil {
		return fmt.Errorf("invalid created_at: %w", err)
	}
	if s.CreatedAt != created.UTC().Format(time.RFC3339Nano) {
		return errors.New("created_at must use canonical UTC RFC3339Nano form")
	}
	if strings.ContainsAny(s.Note, "\r\n\x00") {
		return errors.New("note contains control characters")
	}
	if len(s.Objects) == 0 {
		return errors.New("replica session must contain at least one object")
	}
	for i, object := range s.Objects {
		if err := validateSessionObject(object); err != nil {
			return fmt.Errorf("object %d: %w", i, err)
		}
		if i > 0 && sessionObjectLess(object, s.Objects[i-1]) {
			return errors.New("replica session objects are not deterministically ordered")
		}
	}
	expected, err := SessionID(s.Objects)
	if err != nil {
		return err
	}
	if s.SessionID != expected {
		return errors.New("session_id does not match deterministic session intent")
	}
	return nil
}

func validateSessionObjectIntent(object SessionObject) error {
	r := Receipt{Schema: Schema, CreatedAt: time.Unix(0, 0).UTC().Format(time.RFC3339Nano), ObjectKind: object.ObjectKind, SHA256: object.SHA256, Size: object.Size, ReplicaName: object.ReplicaName}
	return r.Validate()
}

func validateSessionObject(object SessionObject) error {
	if err := validateSessionObjectIntent(object); err != nil {
		return err
	}
	switch object.Result {
	case ResultReplicated, ResultAlreadyPresent:
		if object.Error != "" {
			return errors.New("successful replica session object must not contain error")
		}
	case ResultFailed:
		if object.Error == "" {
			return errors.New("failed replica session object must contain error")
		}
		if strings.ContainsAny(object.Error, "\r\n\x00") || strings.Contains(object.Error, "/") || strings.Contains(object.Error, "\\") {
			return errors.New("replica session error is not portable")
		}
	default:
		return fmt.Errorf("unsupported replica session result %q", object.Result)
	}
	return nil
}

func sortSessionObjects(objects []SessionObject) {
	sort.Slice(objects, func(i, j int) bool { return sessionObjectLess(objects[i], objects[j]) })
}

func sessionObjectLess(a, b SessionObject) bool {
	if a.ObjectKind != b.ObjectKind {
		return a.ObjectKind < b.ObjectKind
	}
	if a.SHA256 != b.SHA256 {
		return a.SHA256 < b.SHA256
	}
	if a.Size != b.Size {
		return a.Size < b.Size
	}
	return a.ReplicaName < b.ReplicaName
}

func (s Session) MarshalDeterministic() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func DecodeSessionStrict(data []byte) (Session, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return Session{}, errors.New("replica session must end with LF")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Session
	if err := dec.Decode(&s); err != nil {
		return Session{}, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Session{}, errors.New("replica session contains trailing JSON data")
		}
		return Session{}, err
	}
	if err := s.Validate(); err != nil {
		return Session{}, err
	}
	canonical, err := s.MarshalDeterministic()
	if err != nil {
		return Session{}, err
	}
	if !bytes.Equal(data, canonical) {
		return Session{}, errors.New("replica session is not deterministically encoded")
	}
	return s, nil
}
