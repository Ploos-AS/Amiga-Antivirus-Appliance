package evidencereplica

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"
)

const Schema = "aaa-evidence-replica-receipt-v1"

type ObjectKind string

const (
	KindEvidenceBundle        ObjectKind = "evidence-bundle"
	KindEvidenceSignature     ObjectKind = "evidence-signature"
	KindEvidenceLedger        ObjectKind = "evidence-ledger"
	KindLedgerCheckpoint      ObjectKind = "ledger-checkpoint"
	KindCheckpointTrustStore  ObjectKind = "checkpoint-trust-store"
	KindCheckpointTrustUpdate ObjectKind = "checkpoint-trust-update"
)

type Receipt struct {
	Schema      string     `json:"schema"`
	CreatedAt   string     `json:"created_at"`
	ObjectKind  ObjectKind `json:"object_kind"`
	SHA256      string     `json:"sha256"`
	Size        int64      `json:"size"`
	ReplicaName string     `json:"replica_name"`
	Note        string     `json:"note,omitempty"`
}

func ObjectName(sha string) (string, error) {
	if err := validateSHA(sha); err != nil {
		return "", err
	}
	return path.Join("aaa-replica-v1", "objects", "sha256", sha[:2], sha), nil
}

func BuildReceipt(kind ObjectKind, sha string, size int64, created time.Time, note string) (Receipt, error) {
	name, err := ObjectName(sha)
	if err != nil {
		return Receipt{}, err
	}
	r := Receipt{Schema: Schema, CreatedAt: created.UTC().Format(time.RFC3339Nano), ObjectKind: kind, SHA256: sha, Size: size, ReplicaName: name, Note: note}
	if err := r.Validate(); err != nil {
		return Receipt{}, err
	}
	return r, nil
}

func (r Receipt) Validate() error {
	if r.Schema != Schema {
		return fmt.Errorf("unsupported replica receipt schema %q", r.Schema)
	}
	switch r.ObjectKind {
	case KindEvidenceBundle, KindEvidenceSignature, KindEvidenceLedger, KindLedgerCheckpoint, KindCheckpointTrustStore, KindCheckpointTrustUpdate:
	default:
		return fmt.Errorf("unsupported replica object kind %q", r.ObjectKind)
	}
	if err := validateSHA(r.SHA256); err != nil {
		return err
	}
	if r.Size < 0 {
		return errors.New("replica object size must be non-negative")
	}
	if _, err := time.Parse(time.RFC3339Nano, r.CreatedAt); err != nil {
		return fmt.Errorf("invalid created_at: %w", err)
	}
	expected, _ := ObjectName(r.SHA256)
	if r.ReplicaName != expected || path.IsAbs(r.ReplicaName) || strings.Contains(r.ReplicaName, "\\") {
		return errors.New("replica_name is not the canonical portable object name")
	}
	if strings.ContainsAny(r.Note, "\r\n\x00") {
		return errors.New("note contains control characters")
	}
	return nil
}

func (r Receipt) MarshalDeterministic() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func DecodeReceiptStrict(data []byte) (Receipt, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return Receipt{}, errors.New("replica receipt must end with LF")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r Receipt
	if err := dec.Decode(&r); err != nil {
		return Receipt{}, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Receipt{}, errors.New("replica receipt contains trailing JSON data")
		}
		return Receipt{}, err
	}
	if err := r.Validate(); err != nil {
		return Receipt{}, err
	}
	canonical, err := r.MarshalDeterministic()
	if err != nil {
		return Receipt{}, err
	}
	if !bytes.Equal(data, canonical) {
		return Receipt{}, errors.New("replica receipt is not deterministically encoded")
	}
	return r, nil
}

func validateSHA(value string) error {
	if len(value) != 64 || strings.ToLower(value) != value {
		return errors.New("sha256 must be 64 lowercase hex characters")
	}
	b, err := hex.DecodeString(value)
	if err != nil || len(b) != 32 {
		return errors.New("sha256 must be 64 lowercase hex characters")
	}
	return nil
}
