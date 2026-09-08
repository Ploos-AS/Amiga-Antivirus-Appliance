package evidenceledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const CheckpointTrustUpdateStateSchema = "aaa-evidence-ledger-checkpoint-trust-update-state-v1"

type CheckpointTrustUpdateState struct {
	Schema           string `json:"schema"`
	Sequence         uint64 `json:"sequence"`
	TrustStoreSHA256 string `json:"trust_store_sha256"`
	TrustStoreFile   string `json:"trust_store_file"`
	RootKeyID        string `json:"root_key_id"`
}

func CheckpointTrustStoreFilename(sequence uint64) (string, error) {
	if sequence == 0 {
		return "", errors.New("checkpoint trust store sequence must be greater than zero")
	}
	return fmt.Sprintf("checkpoint-trust-store-%020d.json", sequence), nil
}

func (s CheckpointTrustUpdateState) Validate() error {
	if s.Schema != CheckpointTrustUpdateStateSchema {
		return fmt.Errorf("unsupported checkpoint trust update state schema %q", s.Schema)
	}
	if s.Sequence == 0 {
		return errors.New("checkpoint trust update state sequence must be greater than zero")
	}
	if !isSHA256(s.TrustStoreSHA256) {
		return errors.New("invalid checkpoint trust store SHA-256 in state")
	}
	if !isSHA256(s.RootKeyID) {
		return errors.New("invalid checkpoint trust root key id in state")
	}
	expected, err := CheckpointTrustStoreFilename(s.Sequence)
	if err != nil {
		return err
	}
	if s.TrustStoreFile != expected {
		return fmt.Errorf("checkpoint trust store filename %q does not match sequence", s.TrustStoreFile)
	}
	return nil
}

func (s CheckpointTrustUpdateState) MarshalDeterministic() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func DecodeCheckpointTrustUpdateStateStrict(data []byte) (CheckpointTrustUpdateState, error) {
	var state CheckpointTrustUpdateState
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&state); err != nil {
		return CheckpointTrustUpdateState{}, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return CheckpointTrustUpdateState{}, errors.New("checkpoint trust update state contains trailing JSON data")
		}
		return CheckpointTrustUpdateState{}, err
	}
	if err := state.Validate(); err != nil {
		return CheckpointTrustUpdateState{}, err
	}
	return state, nil
}
