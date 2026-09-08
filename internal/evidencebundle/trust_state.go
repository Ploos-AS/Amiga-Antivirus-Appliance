package evidencebundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const TrustUpdateStateSchema = "aaa-evidence-trust-update-state-v1"

// TrustUpdateState records the last durably installed authenticated trust store.
// TrustStoreFile is a basename within the operator-controlled state directory.
type TrustUpdateState struct {
	Schema           string `json:"schema"`
	Sequence         uint64 `json:"sequence"`
	TrustStoreSHA256 string `json:"trust_store_sha256"`
	TrustStoreFile   string `json:"trust_store_file"`
	RootKeyID        string `json:"root_key_id"`
}

func TrustStoreFilename(sequence uint64) (string, error) {
	if sequence == 0 {
		return "", errors.New("trust store sequence must be greater than zero")
	}
	return fmt.Sprintf("trust-store-%020d.json", sequence), nil
}

func (s TrustUpdateState) Validate() error {
	if s.Schema != TrustUpdateStateSchema {
		return fmt.Errorf("unsupported trust update state schema %q", s.Schema)
	}
	if s.Sequence == 0 {
		return errors.New("trust update state sequence must be greater than zero")
	}
	if !sha256Pattern.MatchString(s.TrustStoreSHA256) {
		return errors.New("invalid trust store SHA-256 in state")
	}
	if !sha256Pattern.MatchString(s.RootKeyID) {
		return errors.New("invalid root key id in state")
	}
	expected, err := TrustStoreFilename(s.Sequence)
	if err != nil {
		return err
	}
	if s.TrustStoreFile != expected {
		return fmt.Errorf("trust store filename %q does not match sequence", s.TrustStoreFile)
	}
	return nil
}

func (s TrustUpdateState) MarshalDeterministic() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func DecodeTrustUpdateStateStrict(data []byte) (TrustUpdateState, error) {
	var state TrustUpdateState
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&state); err != nil {
		return TrustUpdateState{}, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return TrustUpdateState{}, errors.New("trust update state contains trailing JSON data")
		}
		return TrustUpdateState{}, err
	}
	if err := state.Validate(); err != nil {
		return TrustUpdateState{}, err
	}
	return state, nil
}
