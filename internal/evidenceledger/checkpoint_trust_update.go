package evidenceledger

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	CheckpointTrustUpdateSchema    = "aaa-evidence-ledger-checkpoint-trust-update-v1"
	CheckpointTrustUpdateAlgorithm = "ed25519"
)

type CheckpointTrustUpdate struct {
	Schema           string `json:"schema"`
	Algorithm        string `json:"algorithm"`
	Sequence         uint64 `json:"sequence"`
	TrustStoreSHA256 string `json:"trust_store_sha256"`
	RootKeyID        string `json:"root_key_id"`
	Signature        string `json:"signature"`
}

func (u CheckpointTrustUpdate) Validate() error {
	if u.Schema != CheckpointTrustUpdateSchema {
		return fmt.Errorf("unsupported checkpoint trust update schema %q", u.Schema)
	}
	if u.Algorithm != CheckpointTrustUpdateAlgorithm {
		return fmt.Errorf("unsupported checkpoint trust update algorithm %q", u.Algorithm)
	}
	if u.Sequence == 0 {
		return errors.New("checkpoint trust update sequence must be greater than zero")
	}
	if !isSHA256(u.TrustStoreSHA256) {
		return errors.New("invalid checkpoint trust store SHA-256")
	}
	if !isSHA256(u.RootKeyID) {
		return errors.New("invalid checkpoint trust root key id")
	}
	if len(u.Signature) != ed25519.SignatureSize*2 || u.Signature != strings.ToLower(u.Signature) {
		return errors.New("checkpoint trust update signature must be lowercase hexadecimal")
	}
	raw, err := hex.DecodeString(u.Signature)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return errors.New("checkpoint trust update signature must encode 64 Ed25519 bytes")
	}
	return nil
}

func (u CheckpointTrustUpdate) MarshalDeterministic() ([]byte, error) {
	if err := u.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func DecodeCheckpointTrustUpdateStrict(data []byte) (CheckpointTrustUpdate, error) {
	var update CheckpointTrustUpdate
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&update); err != nil {
		return CheckpointTrustUpdate{}, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return CheckpointTrustUpdate{}, errors.New("checkpoint trust update contains trailing JSON data")
		}
		return CheckpointTrustUpdate{}, err
	}
	if err := update.Validate(); err != nil {
		return CheckpointTrustUpdate{}, err
	}
	return update, nil
}

func SignCheckpointTrustStore(storeBytes []byte, sequence uint64, rootPrivate ed25519.PrivateKey) (CheckpointTrustUpdate, error) {
	if sequence == 0 {
		return CheckpointTrustUpdate{}, errors.New("checkpoint trust update sequence must be greater than zero")
	}
	if len(rootPrivate) != ed25519.PrivateKeySize {
		return CheckpointTrustUpdate{}, errors.New("invalid Ed25519 checkpoint trust root private key length")
	}
	if _, err := DecodeCheckpointTrustStoreStrict(storeBytes); err != nil {
		return CheckpointTrustUpdate{}, fmt.Errorf("invalid checkpoint trust store: %w", err)
	}
	public := rootPrivate.Public().(ed25519.PublicKey)
	rootID := checkpointKeyID(public)
	sum := sha256.Sum256(storeBytes)
	update := CheckpointTrustUpdate{
		Schema:           CheckpointTrustUpdateSchema,
		Algorithm:        CheckpointTrustUpdateAlgorithm,
		Sequence:         sequence,
		TrustStoreSHA256: hex.EncodeToString(sum[:]),
		RootKeyID:        rootID,
	}
	update.Signature = hex.EncodeToString(ed25519.Sign(rootPrivate, checkpointTrustUpdateMessage(update)))
	return update, update.Validate()
}

func VerifyCheckpointTrustStoreUpdate(storeBytes []byte, update CheckpointTrustUpdate, pinnedRoot ed25519.PublicKey, currentSequence uint64) (CheckpointTrustStore, error) {
	if err := update.Validate(); err != nil {
		return CheckpointTrustStore{}, err
	}
	if len(pinnedRoot) != ed25519.PublicKeySize {
		return CheckpointTrustStore{}, errors.New("pinned Ed25519 checkpoint trust root public key is required")
	}
	if update.Sequence <= currentSequence {
		return CheckpointTrustStore{}, fmt.Errorf("checkpoint trust update sequence %d is not newer than current sequence %d", update.Sequence, currentSequence)
	}
	store, err := DecodeCheckpointTrustStoreStrict(storeBytes)
	if err != nil {
		return CheckpointTrustStore{}, err
	}
	if checkpointKeyID(pinnedRoot) != update.RootKeyID {
		return CheckpointTrustStore{}, errors.New("pinned checkpoint trust root public key does not match root_key_id")
	}
	sum := sha256.Sum256(storeBytes)
	if hex.EncodeToString(sum[:]) != update.TrustStoreSHA256 {
		return CheckpointTrustStore{}, errors.New("checkpoint trust store SHA-256 does not match update")
	}
	sig, _ := hex.DecodeString(update.Signature)
	if !ed25519.Verify(pinnedRoot, checkpointTrustUpdateMessage(update), sig) {
		return CheckpointTrustStore{}, errors.New("invalid checkpoint trust update signature")
	}
	return store, nil
}

func checkpointTrustUpdateMessage(update CheckpointTrustUpdate) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%d\n%s\n%s\n",
		CheckpointTrustUpdateSchema,
		CheckpointTrustUpdateAlgorithm,
		update.Sequence,
		update.TrustStoreSHA256,
		update.RootKeyID,
	))
}
