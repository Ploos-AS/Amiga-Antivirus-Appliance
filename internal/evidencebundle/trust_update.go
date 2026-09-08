package evidencebundle

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
	TrustUpdateSchema    = "aaa-evidence-trust-update-v1"
	TrustUpdateAlgorithm = "ed25519"
)

// TrustUpdate authenticates one exact serialized trust store and assigns it a
// monotonically increasing operator sequence number.
type TrustUpdate struct {
	Schema           string `json:"schema"`
	Algorithm        string `json:"algorithm"`
	Sequence         uint64 `json:"sequence"`
	TrustStoreSHA256 string `json:"trust_store_sha256"`
	RootKeyID        string `json:"root_key_id"`
	Signature        string `json:"signature"`
}

func (u TrustUpdate) Validate() error {
	if u.Schema != TrustUpdateSchema {
		return fmt.Errorf("unsupported trust update schema %q", u.Schema)
	}
	if u.Algorithm != TrustUpdateAlgorithm {
		return fmt.Errorf("unsupported trust update algorithm %q", u.Algorithm)
	}
	if u.Sequence == 0 {
		return errors.New("trust update sequence must be greater than zero")
	}
	if !sha256Pattern.MatchString(u.TrustStoreSHA256) {
		return errors.New("invalid trust store SHA-256")
	}
	if !sha256Pattern.MatchString(u.RootKeyID) {
		return errors.New("invalid root key id")
	}
	if len(u.Signature) != ed25519.SignatureSize*2 || u.Signature != strings.ToLower(u.Signature) {
		return errors.New("signature must be 64 raw Ed25519 bytes encoded as lowercase hexadecimal")
	}
	raw, err := hex.DecodeString(u.Signature)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return errors.New("signature must be 64 raw Ed25519 bytes encoded as lowercase hexadecimal")
	}
	return nil
}

func (u TrustUpdate) MarshalDeterministic() ([]byte, error) {
	if err := u.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func DecodeTrustUpdateStrict(data []byte) (TrustUpdate, error) {
	var update TrustUpdate
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&update); err != nil {
		return TrustUpdate{}, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return TrustUpdate{}, errors.New("trust update contains trailing JSON data")
		}
		return TrustUpdate{}, err
	}
	if err := update.Validate(); err != nil {
		return TrustUpdate{}, err
	}
	return update, nil
}

// SignTrustStore authenticates the exact serialized bytes supplied by the
// operator. The trust store must itself pass strict M13.5 validation.
func SignTrustStore(storeBytes []byte, sequence uint64, rootPrivate ed25519.PrivateKey) (TrustUpdate, error) {
	if sequence == 0 {
		return TrustUpdate{}, errors.New("trust update sequence must be greater than zero")
	}
	if len(rootPrivate) != ed25519.PrivateKeySize {
		return TrustUpdate{}, errors.New("invalid Ed25519 root private key length")
	}
	if _, err := DecodeTrustStoreStrict(storeBytes); err != nil {
		return TrustUpdate{}, fmt.Errorf("invalid trust store: %w", err)
	}
	public, ok := rootPrivate.Public().(ed25519.PublicKey)
	if !ok {
		return TrustUpdate{}, errors.New("derive Ed25519 root public key")
	}
	rootID, err := KeyID(public)
	if err != nil {
		return TrustUpdate{}, err
	}
	sum := sha256.Sum256(storeBytes)
	update := TrustUpdate{
		Schema:           TrustUpdateSchema,
		Algorithm:        TrustUpdateAlgorithm,
		Sequence:         sequence,
		TrustStoreSHA256: hex.EncodeToString(sum[:]),
		RootKeyID:        rootID,
	}
	update.Signature = hex.EncodeToString(ed25519.Sign(rootPrivate, trustUpdateMessage(update)))
	if err := update.Validate(); err != nil {
		return TrustUpdate{}, err
	}
	return update, nil
}

// VerifyTrustStoreUpdate verifies the strict trust-store document, exact byte
// digest, pinned root identity, Ed25519 signature, and monotonic sequence.
func VerifyTrustStoreUpdate(storeBytes []byte, update TrustUpdate, pinnedRoot ed25519.PublicKey, currentSequence uint64) (TrustStore, error) {
	if err := update.Validate(); err != nil {
		return TrustStore{}, err
	}
	if len(pinnedRoot) != ed25519.PublicKeySize {
		return TrustStore{}, errors.New("pinned Ed25519 root public key is required")
	}
	if update.Sequence <= currentSequence {
		return TrustStore{}, fmt.Errorf("trust update sequence %d is not newer than current sequence %d", update.Sequence, currentSequence)
	}
	store, err := DecodeTrustStoreStrict(storeBytes)
	if err != nil {
		return TrustStore{}, err
	}
	rootID, err := KeyID(pinnedRoot)
	if err != nil {
		return TrustStore{}, err
	}
	if rootID != update.RootKeyID {
		return TrustStore{}, errors.New("pinned root public key does not match root_key_id")
	}
	sum := sha256.Sum256(storeBytes)
	if hex.EncodeToString(sum[:]) != update.TrustStoreSHA256 {
		return TrustStore{}, errors.New("trust store SHA-256 does not match update")
	}
	sig, _ := hex.DecodeString(update.Signature)
	if !ed25519.Verify(pinnedRoot, trustUpdateMessage(update), sig) {
		return TrustStore{}, errors.New("invalid trust update signature")
	}
	return store, nil
}

func trustUpdateMessage(update TrustUpdate) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%d\n%s\n%s\n",
		TrustUpdateSchema,
		TrustUpdateAlgorithm,
		update.Sequence,
		update.TrustStoreSHA256,
		update.RootKeyID,
	))
}
