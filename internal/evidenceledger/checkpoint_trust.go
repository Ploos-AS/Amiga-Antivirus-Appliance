package evidenceledger

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

const (
	CheckpointTrustStoreSchema = "aaa-evidence-ledger-checkpoint-trust-store-v1"
	CheckpointTrustKeyActive   = "active"
	CheckpointTrustKeyRevoked  = "revoked"
)

type CheckpointTrustStore struct {
	Schema string               `json:"schema"`
	Keys   []CheckpointTrustKey `json:"keys"`
}

type CheckpointTrustKey struct {
	KeyID     string     `json:"key_id"`
	PublicKey string     `json:"public_key"`
	Status    string     `json:"status"`
	Label     string     `json:"label,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	NotAfter  *time.Time `json:"not_after,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

func (k CheckpointTrustKey) Validate() error {
	if !isSHA256(k.KeyID) {
		return errors.New("invalid checkpoint trust key id")
	}
	if len(k.PublicKey) != ed25519.PublicKeySize*2 || k.PublicKey != strings.ToLower(k.PublicKey) {
		return errors.New("checkpoint public_key must be 32 raw Ed25519 bytes encoded as lowercase hexadecimal")
	}
	raw, err := hex.DecodeString(k.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return errors.New("checkpoint public_key must be 32 raw Ed25519 bytes encoded as lowercase hexadecimal")
	}
	if checkpointKeyID(ed25519.PublicKey(raw)) != k.KeyID {
		return errors.New("checkpoint trust key id does not match public_key")
	}
	if k.Status != CheckpointTrustKeyActive && k.Status != CheckpointTrustKeyRevoked {
		return fmt.Errorf("unsupported checkpoint trust key status %q", k.Status)
	}
	if strings.TrimSpace(k.Label) != k.Label {
		return errors.New("checkpoint trust key label must not have leading or trailing whitespace")
	}
	if strings.ContainsAny(k.Label, "\r\n\x00") {
		return errors.New("checkpoint trust key label contains forbidden control characters")
	}
	if k.NotBefore != nil && k.NotBefore.Location() != time.UTC {
		return errors.New("checkpoint not_before must use UTC")
	}
	if k.NotAfter != nil && k.NotAfter.Location() != time.UTC {
		return errors.New("checkpoint not_after must use UTC")
	}
	if k.RevokedAt != nil && k.RevokedAt.Location() != time.UTC {
		return errors.New("checkpoint revoked_at must use UTC")
	}
	if k.NotBefore != nil && k.NotAfter != nil && !k.NotAfter.After(*k.NotBefore) {
		return errors.New("checkpoint not_after must be after not_before")
	}
	if k.Status == CheckpointTrustKeyActive && k.RevokedAt != nil {
		return errors.New("active checkpoint trust key must not have revoked_at")
	}
	return nil
}

func (s CheckpointTrustStore) Validate() error {
	if s.Schema != CheckpointTrustStoreSchema {
		return fmt.Errorf("unsupported checkpoint trust store schema %q", s.Schema)
	}
	if len(s.Keys) == 0 {
		return errors.New("checkpoint trust store must contain at least one key")
	}
	seen := make(map[string]struct{}, len(s.Keys))
	for i, key := range s.Keys {
		if err := key.Validate(); err != nil {
			return fmt.Errorf("checkpoint trust key %d: %w", i, err)
		}
		if _, ok := seen[key.KeyID]; ok {
			return fmt.Errorf("duplicate checkpoint trust key id %s", key.KeyID)
		}
		seen[key.KeyID] = struct{}{}
	}
	return nil
}

func (s CheckpointTrustStore) MarshalDeterministic() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	canonical := s
	canonical.Keys = append([]CheckpointTrustKey(nil), s.Keys...)
	sort.Slice(canonical.Keys, func(i, j int) bool { return canonical.Keys[i].KeyID < canonical.Keys[j].KeyID })
	data, err := json.MarshalIndent(canonical, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func DecodeCheckpointTrustStoreStrict(data []byte) (CheckpointTrustStore, error) {
	var store CheckpointTrustStore
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&store); err != nil {
		return CheckpointTrustStore{}, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return CheckpointTrustStore{}, errors.New("checkpoint trust store contains trailing JSON data")
		}
		return CheckpointTrustStore{}, err
	}
	if err := store.Validate(); err != nil {
		return CheckpointTrustStore{}, err
	}
	return store, nil
}

func (s CheckpointTrustStore) ResolveTrustedKey(signerKeyID string, now time.Time) (ed25519.PublicKey, CheckpointTrustKey, error) {
	if err := s.Validate(); err != nil {
		return nil, CheckpointTrustKey{}, err
	}
	if now.IsZero() {
		return nil, CheckpointTrustKey{}, errors.New("checkpoint verification time is required")
	}
	now = now.UTC()
	for _, key := range s.Keys {
		if key.KeyID != signerKeyID {
			continue
		}
		if key.Status == CheckpointTrustKeyRevoked {
			return nil, CheckpointTrustKey{}, fmt.Errorf("checkpoint signer key %s is revoked", signerKeyID)
		}
		if key.NotBefore != nil && now.Before(*key.NotBefore) {
			return nil, CheckpointTrustKey{}, fmt.Errorf("checkpoint signer key %s is not yet valid", signerKeyID)
		}
		if key.NotAfter != nil && !now.Before(*key.NotAfter) {
			return nil, CheckpointTrustKey{}, fmt.Errorf("checkpoint signer key %s is expired", signerKeyID)
		}
		raw, _ := hex.DecodeString(key.PublicKey)
		return ed25519.PublicKey(raw), key, nil
	}
	return nil, CheckpointTrustKey{}, fmt.Errorf("checkpoint signer key %s is not present in trust store", signerKeyID)
}

func VerifyLedgerAgainstCheckpointTrustStore(ledger []byte, checkpoint Checkpoint, store CheckpointTrustStore, now time.Time) (CheckpointTrustKey, error) {
	if err := checkpoint.Validate(); err != nil {
		return CheckpointTrustKey{}, err
	}
	publicKey, key, err := store.ResolveTrustedKey(checkpoint.SignerKeyID, now)
	if err != nil {
		return CheckpointTrustKey{}, err
	}
	if err := VerifyLedgerAgainstCheckpoint(ledger, checkpoint, publicKey); err != nil {
		return CheckpointTrustKey{}, err
	}
	return key, nil
}
