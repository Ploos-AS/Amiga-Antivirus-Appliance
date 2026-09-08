package evidencebundle

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
	TrustStoreSchema = "aaa-evidence-trust-store-v1"
	TrustKeyActive   = "active"
	TrustKeyRevoked  = "revoked"
)

// TrustStore is an operator-supplied trust policy for M13 evidence signatures.
// It is not self-authenticating: callers must obtain the store through an
// independent trusted channel.
type TrustStore struct {
	Schema string     `json:"schema"`
	Keys   []TrustKey `json:"keys"`
}

// TrustKey binds one raw Ed25519 public key to an explicit trust status.
type TrustKey struct {
	KeyID      string     `json:"key_id"`
	PublicKey  string     `json:"public_key"`
	Status     string     `json:"status"`
	Label      string     `json:"label,omitempty"`
	NotBefore  *time.Time `json:"not_before,omitempty"`
	NotAfter   *time.Time `json:"not_after,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

func (k TrustKey) Validate() error {
	if !sha256Pattern.MatchString(k.KeyID) {
		return errors.New("invalid trust key id")
	}
	if len(k.PublicKey) != ed25519.PublicKeySize*2 || k.PublicKey != strings.ToLower(k.PublicKey) {
		return errors.New("public_key must be 32 raw Ed25519 bytes encoded as lowercase hexadecimal")
	}
	raw, err := hex.DecodeString(k.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return errors.New("public_key must be 32 raw Ed25519 bytes encoded as lowercase hexadecimal")
	}
	derived, err := KeyID(ed25519.PublicKey(raw))
	if err != nil {
		return err
	}
	if derived != k.KeyID {
		return errors.New("trust key id does not match public_key")
	}
	if k.Status != TrustKeyActive && k.Status != TrustKeyRevoked {
		return fmt.Errorf("unsupported trust key status %q", k.Status)
	}
	if strings.TrimSpace(k.Label) != k.Label {
		return errors.New("trust key label must not have leading or trailing whitespace")
	}
	if strings.ContainsAny(k.Label, "\r\n\x00") {
		return errors.New("trust key label contains forbidden control characters")
	}
	if k.NotBefore != nil && !isCanonicalUTC(*k.NotBefore) {
		return errors.New("not_before must use UTC")
	}
	if k.NotAfter != nil && !isCanonicalUTC(*k.NotAfter) {
		return errors.New("not_after must use UTC")
	}
	if k.RevokedAt != nil && !isCanonicalUTC(*k.RevokedAt) {
		return errors.New("revoked_at must use UTC")
	}
	if k.NotBefore != nil && k.NotAfter != nil && !k.NotAfter.After(*k.NotBefore) {
		return errors.New("not_after must be after not_before")
	}
	if k.Status == TrustKeyActive && k.RevokedAt != nil {
		return errors.New("active trust key must not have revoked_at")
	}
	return nil
}

func (s TrustStore) Validate() error {
	if s.Schema != TrustStoreSchema {
		return fmt.Errorf("unsupported trust store schema %q", s.Schema)
	}
	if len(s.Keys) == 0 {
		return errors.New("trust store must contain at least one key")
	}
	seen := make(map[string]struct{}, len(s.Keys))
	for i, key := range s.Keys {
		if err := key.Validate(); err != nil {
			return fmt.Errorf("trust key %d: %w", i, err)
		}
		if _, ok := seen[key.KeyID]; ok {
			return fmt.Errorf("duplicate trust key id %s", key.KeyID)
		}
		seen[key.KeyID] = struct{}{}
	}
	return nil
}

// MarshalDeterministic returns a stable representation sorted by key id.
func (s TrustStore) MarshalDeterministic() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	canonical := s
	canonical.Keys = append([]TrustKey(nil), s.Keys...)
	sort.Slice(canonical.Keys, func(i, j int) bool { return canonical.Keys[i].KeyID < canonical.Keys[j].KeyID })
	data, err := json.MarshalIndent(canonical, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// DecodeTrustStoreStrict rejects unknown fields, trailing JSON and malformed keys.
func DecodeTrustStoreStrict(data []byte) (TrustStore, error) {
	var store TrustStore
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&store); err != nil {
		return TrustStore{}, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return TrustStore{}, errors.New("trust store contains trailing JSON data")
		}
		return TrustStore{}, err
	}
	if err := store.Validate(); err != nil {
		return TrustStore{}, err
	}
	return store, nil
}

// ResolveTrustedKey returns the active trusted public key identified by signerKeyID.
// Revoked and out-of-window keys are rejected. Because M13.4 has no trusted signing
// timestamp, revocation is evaluated at verification time and is not backdated.
func (s TrustStore) ResolveTrustedKey(signerKeyID string, now time.Time) (ed25519.PublicKey, TrustKey, error) {
	if err := s.Validate(); err != nil {
		return nil, TrustKey{}, err
	}
	if now.IsZero() {
		return nil, TrustKey{}, errors.New("verification time is required")
	}
	now = now.UTC()
	for _, key := range s.Keys {
		if key.KeyID != signerKeyID {
			continue
		}
		if key.Status == TrustKeyRevoked {
			return nil, TrustKey{}, fmt.Errorf("signer key %s is revoked", signerKeyID)
		}
		if key.NotBefore != nil && now.Before(*key.NotBefore) {
			return nil, TrustKey{}, fmt.Errorf("signer key %s is not yet valid", signerKeyID)
		}
		if key.NotAfter != nil && !now.Before(*key.NotAfter) {
			return nil, TrustKey{}, fmt.Errorf("signer key %s is expired", signerKeyID)
		}
		raw, _ := hex.DecodeString(key.PublicKey)
		return ed25519.PublicKey(raw), key, nil
	}
	return nil, TrustKey{}, fmt.Errorf("signer key %s is not present in trust store", signerKeyID)
}

// VerifySignedArchiveWithTrustStore resolves the signer through the operator trust
// store, then applies the complete M13.4 signed-archive verification gate.
func VerifySignedArchiveWithTrustStore(path string, signature Signature, store TrustStore, now time.Time) (Manifest, TrustKey, error) {
	if err := signature.Validate(); err != nil {
		return Manifest{}, TrustKey{}, err
	}
	publicKey, key, err := store.ResolveTrustedKey(signature.SignerKeyID, now)
	if err != nil {
		return Manifest{}, TrustKey{}, err
	}
	manifest, err := VerifySignedArchive(path, signature, publicKey)
	if err != nil {
		return Manifest{}, TrustKey{}, err
	}
	return manifest, key, nil
}

func isCanonicalUTC(t time.Time) bool {
	return t.Location() == time.UTC
}
