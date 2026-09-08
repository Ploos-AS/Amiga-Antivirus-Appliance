package evidencebundle

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func testTrustKey(t *testing.T, seedByte byte, status string) (TrustKey, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	id, err := KeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return TrustKey{
		KeyID:     id,
		PublicKey: hex.EncodeToString(publicKey),
		Status:    status,
		Label:     "test-key",
	}, privateKey
}

func TestTrustStoreDeterministicAndStrict(t *testing.T) {
	keyA, _ := testTrustKey(t, 1, TrustKeyActive)
	keyB, _ := testTrustKey(t, 2, TrustKeyRevoked)
	store := TrustStore{Schema: TrustStoreSchema, Keys: []TrustKey{keyB, keyA}}
	data, err := store.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(string(data), keyA.KeyID) > strings.Index(string(data), keyB.KeyID) && keyA.KeyID < keyB.KeyID {
		t.Fatalf("keys not sorted by key id: %s", data)
	}
	decoded, err := DecodeTrustStoreStrict(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Keys) != 2 {
		t.Fatalf("got %d keys", len(decoded.Keys))
	}
	bad := strings.Replace(string(data), "\"keys\":", "\"unknown\": 1,\n  \"keys\":", 1)
	if _, err := DecodeTrustStoreStrict([]byte(bad)); err == nil {
		t.Fatal("expected unknown field rejection")
	}
	if _, err := DecodeTrustStoreStrict(append(data, []byte("{}")...)); err == nil {
		t.Fatal("expected trailing JSON rejection")
	}
}

func TestTrustKeyIDMismatchAndDuplicateRejected(t *testing.T) {
	keyA, _ := testTrustKey(t, 3, TrustKeyActive)
	keyB, _ := testTrustKey(t, 4, TrustKeyActive)
	keyB.KeyID = keyA.KeyID
	if err := keyB.Validate(); err == nil {
		t.Fatal("expected key-id mismatch rejection")
	}
	store := TrustStore{Schema: TrustStoreSchema, Keys: []TrustKey{keyA, keyA}}
	if err := store.Validate(); err == nil {
		t.Fatal("expected duplicate key rejection")
	}
}

func TestResolveTrustedKeyRotationAndRevocation(t *testing.T) {
	now := time.Date(2026, 9, 8, 5, 0, 0, 0, time.UTC)
	oldKey, _ := testTrustKey(t, 5, TrustKeyRevoked)
	newKey, _ := testTrustKey(t, 6, TrustKeyActive)
	revokedAt := now.Add(-time.Hour)
	oldKey.RevokedAt = &revokedAt
	store := TrustStore{Schema: TrustStoreSchema, Keys: []TrustKey{oldKey, newKey}}
	if _, _, err := store.ResolveTrustedKey(oldKey.KeyID, now); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("expected revoked rejection, got %v", err)
	}
	publicKey, resolved, err := store.ResolveTrustedKey(newKey.KeyID, now)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.KeyID != newKey.KeyID || len(publicKey) != ed25519.PublicKeySize {
		t.Fatal("resolved wrong key")
	}
}

func TestResolveTrustedKeyValidityWindow(t *testing.T) {
	now := time.Date(2026, 9, 8, 5, 0, 0, 0, time.UTC)
	key, _ := testTrustKey(t, 7, TrustKeyActive)
	notBefore := now.Add(time.Hour)
	key.NotBefore = &notBefore
	store := TrustStore{Schema: TrustStoreSchema, Keys: []TrustKey{key}}
	if _, _, err := store.ResolveTrustedKey(key.KeyID, now); err == nil || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("expected not-yet-valid rejection, got %v", err)
	}
	key.NotBefore = nil
	notAfter := now
	key.NotAfter = &notAfter
	store.Keys[0] = key
	if _, _, err := store.ResolveTrustedKey(key.KeyID, now); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry rejection, got %v", err)
	}
}

func TestActiveKeyCannotCarryRevocationTime(t *testing.T) {
	key, _ := testTrustKey(t, 8, TrustKeyActive)
	revokedAt := time.Date(2026, 9, 8, 5, 0, 0, 0, time.UTC)
	key.RevokedAt = &revokedAt
	if err := key.Validate(); err == nil {
		t.Fatal("expected active revoked_at rejection")
	}
}
