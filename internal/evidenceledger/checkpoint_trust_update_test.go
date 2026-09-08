package evidenceledger

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func checkpointTrustStoreFixture(t *testing.T, public ed25519.PublicKey) []byte {
	t.Helper()
	store := CheckpointTrustStore{
		Schema: CheckpointTrustStoreSchema,
		Keys: []CheckpointTrustKey{{
			KeyID:     checkpointKeyID(public),
			PublicKey: hex.EncodeToString(public),
			Status:    CheckpointTrustKeyActive,
			Label:     "checkpoint signer",
		}},
	}
	data, err := store.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCheckpointTrustUpdateSignVerifyAndReplay(t *testing.T) {
	rootSeed := sha256.Sum256([]byte("m14.6-root"))
	rootPrivate := ed25519.NewKeyFromSeed(rootSeed[:])
	rootPublic := rootPrivate.Public().(ed25519.PublicKey)
	signerSeed := sha256.Sum256([]byte("m14.6-signer"))
	signerPrivate := ed25519.NewKeyFromSeed(signerSeed[:])
	storeData := checkpointTrustStoreFixture(t, signerPrivate.Public().(ed25519.PublicKey))

	update, err := SignCheckpointTrustStore(storeData, 7, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := update.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCheckpointTrustUpdateStrict(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCheckpointTrustStoreUpdate(storeData, decoded, rootPublic, 6); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCheckpointTrustStoreUpdate(storeData, decoded, rootPublic, 7); err == nil || !strings.Contains(err.Error(), "not newer") {
		t.Fatalf("expected replay rejection, got %v", err)
	}
}

func TestCheckpointTrustUpdateRejectsWrongRootAndTampering(t *testing.T) {
	rootSeed := sha256.Sum256([]byte("m14.6-root-a"))
	rootPrivate := ed25519.NewKeyFromSeed(rootSeed[:])
	wrongSeed := sha256.Sum256([]byte("m14.6-root-b"))
	wrongPublic := ed25519.NewKeyFromSeed(wrongSeed[:]).Public().(ed25519.PublicKey)
	signerSeed := sha256.Sum256([]byte("m14.6-signer-a"))
	signerPrivate := ed25519.NewKeyFromSeed(signerSeed[:])
	storeData := checkpointTrustStoreFixture(t, signerPrivate.Public().(ed25519.PublicKey))
	update, err := SignCheckpointTrustStore(storeData, 2, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCheckpointTrustStoreUpdate(storeData, update, wrongPublic, 0); err == nil {
		t.Fatal("wrong root accepted")
	}
	tampered := append([]byte(nil), storeData...)
	tampered[len(tampered)-2] ^= 1
	if _, err := VerifyCheckpointTrustStoreUpdate(tampered, update, rootPrivate.Public().(ed25519.PublicKey), 0); err == nil {
		t.Fatal("tampered trust store accepted")
	}
}

func TestCheckpointTrustUpdateStateRoundTrip(t *testing.T) {
	state := CheckpointTrustUpdateState{
		Schema:           CheckpointTrustUpdateStateSchema,
		Sequence:         9,
		TrustStoreSHA256: strings.Repeat("a", 64),
		TrustStoreFile:   "checkpoint-trust-store-00000000000000000009.json",
		RootKeyID:        strings.Repeat("b", 64),
	}
	data, err := state.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCheckpointTrustUpdateStateStrict(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Sequence != state.Sequence || decoded.TrustStoreFile != state.TrustStoreFile {
		t.Fatalf("decoded=%+v", decoded)
	}
}
