package evidencebundle

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

func testTrustStoreBytes(t *testing.T, public ed25519.PublicKey) []byte {
	t.Helper()
	id, err := KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	store := TrustStore{
		Schema: TrustStoreSchema,
		Keys: []TrustKey{{
			KeyID:     id,
			PublicKey: hex.EncodeToString(public),
			Status:    TrustKeyActive,
			Label:     "signer",
		}},
	}
	data, err := store.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestTrustUpdateSignVerifyAndDeterministicMarshal(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signerPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	storeBytes := testTrustStoreBytes(t, signerPublic)
	update, err := SignTrustStore(storeBytes, 7, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	first, err := update.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	second, err := update.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("trust update serialization is not deterministic")
	}
	decoded, err := DecodeTrustUpdateStrict(first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTrustStoreUpdate(storeBytes, decoded, rootPublic, 6); err != nil {
		t.Fatal(err)
	}
}

func TestTrustUpdateRejectsRollbackReplayAndWrongRoot(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	wrongPublic := wrongPrivate.Public().(ed25519.PublicKey)
	signerPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	storeBytes := testTrustStoreBytes(t, signerPublic)
	update, err := SignTrustStore(storeBytes, 4, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	for _, current := range []uint64{4, 5} {
		if _, err := VerifyTrustStoreUpdate(storeBytes, update, rootPublic, current); err == nil {
			t.Fatalf("sequence %d accepted against current %d", update.Sequence, current)
		}
	}
	if _, err := VerifyTrustStoreUpdate(storeBytes, update, wrongPublic, 3); err == nil {
		t.Fatal("wrong pinned root accepted")
	}
}

func TestTrustUpdateRejectsTamperedStoreAndSignature(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signerPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	storeBytes := testTrustStoreBytes(t, signerPublic)
	update, err := SignTrustStore(storeBytes, 1, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), storeBytes...)
	tampered[len(tampered)-2] ^= 1
	if _, err := VerifyTrustStoreUpdate(tampered, update, rootPublic, 0); err == nil {
		t.Fatal("tampered trust store accepted")
	}
	bad := update
	if bad.Signature[0] == '0' {
		bad.Signature = "1" + bad.Signature[1:]
	} else {
		bad.Signature = "0" + bad.Signature[1:]
	}
	if _, err := VerifyTrustStoreUpdate(storeBytes, bad, rootPublic, 0); err == nil {
		t.Fatal("tampered update signature accepted")
	}
}

func TestDecodeTrustUpdateStrictRejectsUnknownAndTrailingJSON(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signerPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	storeBytes := testTrustStoreBytes(t, signerPublic)
	update, err := SignTrustStore(storeBytes, 2, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	data, err := update.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	unknown := strings.Replace(string(data), "\n}", ",\n  \"surprise\": true\n}", 1)
	if _, err := DecodeTrustUpdateStrict([]byte(unknown)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := DecodeTrustUpdateStrict(append(data, []byte("{}")...)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	_ = rootPublic
}
