package signaturefactory

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	DistributionPublicKeyHexLength = ed25519.PublicKeySize * 2
	DistributionSignatureHexLength = ed25519.SignatureSize * 2
)

type TrustedDistributionKeys struct {
	keys map[string]ed25519.PublicKey
}

func DistributionKeyID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid Ed25519 public key size %d", len(publicKey))
	}
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:]), nil
}

func ParseDistributionPublicKeyHex(value string) (ed25519.PublicKey, string, error) {
	if len(value) != DistributionPublicKeyHexLength || value != strings.ToLower(value) {
		return nil, "", errors.New("public key must be 32 raw Ed25519 bytes encoded as lowercase hexadecimal")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, "", errors.New("public key must be 32 raw Ed25519 bytes encoded as lowercase hexadecimal")
	}
	publicKey := ed25519.PublicKey(append([]byte(nil), decoded...))
	keyID, err := DistributionKeyID(publicKey)
	if err != nil {
		return nil, "", err
	}
	return publicKey, keyID, nil
}

func NewTrustedDistributionKeys(publicKeysHex ...string) (*TrustedDistributionKeys, error) {
	trusted := &TrustedDistributionKeys{keys: make(map[string]ed25519.PublicKey, len(publicKeysHex))}
	for _, value := range publicKeysHex {
		if _, err := trusted.AddPublicKeyHex(value); err != nil {
			return nil, err
		}
	}
	return trusted, nil
}

func (t *TrustedDistributionKeys) AddPublicKeyHex(value string) (string, error) {
	if t == nil {
		return "", errors.New("trusted key set is nil")
	}
	publicKey, keyID, err := ParseDistributionPublicKeyHex(value)
	if err != nil {
		return "", err
	}
	if t.keys == nil {
		t.keys = make(map[string]ed25519.PublicKey)
	}
	if existing, ok := t.keys[keyID]; ok {
		if !existing.Equal(publicKey) {
			return "", fmt.Errorf("trusted key id %s already exists with different key material", keyID)
		}
		return keyID, nil
	}
	t.keys[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	return keyID, nil
}

func SignDistributionManifest(manifest DistributionManifest, privateKey ed25519.PrivateKey) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid Ed25519 private key size %d", len(privateKey))
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return "", errors.New("private key does not expose an Ed25519 public key")
	}
	keyID, err := DistributionKeyID(publicKey)
	if err != nil {
		return "", err
	}
	if manifest.SignerKeyID != keyID {
		return "", errors.New("manifest signer_key_id does not match private key")
	}
	canonical, err := manifest.CanonicalBytes()
	if err != nil {
		return "", err
	}
	signature := ed25519.Sign(privateKey, canonical)
	return hex.EncodeToString(signature), nil
}

func VerifyDistributionManifestSignature(manifest DistributionManifest, signatureHex string, trusted *TrustedDistributionKeys) error {
	if trusted == nil {
		return errors.New("trusted key set is required")
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	if len(signatureHex) != DistributionSignatureHexLength || signatureHex != strings.ToLower(signatureHex) {
		return errors.New("signature must be 64 raw Ed25519 bytes encoded as lowercase hexadecimal")
	}
	signature, err := hex.DecodeString(signatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("signature must be 64 raw Ed25519 bytes encoded as lowercase hexadecimal")
	}
	publicKey, ok := trusted.keys[manifest.SignerKeyID]
	if !ok {
		return fmt.Errorf("unknown signer key id %s", manifest.SignerKeyID)
	}
	derivedID, err := DistributionKeyID(publicKey)
	if err != nil {
		return err
	}
	if derivedID != manifest.SignerKeyID {
		return errors.New("trusted public key does not match manifest signer_key_id")
	}
	canonical, err := manifest.CanonicalBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, canonical, signature) {
		return errors.New("invalid distribution manifest signature")
	}
	return nil
}
