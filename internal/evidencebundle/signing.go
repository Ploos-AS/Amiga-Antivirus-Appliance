package evidencebundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	SignatureSchema    = "aaa-evidence-signature-v1"
	SignatureAlgorithm = "ed25519"
)

// Signature is a detached signature over the exact bytes of one M13 evidence ZIP.
type Signature struct {
	Schema       string `json:"schema"`
	Algorithm    string `json:"algorithm"`
	BundleSHA256 string `json:"bundle_sha256"`
	SignerKeyID  string `json:"signer_key_id"`
	Signature    string `json:"signature"`
}

func (s Signature) Validate() error {
	if s.Schema != SignatureSchema {
		return fmt.Errorf("unsupported evidence signature schema %q", s.Schema)
	}
	if s.Algorithm != SignatureAlgorithm {
		return fmt.Errorf("unsupported evidence signature algorithm %q", s.Algorithm)
	}
	if !sha256Pattern.MatchString(s.BundleSHA256) {
		return errors.New("invalid bundle SHA-256")
	}
	if !sha256Pattern.MatchString(s.SignerKeyID) {
		return errors.New("invalid signer key id")
	}
	if len(s.Signature) != ed25519.SignatureSize*2 || s.Signature != strings.ToLower(s.Signature) {
		return errors.New("signature must be 64 raw Ed25519 bytes encoded as lowercase hexadecimal")
	}
	decoded, err := hex.DecodeString(s.Signature)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return errors.New("signature must be 64 raw Ed25519 bytes encoded as lowercase hexadecimal")
	}
	return nil
}

// MarshalDeterministic serializes the detached signature in canonical field order.
func (s Signature) MarshalDeterministic() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// DecodeSignatureStrict parses one detached signature and rejects unknown or trailing data.
func DecodeSignatureStrict(data []byte) (Signature, error) {
	var s Signature
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Signature{}, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Signature{}, errors.New("signature document contains trailing JSON data")
		}
		return Signature{}, err
	}
	if err := s.Validate(); err != nil {
		return Signature{}, err
	}
	return s, nil
}

// KeyID is SHA-256 of the raw Ed25519 public key, encoded as lowercase hexadecimal.
func KeyID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid Ed25519 public key size %d", len(publicKey))
	}
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:]), nil
}

func ParsePrivateKeyHexFile(data []byte) (ed25519.PrivateKey, error) {
	value, err := decodeLowerHexLine(data, ed25519.PrivateKeySize*2, "Ed25519 private key")
	if err != nil {
		return nil, err
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("Ed25519 private key must be 64 raw bytes encoded as lowercase hexadecimal")
	}
	return ed25519.PrivateKey(decoded), nil
}

func ParsePublicKeyHexFile(data []byte) (ed25519.PublicKey, string, error) {
	value, err := decodeLowerHexLine(data, ed25519.PublicKeySize*2, "Ed25519 public key")
	if err != nil {
		return nil, "", err
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, "", errors.New("Ed25519 public key must be 32 raw bytes encoded as lowercase hexadecimal")
	}
	key := ed25519.PublicKey(decoded)
	id, err := KeyID(key)
	if err != nil {
		return nil, "", err
	}
	return key, id, nil
}

func decodeLowerHexLine(data []byte, length int, label string) (string, error) {
	if len(data) != length+1 || data[len(data)-1] != '\n' {
		return "", fmt.Errorf("%s file must contain exactly one lowercase hexadecimal value followed by newline", label)
	}
	value := string(data[:len(data)-1])
	if value != strings.ToLower(value) || strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("%s file must contain lowercase hexadecimal", label)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", fmt.Errorf("%s file must contain lowercase hexadecimal", label)
	}
	return value, nil
}

// SignArchive first validates the full evidence archive, then signs a domain-separated
// statement binding the exact archive SHA-256 to the signing key identity.
func SignArchive(path string, privateKey ed25519.PrivateKey) (Signature, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Signature{}, errors.New("invalid Ed25519 private key length")
	}
	before, err := archiveSHA256(path)
	if err != nil {
		return Signature{}, err
	}
	if _, err := VerifyArchive(path); err != nil {
		return Signature{}, fmt.Errorf("evidence archive verification failed before signing: %w", err)
	}
	after, err := archiveSHA256(path)
	if err != nil {
		return Signature{}, err
	}
	if before != after {
		return Signature{}, errors.New("evidence archive changed while validating for signing")
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return Signature{}, errors.New("derive Ed25519 public key")
	}
	keyID, err := KeyID(publicKey)
	if err != nil {
		return Signature{}, err
	}
	s := Signature{Schema: SignatureSchema, Algorithm: SignatureAlgorithm, BundleSHA256: after, SignerKeyID: keyID}
	s.Signature = hex.EncodeToString(ed25519.Sign(privateKey, signatureMessage(s)))
	if err := s.Validate(); err != nil {
		return Signature{}, err
	}
	return s, nil
}

// VerifySignedArchive validates the archive, its exact SHA-256, the signer identity,
// and the detached Ed25519 signature using only the supplied trusted public key.
func VerifySignedArchive(path string, signature Signature, trusted ed25519.PublicKey) (Manifest, error) {
	if err := signature.Validate(); err != nil {
		return Manifest{}, err
	}
	if len(trusted) != ed25519.PublicKeySize {
		return Manifest{}, errors.New("trusted Ed25519 public key is required")
	}
	trustedID, err := KeyID(trusted)
	if err != nil {
		return Manifest{}, err
	}
	if trustedID != signature.SignerKeyID {
		return Manifest{}, errors.New("trusted public key does not match signer_key_id")
	}
	before, err := archiveSHA256(path)
	if err != nil {
		return Manifest{}, err
	}
	if before != signature.BundleSHA256 {
		return Manifest{}, errors.New("evidence bundle SHA-256 does not match detached signature")
	}
	manifest, err := VerifyArchive(path)
	if err != nil {
		return Manifest{}, err
	}
	after, err := archiveSHA256(path)
	if err != nil {
		return Manifest{}, err
	}
	if before != after {
		return Manifest{}, errors.New("evidence archive changed during signed verification")
	}
	sigBytes, _ := hex.DecodeString(signature.Signature)
	if !ed25519.Verify(trusted, signatureMessage(signature), sigBytes) {
		return Manifest{}, errors.New("invalid evidence bundle signature")
	}
	return manifest, nil
}

func signatureMessage(s Signature) []byte {
	return []byte(SignatureSchema + "\n" + SignatureAlgorithm + "\n" + s.BundleSHA256 + "\n" + s.SignerKeyID + "\n")
}

func archiveSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return "", err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !opened.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return "", errors.New("evidence archive must remain the same regular file while opened")
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", err
	}
	finished, err := f.Stat()
	if err != nil {
		return "", err
	}
	if n != opened.Size() || finished.Size() != opened.Size() || !finished.ModTime().Equal(opened.ModTime()) {
		return "", errors.New("evidence archive changed while hashing")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
