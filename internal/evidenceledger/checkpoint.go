package evidenceledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	CheckpointSchema    = "aaa-evidence-ledger-checkpoint-v1"
	CheckpointAlgorithm = "ed25519"
)

type Checkpoint struct {
	Schema           string `json:"schema"`
	Algorithm        string `json:"algorithm"`
	Sequence         uint64 `json:"sequence"`
	TailLineSHA256   string `json:"tail_line_sha256"`
	TailRecordSHA256 string `json:"tail_record_sha256"`
	SignerKeyID      string `json:"signer_key_id"`
	Signature        string `json:"signature"`
}

func BuildCheckpoint(ledger []byte, privateKey ed25519.PrivateKey) (Checkpoint, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Checkpoint{}, errors.New("invalid Ed25519 private key size")
	}
	verification, err := Verify(ledger)
	if err != nil {
		return Checkpoint{}, err
	}
	if verification.Records == 0 {
		return Checkpoint{}, errors.New("cannot checkpoint an empty ledger")
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return Checkpoint{}, errors.New("invalid Ed25519 public key")
	}
	checkpoint := Checkpoint{
		Schema:           CheckpointSchema,
		Algorithm:        CheckpointAlgorithm,
		Sequence:         verification.TailSequence,
		TailLineSHA256:   verification.TailLineSHA256,
		TailRecordSHA256: verification.TailRecordSHA256,
		SignerKeyID:      checkpointKeyID(publicKey),
	}
	checkpoint.Signature = hex.EncodeToString(ed25519.Sign(privateKey, checkpoint.message()))
	return checkpoint, nil
}

func (c Checkpoint) Validate() error {
	if c.Schema != CheckpointSchema {
		return fmt.Errorf("unsupported ledger checkpoint schema %q", c.Schema)
	}
	if c.Algorithm != CheckpointAlgorithm {
		return fmt.Errorf("unsupported ledger checkpoint algorithm %q", c.Algorithm)
	}
	if c.Sequence == 0 {
		return errors.New("ledger checkpoint sequence must be greater than zero")
	}
	if !isSHA256(c.TailLineSHA256) {
		return errors.New("invalid checkpoint tail line SHA-256")
	}
	if !isSHA256(c.TailRecordSHA256) {
		return errors.New("invalid checkpoint tail record SHA-256")
	}
	if !isSHA256(c.SignerKeyID) {
		return errors.New("invalid checkpoint signer key ID")
	}
	if len(c.Signature) != ed25519.SignatureSize*2 || c.Signature != strings.ToLower(c.Signature) {
		return errors.New("invalid checkpoint signature encoding")
	}
	if _, err := hex.DecodeString(c.Signature); err != nil {
		return errors.New("invalid checkpoint signature encoding")
	}
	return nil
}

func (c Checkpoint) MarshalDeterministic() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func DecodeCheckpointStrict(data []byte) (Checkpoint, error) {
	var checkpoint Checkpoint
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&checkpoint); err != nil {
		return Checkpoint{}, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Checkpoint{}, errors.New("ledger checkpoint contains trailing JSON data")
		}
		return Checkpoint{}, err
	}
	if err := checkpoint.Validate(); err != nil {
		return Checkpoint{}, err
	}
	return checkpoint, nil
}

func VerifyCheckpointSignature(checkpoint Checkpoint, publicKey ed25519.PublicKey) error {
	if err := checkpoint.Validate(); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key size")
	}
	if checkpointKeyID(publicKey) != checkpoint.SignerKeyID {
		return errors.New("checkpoint signer key ID does not match trusted public key")
	}
	signature, err := hex.DecodeString(checkpoint.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, checkpoint.message(), signature) {
		return errors.New("ledger checkpoint signature verification failed")
	}
	return nil
}

func VerifyLedgerAgainstCheckpoint(ledger []byte, checkpoint Checkpoint, publicKey ed25519.PublicKey) error {
	if err := VerifyCheckpointSignature(checkpoint, publicKey); err != nil {
		return err
	}
	verification, err := Verify(ledger)
	if err != nil {
		return err
	}
	if verification.TailSequence < checkpoint.Sequence {
		return fmt.Errorf("ledger ends at sequence %d before checkpoint sequence %d", verification.TailSequence, checkpoint.Sequence)
	}
	lineSHA, recordSHA, err := hashesAtSequence(ledger, checkpoint.Sequence)
	if err != nil {
		return err
	}
	if lineSHA != checkpoint.TailLineSHA256 {
		return errors.New("ledger checkpoint tail line SHA-256 mismatch")
	}
	if recordSHA != checkpoint.TailRecordSHA256 {
		return errors.New("ledger checkpoint tail record SHA-256 mismatch")
	}
	return nil
}

func (c Checkpoint) message() []byte {
	return []byte(CheckpointSchema + "\n" +
		CheckpointAlgorithm + "\n" +
		strconv.FormatUint(c.Sequence, 10) + "\n" +
		c.TailLineSHA256 + "\n" +
		c.TailRecordSHA256 + "\n" +
		c.SignerKeyID + "\n")
}

func checkpointKeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

func hashesAtSequence(ledger []byte, sequence uint64) (string, string, error) {
	if sequence == 0 {
		return "", "", errors.New("sequence must be greater than zero")
	}
	if len(ledger) == 0 || ledger[len(ledger)-1] != '\n' {
		return "", "", errors.New("ledger is empty or has a partial final record")
	}
	lines := bytes.Split(ledger[:len(ledger)-1], []byte{'\n'})
	if sequence > uint64(len(lines)) {
		return "", "", fmt.Errorf("ledger does not contain sequence %d", sequence)
	}
	line := lines[sequence-1]
	record, err := DecodeRecordStrict(line)
	if err != nil {
		return "", "", err
	}
	lineWithLF := append(append([]byte(nil), line...), '\n')
	return sha256Hex(lineWithLF), record.RecordSHA256, nil
}
