package evidencereplica

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
)

const CatalogueNamespace = "aaa-replica-v1/receipts/sha256"

type CatalogueDocumentType string

const (
	CatalogueReceipt CatalogueDocumentType = "receipt"
	CatalogueSession CatalogueDocumentType = "session"
)

type CatalogueRecord struct {
	SHA256       string                `json:"sha256"`
	Size         int64                 `json:"size"`
	DocumentType CatalogueDocumentType `json:"document_type"`
	Schema       string                `json:"schema"`
	ObjectKind   ObjectKind            `json:"object_kind,omitempty"`
	ObjectSHA256 string                `json:"object_sha256,omitempty"`
	SessionID    string                `json:"session_id,omitempty"`
	ObjectCount  int                   `json:"object_count,omitempty"`
	Complete     *bool                 `json:"complete,omitempty"`
}

func CatalogueName(sha string) (string, error) {
	if err := validateSHA(sha); err != nil {
		return "", err
	}
	return path.Join(CatalogueNamespace, sha[:2], sha), nil
}

func CatalogueMetadataSHA(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func DecodeCatalogueDocument(data []byte) (CatalogueRecord, error) {
	sha := CatalogueMetadataSHA(data)
	if receipt, err := DecodeReceiptStrict(data); err == nil {
		return CatalogueRecord{
			SHA256:       sha,
			Size:         int64(len(data)),
			DocumentType: CatalogueReceipt,
			Schema:       Schema,
			ObjectKind:   receipt.ObjectKind,
			ObjectSHA256: receipt.SHA256,
		}, nil
	}
	if session, err := DecodeSessionStrict(data); err == nil {
		complete := true
		for _, object := range session.Objects {
			if object.Result == ResultFailed {
				complete = false
				break
			}
		}
		return CatalogueRecord{
			SHA256:       sha,
			Size:         int64(len(data)),
			DocumentType: CatalogueSession,
			Schema:       SessionSchema,
			SessionID:    session.SessionID,
			ObjectCount:  len(session.Objects),
			Complete:     &complete,
		}, nil
	}
	return CatalogueRecord{}, errors.New("unsupported or invalid replica catalogue document")
}

func (r CatalogueRecord) Validate() error {
	if err := validateSHA(r.SHA256); err != nil {
		return err
	}
	if r.Size < 0 {
		return errors.New("catalogue record size must be non-negative")
	}
	switch r.DocumentType {
	case CatalogueReceipt:
		if r.Schema != Schema || r.ObjectKind == "" || r.ObjectSHA256 == "" || r.SessionID != "" || r.ObjectCount != 0 || r.Complete != nil {
			return errors.New("invalid receipt catalogue record")
		}
		if err := validateSHA(r.ObjectSHA256); err != nil {
			return fmt.Errorf("object sha256: %w", err)
		}
	case CatalogueSession:
		if r.Schema != SessionSchema || r.SessionID == "" || r.ObjectKind != "" || r.ObjectSHA256 != "" || r.ObjectCount < 1 || r.Complete == nil {
			return errors.New("invalid session catalogue record")
		}
		if err := validateSHA(r.SessionID); err != nil {
			return fmt.Errorf("session id: %w", err)
		}
	default:
		return fmt.Errorf("unsupported catalogue document type %q", r.DocumentType)
	}
	return nil
}
