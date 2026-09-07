package dropfolder

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Receipt records the last successfully submitted content for one drop name.
type Receipt struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// ReceiptStore persists drop-folder submission receipts atomically.
type ReceiptStore struct {
	path     string
	receipts map[string]Receipt
}

// OpenReceiptStore loads or creates a persistent receipt store.
func OpenReceiptStore(path string) (*ReceiptStore, error) {
	if path == "" {
		return nil, errors.New("receipt path is required")
	}
	s := &ReceiptStore{path: path, receipts: make(map[string]Receipt)}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read drop receipts: %w", err)
	}
	var list []Receipt
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("decode drop receipts: %w", err)
	}
	for _, receipt := range list {
		if receipt.Name == "" || receipt.SHA256 == "" || receipt.Size < 1 {
			return nil, errors.New("invalid drop receipt")
		}
		s.receipts[receipt.Name] = receipt
	}
	return s, nil
}

// Matches reports whether name is already recorded with identical staged content.
func (s *ReceiptStore) Matches(name string, snapshot Snapshot) bool {
	receipt, ok := s.receipts[name]
	return ok && receipt.SHA256 == snapshot.SHA256 && receipt.Size == snapshot.Size
}

// Record persists a successful submission receipt.
func (s *ReceiptStore) Record(name string, snapshot Snapshot) error {
	s.receipts[name] = Receipt{Name: name, SHA256: snapshot.SHA256, Size: snapshot.Size}
	return s.save()
}

// Prune removes receipts for source names no longer present in the drop directory.
func (s *ReceiptStore) Prune(present map[string]struct{}) error {
	changed := false
	for name := range s.receipts {
		if _, ok := present[name]; ok {
			continue
		}
		delete(s.receipts, name)
		changed = true
	}
	if !changed {
		return nil
	}
	return s.save()
}

func (s *ReceiptStore) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return fmt.Errorf("create drop receipt directory: %w", err)
	}
	list := make([]Receipt, 0, len(s.receipts))
	for _, receipt := range s.receipts {
		list = append(list, receipt)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("encode drop receipts: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".drop-receipts-*")
	if err != nil {
		return fmt.Errorf("create drop receipt temp file: %w", err)
	}
	tmpPath := tmp.Name()
	remove := true
	defer func() {
		_ = tmp.Close()
		if remove {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o640); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("publish drop receipts: %w", err)
	}
	remove = false
	return nil
}
