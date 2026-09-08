package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidencebundle"
)

func makeTrustUpdateFixture(t *testing.T, root string, rootPrivate ed25519.PrivateKey, sequence string, storePath string) string {
	t.Helper()
	privatePath := filepath.Join(root, "root.private")
	writeHexKeyFile(t, privatePath, rootPrivate)
	updatePath := filepath.Join(root, "trust-update-"+sequence+".json")
	if err := runTrustUpdateSign([]string{
		"--root-private-key", privatePath,
		"--sequence", sequence,
		"--output", updatePath,
		storePath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	return updatePath
}

func TestRunTrustUpdateInstallPersistsSequenceAndRejectsReplay(t *testing.T) {
	work := t.TempDir()
	stateRoot := filepath.Join(work, "state")
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signerPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(work, "root.public")
	storePath := filepath.Join(work, "trust-store.json")
	writeHexKeyFile(t, publicPath, rootPublic)
	writeTrustStoreFixture(t, storePath, signerPublic)
	updatePath := makeTrustUpdateFixture(t, work, rootPrivate, "1", storePath)

	var out bytes.Buffer
	if err := runTrustUpdateInstall([]string{
		"--root-public-key", publicPath,
		"--state-root", stateRoot,
		storePath,
		updatePath,
	}, &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "sequence=1 previous=0") {
		t.Fatalf("install output=%q", out.String())
	}

	state, err := loadInstalledTrustState(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || state.Sequence != 1 {
		t.Fatalf("installed state=%+v", state)
	}
	if _, err := os.Stat(filepath.Join(stateRoot, state.TrustStoreFile)); err != nil {
		t.Fatal(err)
	}

	if err := runTrustUpdateInstall([]string{
		"--root-public-key", publicPath,
		"--state-root", stateRoot,
		storePath,
		updatePath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("replayed installed update accepted")
	}
}

func TestRunTrustUpdateInstallAdvancesAndKeepsPriorStore(t *testing.T) {
	work := t.TempDir()
	stateRoot := filepath.Join(work, "state")
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(work, "root.public")
	writeHexKeyFile(t, publicPath, rootPublic)

	signer1, _, _ := ed25519.GenerateKey(nil)
	store1 := filepath.Join(work, "store1.json")
	writeTrustStoreFixture(t, store1, signer1)
	update1 := makeTrustUpdateFixture(t, work, rootPrivate, "1", store1)
	if err := runTrustUpdateInstall([]string{"--root-public-key", publicPath, "--state-root", stateRoot, store1, update1}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	signer2, _, _ := ed25519.GenerateKey(nil)
	store2 := filepath.Join(work, "store2.json")
	writeTrustStoreFixture(t, store2, signer2)
	update2 := makeTrustUpdateFixture(t, work, rootPrivate, "2", store2)
	if err := runTrustUpdateInstall([]string{"--root-public-key", publicPath, "--state-root", stateRoot, store2, update2}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	state, err := loadInstalledTrustState(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if state.Sequence != 2 {
		t.Fatalf("sequence=%d", state.Sequence)
	}
	oldName, _ := evidencebundle.TrustStoreFilename(1)
	if _, err := os.Stat(filepath.Join(stateRoot, oldName)); err != nil {
		t.Fatalf("prior immutable trust store missing: %v", err)
	}
}

func TestInstallVerifiedTrustStoreRecoversMatchingOrphanAndRejectsConflict(t *testing.T) {
	work := t.TempDir()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signerPublic, _, _ := ed25519.GenerateKey(nil)
	storePath := filepath.Join(work, "store.json")
	writeTrustStoreFixture(t, storePath, signerPublic)
	storeData, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatal(err)
	}
	update, err := evidencebundle.SignTrustStore(storeData, 7, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_ = rootPublic

	stateRoot := filepath.Join(work, "recover")
	if err := os.MkdirAll(stateRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	name, _ := evidencebundle.TrustStoreFilename(7)
	if err := os.WriteFile(filepath.Join(stateRoot, name), storeData, 0o640); err != nil {
		t.Fatal(err)
	}
	state, err := installVerifiedTrustStore(stateRoot, storeData, update)
	if err != nil {
		t.Fatal(err)
	}
	if state.Sequence != 7 {
		t.Fatalf("sequence=%d", state.Sequence)
	}

	conflictRoot := filepath.Join(work, "conflict")
	if err := os.MkdirAll(conflictRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(conflictRoot, name), []byte("different"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := installVerifiedTrustStore(conflictRoot, storeData, update); err == nil {
		t.Fatal("conflicting immutable orphan accepted")
	}
}

func TestLoadInstalledTrustStateRejectsTamperedActiveStore(t *testing.T) {
	work := t.TempDir()
	stateRoot := filepath.Join(work, "state")
	_, rootPrivate, _ := ed25519.GenerateKey(nil)
	signerPublic, _, _ := ed25519.GenerateKey(nil)
	storePath := filepath.Join(work, "store.json")
	writeTrustStoreFixture(t, storePath, signerPublic)
	storeData, _ := os.ReadFile(storePath)
	update, err := evidencebundle.SignTrustStore(storeData, 1, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	state, err := installVerifiedTrustStore(stateRoot, storeData, update)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateRoot, state.TrustStoreFile), []byte("tampered"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInstalledTrustState(stateRoot); err == nil {
		t.Fatal("tampered installed trust store accepted")
	}
}
