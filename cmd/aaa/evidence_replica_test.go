package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidencereplica"
)

func replicaFixture(t *testing.T) (string, string, evidencereplica.Receipt) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "replica")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(base, "evidence.bin")
	if err := os.WriteFile(source, []byte("portable evidence\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	sha, size, err := hashRegularFile(source)
	if err != nil {
		t.Fatal(err)
	}
	r, err := evidencereplica.BuildReceipt(evidencereplica.KindEvidenceBundle, sha, size, time.Unix(0, 0), "")
	if err != nil {
		t.Fatal(err)
	}
	return root, source, r
}

func TestReplicateObjectAndVerify(t *testing.T) {
	root, source, r := replicaFixture(t)
	if err := replicateObject(source, root, r); err != nil {
		t.Fatal(err)
	}
	object := filepath.Join(root, filepath.FromSlash(r.ReplicaName))
	sha, size, err := hashRegularFile(object)
	if err != nil {
		t.Fatal(err)
	}
	if sha != r.SHA256 || size != r.Size {
		t.Fatal("replica content mismatch")
	}
	// An identical object is an idempotent success.
	if err := replicateObject(source, root, r); err != nil {
		t.Fatalf("idempotent replication failed: %v", err)
	}
}

func TestReplicateObjectRejectsConflict(t *testing.T) {
	root, source, r := replicaFixture(t)
	if err := ensureReplicaDirectories(root, r.SHA256); err != nil {
		t.Fatal(err)
	}
	object := filepath.Join(root, filepath.FromSlash(r.ReplicaName))
	if err := os.WriteFile(object, []byte("conflict"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := replicateObject(source, root, r); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("expected conflict failure, got %v", err)
	}
}

func TestReplicateObjectRejectsSourceSymlink(t *testing.T) {
	root, source, r := replicaFixture(t)
	link := filepath.Join(filepath.Dir(source), "source-link")
	if err := os.Symlink(source, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := replicateObject(link, root, r); err == nil {
		t.Fatal("expected source symlink rejection")
	}
}

func TestReplicaRejectsRootSymlink(t *testing.T) {
	root, source, r := replicaFixture(t)
	link := filepath.Join(filepath.Dir(root), "root-link")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := replicateObject(source, link, r); err == nil {
		t.Fatal("expected replica root symlink rejection")
	}
}

func TestReplicaRejectsNamespaceSymlink(t *testing.T) {
	root, source, r := replicaFixture(t)
	outside := filepath.Join(filepath.Dir(root), "outside")
	if err := os.Mkdir(outside, 0o750); err != nil {
		t.Fatal(err)
	}
	component := filepath.Join(root, "aaa-replica-v1")
	if err := os.Symlink(outside, component); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := replicateObject(source, root, r); err == nil {
		t.Fatal("expected namespace symlink rejection")
	}
}

func TestReplicaVerifyDetectsTamperAndMissingObject(t *testing.T) {
	root, source, r := replicaFixture(t)
	if err := replicateObject(source, root, r); err != nil {
		t.Fatal(err)
	}
	receiptData, err := r.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join(filepath.Dir(root), "receipt.json")
	if err := os.WriteFile(receipt, receiptData, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceReplica([]string{"verify", "--root", root, receipt}, os.Stdout, os.Stderr); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
	object := filepath.Join(root, filepath.FromSlash(r.ReplicaName))
	if err := os.WriteFile(object, []byte("tampered"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceReplica([]string{"verify", "--root", root, receipt}, os.Stdout, os.Stderr); err == nil {
		t.Fatal("expected tamper detection")
	}
	if err := os.Remove(object); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceReplica([]string{"verify", "--root", root, receipt}, os.Stdout, os.Stderr); err == nil {
		t.Fatal("expected missing object detection")
	}
}

func TestReplicaLeavesNoTemporaryFiles(t *testing.T) {
	root, source, r := replicaFixture(t)
	if err := replicateObject(source, root, r); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(filepath.Join(root, filepath.FromSlash(r.ReplicaName)))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".aaa-replica-") {
			t.Fatalf("temporary file left behind: %s", entry.Name())
		}
	}
}
