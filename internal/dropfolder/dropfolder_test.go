package dropfolder

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestObserveAcceptsRegularVisibleFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "disk.adf")
	if err := os.WriteFile(path, []byte("payload"), 0o640); err != nil {
		t.Fatal(err)
	}
	candidate, ok, err := Observe(root, "disk.adf")
	if err != nil || !ok {
		t.Fatalf("candidate=%+v ok=%v err=%v", candidate, ok, err)
	}
	if candidate.Name != "disk.adf" || candidate.Size != 7 {
		t.Fatalf("unexpected candidate: %+v", candidate)
	}
}

func TestObserveIgnoresUnsafeIncompleteAndNonRegularEntries(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".partial"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "empty.adf"), nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "folder"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, ".partial"), filepath.Join(root, "link.adf")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".partial", "empty.adf", "folder", "link.adf", "../escape"} {
		if _, ok, err := Observe(root, name); err != nil || ok {
			t.Fatalf("name=%q ok=%v err=%v", name, ok, err)
		}
	}
}

func TestStableRequiresSamePathSizeAndModificationTime(t *testing.T) {
	now := time.Now()
	base := Candidate{Path: "/drop/a.adf", Size: 10, ModTime: now}
	if !Stable(base, base) {
		t.Fatal("identical observations should be stable")
	}
	changed := base
	changed.Size++
	if Stable(base, changed) {
		t.Fatal("size change must be unstable")
	}
	changed = base
	changed.ModTime = now.Add(time.Second)
	if Stable(base, changed) {
		t.Fatal("mtime change must be unstable")
	}
}

func TestStageCreatesContentAddressedSnapshotAndDeduplicates(t *testing.T) {
	drop := t.TempDir()
	incoming := t.TempDir()
	payload := []byte("amiga sample")
	path := filepath.Join(drop, "sample.lha")
	if err := os.WriteFile(path, payload, 0o640); err != nil {
		t.Fatal(err)
	}
	candidate, ok, err := Observe(drop, "sample.lha")
	if err != nil || !ok {
		t.Fatalf("observe ok=%v err=%v", ok, err)
	}

	first, err := Stage(candidate, incoming, 1024)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	wantHash := hex.EncodeToString(sum[:])
	wantPath := filepath.Join(incoming, wantHash+"-sample.lha")
	if first.SHA256 != wantHash || first.Path != wantPath || first.Size != int64(len(payload)) || first.Duplicate {
		t.Fatalf("unexpected first snapshot: %+v", first)
	}
	got, err := os.ReadFile(first.Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("snapshot=%q want=%q", got, payload)
	}

	second, err := Stage(candidate, incoming, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Duplicate || second.Path != first.Path {
		t.Fatalf("unexpected duplicate snapshot: %+v", second)
	}
}

func TestStageRejectsChangedOrOversizedCandidate(t *testing.T) {
	drop := t.TempDir()
	incoming := t.TempDir()
	path := filepath.Join(drop, "disk.adf")
	if err := os.WriteFile(path, []byte("first"), 0o640); err != nil {
		t.Fatal(err)
	}
	candidate, ok, err := Observe(drop, "disk.adf")
	if err != nil || !ok {
		t.Fatalf("observe ok=%v err=%v", ok, err)
	}
	if err := os.WriteFile(path, []byte("replacement payload"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Stage(candidate, incoming, 1024); err == nil {
		t.Fatal("changed candidate should fail")
	}

	candidate, ok, err = Observe(drop, "disk.adf")
	if err != nil || !ok {
		t.Fatalf("observe second ok=%v err=%v", ok, err)
	}
	if _, err := Stage(candidate, incoming, 4); err == nil {
		t.Fatal("oversized candidate should fail")
	}
}

func TestStageRejectsSymlinkReplacementWithMatchingMetadata(t *testing.T) {
	drop := t.TempDir()
	incoming := t.TempDir()
	path := filepath.Join(drop, "disk.adf")
	payload := []byte("original")
	if err := os.WriteFile(path, payload, 0o640); err != nil {
		t.Fatal(err)
	}
	candidate, ok, err := Observe(drop, "disk.adf")
	if err != nil || !ok {
		t.Fatalf("observe ok=%v err=%v", ok, err)
	}

	target := filepath.Join(drop, ".replacement")
	if err := os.WriteFile(target, []byte("attacker"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(target, candidate.ModTime, candidate.ModTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	_, err = Stage(candidate, incoming, 1024)
	if err == nil || !strings.Contains(err.Error(), "path changed") {
		t.Fatalf("expected path replacement rejection, got %v", err)
	}
	entries, err := os.ReadDir(incoming)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("staging wrote incoming artifacts after rejected replacement: %v", entries)
	}
}
