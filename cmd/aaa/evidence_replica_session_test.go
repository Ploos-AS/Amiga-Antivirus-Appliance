package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/evidencereplica"
)

func TestReplicateSessionAndVerify(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(t.TempDir(), "a.bin")
	b := filepath.Join(t.TempDir(), "b.bin")
	if err := os.WriteFile(a, []byte("alpha"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("beta"), 0o600); err != nil {
		t.Fatal(err)
	}
	sessionPath := filepath.Join(t.TempDir(), "session.json")
	args := []string{"--destination", root, "--session", sessionPath, "--object", "evidence-bundle:" + a, "--object", "ledger-checkpoint:" + b}
	var out bytes.Buffer
	if err := runEvidenceReplicateSession(args, &out, &out, func() time.Time { return time.Unix(10, 0) }); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(sessionPath)
	if err != nil {
		t.Fatal(err)
	}
	session, err := evidencereplica.DecodeSessionStrict(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(session.Objects) != 2 {
		t.Fatalf("objects=%d", len(session.Objects))
	}
	for _, object := range session.Objects {
		if object.Result != evidencereplica.ResultReplicated {
			t.Fatalf("unexpected result %q", object.Result)
		}
	}
	out.Reset()
	if err := runEvidenceReplicaVerifySession([]string{"--root", root, sessionPath}, &out, &out); err != nil {
		t.Fatal(err)
	}
}

func TestReplicateSessionRepeatAlreadyPresent(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(t.TempDir(), "a.bin")
	if err := os.WriteFile(source, []byte("alpha"), 0o600); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(t.TempDir(), "first.json")
	second := filepath.Join(t.TempDir(), "second.json")
	base := []string{"--destination", root, "--object", "evidence-bundle:" + source}
	if err := runEvidenceReplicateSession(append([]string{"--session", first}, base...), &bytes.Buffer{}, &bytes.Buffer{}, time.Now); err != nil {
		t.Fatal(err)
	}
	if err := runEvidenceReplicateSession(append([]string{"--session", second}, base...), &bytes.Buffer{}, &bytes.Buffer{}, time.Now); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	session, err := evidencereplica.DecodeSessionStrict(data)
	if err != nil {
		t.Fatal(err)
	}
	if session.Objects[0].Result != evidencereplica.ResultAlreadyPresent {
		t.Fatalf("result=%q", session.Objects[0].Result)
	}
}

func TestReplicateSessionConflictContinuesAndSanitizes(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(t.TempDir(), "a.bin")
	b := filepath.Join(t.TempDir(), "b.bin")
	if err := os.WriteFile(a, []byte("alpha"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("beta"), 0o600); err != nil {
		t.Fatal(err)
	}
	sha, _, err := hashRegularFile(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureReplicaDirectories(root, sha); err != nil {
		t.Fatal(err)
	}
	name, err := evidencereplica.ObjectName(sha)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte("conflict"), 0o600); err != nil {
		t.Fatal(err)
	}
	sessionPath := filepath.Join(t.TempDir(), "session.json")
	args := []string{"--destination", root, "--session", sessionPath, "--object", "evidence-bundle:" + a, "--object", "ledger-checkpoint:" + b}
	err = runEvidenceReplicateSession(args, &bytes.Buffer{}, &bytes.Buffer{}, time.Now)
	if err == nil {
		t.Fatal("expected incomplete session error")
	}
	data, readErr := os.ReadFile(sessionPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if strings.Contains(string(data), a) || strings.Contains(string(data), b) || strings.Contains(string(data), root) {
		t.Fatal("session leaked host path")
	}
	session, decodeErr := evidencereplica.DecodeSessionStrict(data)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	failed, succeeded := 0, 0
	for _, object := range session.Objects {
		switch object.Result {
		case evidencereplica.ResultFailed:
			failed++
			if object.Error != "destination-conflict" {
				t.Fatalf("error class=%q", object.Error)
			}
		case evidencereplica.ResultReplicated:
			succeeded++
		}
	}
	if failed != 1 || succeeded != 1 {
		t.Fatalf("failed=%d succeeded=%d", failed, succeeded)
	}
}
