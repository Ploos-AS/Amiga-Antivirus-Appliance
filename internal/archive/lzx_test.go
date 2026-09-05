package archive

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDecodeLZXWithToolWrappers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell wrapper test")
	}
	dir := t.TempDir()
	lsar := filepath.Join(dir, "lsar")
	unar := filepath.Join(dir, "unar")
	payload := []byte("hello amiga")

	lsarScript := `#!/bin/sh
printf '%s\n' '{"lsarFormatName":"LZX","lsarContents":[{"XADFileName":"C/tool","XADFileSize":11}]}'
`
	if err := os.WriteFile(lsar, []byte(lsarScript), 0700); err != nil {
		t.Fatal(err)
	}
	unarScript := `#!/bin/sh
printf 'hello amiga'
`
	if err := os.WriteFile(unar, []byte(unarScript), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AAA_LSAR", lsar)
	t.Setenv("AAA_UNAR", unar)

	members, analysis, err := DecodeLZX([]byte("synthetic-lzx"))
	if err != nil {
		t.Fatal(err)
	}
	if analysis.Format != "lzx" || analysis.ExpandedSize != int64(len(payload)) || len(analysis.Members) != 1 {
		t.Fatalf("unexpected analysis: %+v", analysis)
	}
	if len(members) != 1 || members[0].Name != "C/tool" || !bytes.Equal(members[0].Data, payload) {
		t.Fatalf("unexpected members: %+v", members)
	}
	if len(analysis.Members[0].SHA256) != 64 {
		t.Fatalf("missing LZX member hash: %+v", analysis.Members[0])
	}
}

func TestDecodeLZXRejectsWrongFormat(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell wrapper test")
	}
	dir := t.TempDir()
	lsar := filepath.Join(dir, "lsar")
	unar := filepath.Join(dir, "unar")
	if err := os.WriteFile(lsar, []byte("#!/bin/sh\nprintf '%s\\n' '{\"lsarFormatName\":\"Zip\",\"lsarContents\":[]}'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unar, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AAA_LSAR", lsar)
	t.Setenv("AAA_UNAR", unar)
	if _, _, err := DecodeLZX([]byte("not-really-lzx")); err == nil {
		t.Fatal("expected wrong-format error")
	}
}

func TestDecodeLZXHonorsExpansionLimit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell wrapper test")
	}
	dir := t.TempDir()
	lsar := filepath.Join(dir, "lsar")
	unar := filepath.Join(dir, "unar")
	if err := os.WriteFile(lsar, []byte("#!/bin/sh\nprintf '%s\\n' '{\"lsarFormatName\":\"LZX\",\"lsarContents\":[{\"XADFileName\":\"big\",\"XADFileSize\":12}]}'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unar, []byte("#!/bin/sh\nprintf 'hello amiga!'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AAA_LSAR", lsar)
	t.Setenv("AAA_UNAR", unar)
	if _, _, err := DecodeLZXLimited([]byte("synthetic-lzx"), 8, MaxMembers); err == nil {
		t.Fatal("expected expansion-limit error")
	}
}
