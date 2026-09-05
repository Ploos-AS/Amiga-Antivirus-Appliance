package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestScanLZXScansHunkMember(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell wrapper test")
	}
	dir := t.TempDir()
	lsar := filepath.Join(dir, "lsar")
	unar := filepath.Join(dir, "unar")
	payloadPath := filepath.Join(dir, "payload.bin")
	payload := testHunkExecutable()
	if err := os.WriteFile(payloadPath, payload, 0600); err != nil {
		t.Fatal(err)
	}
	lsarScript := `#!/bin/sh
printf '%s\n' '{"lsarFormatName":"LZX","lsarContents":[{"XADFileName":"C/tool","XADFileSize":40}]}'
`
	if err := os.WriteFile(lsar, []byte(lsarScript), 0700); err != nil {
		t.Fatal(err)
	}
	unarScript := `#!/bin/sh
cat "$AAA_TEST_LZX_PAYLOAD"
`
	if err := os.WriteFile(unar, []byte(unarScript), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AAA_LSAR", lsar)
	t.Setenv("AAA_UNAR", unar)
	t.Setenv("AAA_TEST_LZX_PAYLOAD", payloadPath)

	archivePath := filepath.Join(dir, "tools.lzx")
	if err := os.WriteFile(archivePath, []byte("synthetic-lzx"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ScanFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != "lzx" || got.Archive == nil || len(got.MemberResults) != 1 {
		t.Fatalf("missing LZX analysis: %+v", got)
	}
	member := got.MemberResults[0]
	if member.Name != "C/tool" || member.Format != "amiga-hunk-executable" || member.Hunk == nil || !member.Hunk.Recognized {
		t.Fatalf("LZX Hunk member not scanned: %+v", member)
	}
}
