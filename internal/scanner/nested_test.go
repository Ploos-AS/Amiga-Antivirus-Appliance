package scanner

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNestedZIPScansHunkAtDepthTwo(t *testing.T) {
	inner := makeZIP(t, "C/tool", testHunkExecutable())
	outer := makeZIP(t, "inner.zip", inner)

	path := filepath.Join(t.TempDir(), "outer.zip")
	if err := os.WriteFile(path, outer, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.MemberResults) != 1 {
		t.Fatalf("unexpected outer results: %+v", got.MemberResults)
	}
	innerResult := got.MemberResults[0]
	if innerResult.Format != "zip" || innerResult.Archive == nil || len(innerResult.Children) != 1 {
		t.Fatalf("nested ZIP not decoded: %+v", innerResult)
	}
	child := innerResult.Children[0]
	if child.Format != "amiga-hunk-executable" || child.Hunk == nil || !child.Hunk.Recognized {
		t.Fatalf("nested Hunk not scanned: %+v", child)
	}
}

func TestNestedZIPDepthLimit(t *testing.T) {
	level3 := makeZIP(t, "C/tool", testHunkExecutable())
	level2 := makeZIP(t, "level3.zip", level3)
	level1 := makeZIP(t, "level2.zip", level2)

	path := filepath.Join(t.TempDir(), "level1.zip")
	if err := os.WriteFile(path, level1, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.MemberResults) != 1 || len(got.MemberResults[0].Children) != 1 {
		t.Fatalf("unexpected nested results: %+v", got.MemberResults)
	}
	blocked := got.MemberResults[0].Children[0]
	if blocked.Format != "zip" || !strings.Contains(blocked.Error, "depth exceeds limit") {
		t.Fatalf("expected depth-limit error, got %+v", blocked)
	}
}

func TestNestedArchiveGlobalExpansionBudget(t *testing.T) {
	payload := bytes.Repeat([]byte{'A'}, 20*1024*1024)
	inner := makeZIP(t, "big.bin", payload)
	outer := makeZIPTwo(t, "padding.bin", payload, "inner.zip", inner)

	path := filepath.Join(t.TempDir(), "budget.zip")
	if err := os.WriteFile(path, outer, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.MemberResults) != 2 {
		t.Fatalf("unexpected results: %+v", got.MemberResults)
	}
	if !strings.Contains(got.MemberResults[1].Error, "global safety limit") {
		t.Fatalf("expected global expansion budget error, got %+v", got.MemberResults[1])
	}
}

func makeZIP(t *testing.T, name string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func makeZIPTwo(t *testing.T, name1 string, payload1 []byte, name2 string, payload2 []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, entry := range []struct {
		name    string
		payload []byte
	}{{name1, payload1}, {name2, payload2}} {
		w, err := zw.Create(entry.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entry.payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
