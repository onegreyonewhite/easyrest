package local

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func newTestPlugin(t *testing.T) *Plugin {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "store")
	plug := New()
	if _, err := plug.Init(map[string]any{"name": "local", "dir": dir}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	return plug
}

func TestInit(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "media-root")
	plug := New()
	info, err := plug.Init(map[string]any{"name": "local", "dir": dir}, easyrest.HostRPC{})
	root, inline := info.Root, info.Inline
	if err != nil {
		t.Fatal(err)
	}
	if root != dir || inline {
		t.Fatalf("root %q inline %v", root, inline)
	}
	stat, err := os.Stat(dir)
	if err != nil || !stat.IsDir() {
		t.Fatalf("dir not created: %v", err)
	}

	info, err = plug.Init(map[string]any{"name": "local", "dir": dir}, easyrest.HostRPC{})
	root, inline = info.Root, info.Inline
	if err != nil {
		t.Fatal(err)
	}
	if root != dir {
		t.Fatalf("second root %q", root)
	}

	file := filepath.Join(parent, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New().Init(map[string]any{"dir": file}, easyrest.HostRPC{}); err == nil {
		t.Fatal("expected error when dir is a file")
	}
}

func TestInlineSetting(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	plug := New()
	info, err := plug.Init(map[string]any{"name": "local", "dir": dir, "inline": true}, easyrest.HostRPC{})
	_, inline := info.Root, info.Inline
	if err != nil {
		t.Fatal(err)
	}
	if !inline {
		t.Fatal("expected inline")
	}
	got, _, err := plug.Put("a.txt", []byte("hi"), nil)
	want := easyrest.FormatDataURL("text/plain; charset=utf-8", []byte("hi"))
	if err != nil || got != want {
		t.Fatalf("stored %q err %v", got, err)
	}
	typed, _, err := plug.Put("b.bin", []byte{0x00, 0x01}, map[string]any{easyrest.CtxStorageMIME: "image/png"})
	if err != nil || typed != easyrest.FormatDataURL("image/png", []byte{0x00, 0x01}) {
		t.Fatalf("typed %q err %v", typed, err)
	}
	body, _, _, err := plug.GetBin("a.txt", nil)
	if err != nil || string(body) != "hi" {
		t.Fatalf("body %q err %v", body, err)
	}

	plain := New()
	info, err = plain.Init(map[string]any{"name": "local", "dir": filepath.Join(t.TempDir(), "plain")}, easyrest.HostRPC{})
	inline = info.Inline
	if err != nil || inline {
		t.Fatalf("inline %v err %v", inline, err)
	}
	got, _, err = plain.Put("a.txt", []byte("hi"), nil)
	if err != nil || got != "a.txt" {
		t.Fatalf("stored %q err %v", got, err)
	}
}

func TestPutStreamGetStream(t *testing.T) {
	plug := newTestPlugin(t)
	rel, _, err := plug.PutStream("docs/note.txt", strings.NewReader("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rel != "docs/note.txt" {
		t.Fatalf("rel %q", rel)
	}
	got, err := readStream(plug, "docs/note.txt", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got != "hello" {
		t.Fatalf("body %q", got)
	}
	got, err = readStream(plug, "docs/note.txt", 4)
	if err != nil {
		t.Fatal(err)
	}
	if got != "o" {
		t.Fatalf("suffix %q", got)
	}
}

func readStream(plug *Plugin, rel string, offset int64) (string, error) {
	rc, _, _, err := plug.GetStream(rel, offset, nil)
	if err != nil {
		return "", err
	}
	defer rc.Close()
	body, err := io.ReadAll(rc)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func TestPutGetBin(t *testing.T) {
	plug := newTestPlugin(t)
	rel, ctx, err := plug.Put("docs/note.txt", []byte("hello"), map[string]any{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	if rel != "docs/note.txt" {
		t.Fatalf("rel %q", rel)
	}
	if ctx["k"] != "v" {
		t.Fatalf("ctx %#v", ctx)
	}
	body, mime, _, err := plug.GetBin("docs/note.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" {
		t.Fatalf("body %q", body)
	}
	if mime != "text/plain" && mime != "text/plain; charset=utf-8" {
		t.Fatalf("mime %q", mime)
	}
}

func TestMetadata(t *testing.T) {
	plug := newTestPlugin(t)
	if _, _, err := plug.Put("docs/note.txt", []byte("hello"), nil); err != nil {
		t.Fatal(err)
	}
	meta, err := plug.GetMetadata("docs/note.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Size != 5 {
		t.Fatalf("size %d", meta.Size)
	}
	if meta.Mime != "text/plain; charset=utf-8" {
		t.Fatalf("mime %q", meta.Mime)
	}
	if meta.ModTime.IsZero() || meta.Created.IsZero() {
		t.Fatalf("timestamps mod=%v created=%v", meta.ModTime, meta.Created)
	}
}

func TestGetUrl(t *testing.T) {
	plug := newTestPlugin(t)
	if _, _, err := plug.Put("docs/note.txt", []byte("hello"), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := plug.Put("docs/sub/b.txt", []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	ctx := map[string]any{
		"request": map[string]any{
			"scheme": "https",
			"host":   "example.com:8433",
			"prefix": "/someapp",
		},
	}
	empty, err := plug.GetUrl(nil, ctx)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty %#v err %v", empty, err)
	}
	got, err := plug.GetUrl([]string{"docs/note.txt", "docs/sub/b.txt"}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []easyrest.StorageURL{
		{URL: "https://example.com:8433/someapp/media/local/docs/note.txt", Mime: "text/plain; charset=utf-8"},
		{URL: "https://example.com:8433/someapp/media/local/docs/sub/b.txt", Mime: "text/plain; charset=utf-8"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] %#v want %#v", i, got[i], want[i])
		}
	}
	if _, err := plug.GetUrl([]string{"docs/note.txt", "missing.txt"}, ctx); err == nil {
		t.Fatal("expected error for a missing path")
	}
}

func TestList(t *testing.T) {
	plug := newTestPlugin(t)
	if _, _, err := plug.Put("docs/note.txt", []byte("hello"), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := plug.Put("docs/sub/b.txt", []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	root, err := plug.List("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(root) != 1 || root[0].Name != "docs" || root[0].Type != "dir" || root[0].Path != "" {
		t.Fatalf("root %#v", root)
	}
	docs, err := plug.List("docs", nil)
	if err != nil {
		t.Fatal(err)
	}
	var file, dir bool
	for _, entry := range docs {
		switch entry.Name {
		case "note.txt":
			file = entry.Type == "file" && entry.Path == "docs/note.txt" && entry.Mime != ""
		case "sub":
			dir = entry.Type == "dir" && entry.Path == ""
		}
	}
	if !file || !dir {
		t.Fatalf("docs %#v", docs)
	}
	if _, err := plug.List("docs/note.txt", nil); err == nil {
		t.Fatal("expected error listing a file")
	}
}

func TestDelete(t *testing.T) {
	plug := newTestPlugin(t)
	if _, _, err := plug.Put("docs/note.txt", []byte("hello"), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := plug.Put("docs/sub/b.txt", []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	if err := plug.Delete("docs/note.txt", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := plug.GetBin("docs/note.txt", nil); err == nil {
		t.Fatal("file still present")
	}
	if err := plug.Delete("docs", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := plug.List("docs", nil); err == nil {
		t.Fatal("directory still present")
	}
}

func TestRejectEscape(t *testing.T) {
	plug := newTestPlugin(t)
	for _, rel := range []string{"../outside.txt", "/etc/passwd", `docs\note.txt`, ".."} {
		if _, _, err := plug.Put(rel, []byte("x"), nil); err == nil {
			t.Fatalf("put accepted %q", rel)
		}
		if _, _, _, err := plug.GetBin(rel, nil); err == nil {
			t.Fatalf("get accepted %q", rel)
		}
		if err := plug.Delete(rel, nil); err == nil {
			t.Fatalf("delete accepted %q", rel)
		}
	}
}
