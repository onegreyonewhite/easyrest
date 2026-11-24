package memory

import (
	"io"
	"strings"
	"testing"
	"time"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func newTestPlugin(t *testing.T) *Plugin {
	t.Helper()
	plug := New()
	info, err := plug.Init(map[string]any{"name": "memory"}, easyrest.HostRPC{})
	root, inline := info.Root, info.Inline
	if err != nil {
		t.Fatal(err)
	}
	if root != "." || inline {
		t.Fatalf("root %q inline %v", root, inline)
	}
	return plug
}

func TestInlineSetting(t *testing.T) {
	plug := New()
	info, err := plug.Init(map[string]any{"name": "memory", "inline": true}, easyrest.HostRPC{})
	_, inline := info.Root, info.Inline
	if err != nil || !inline {
		t.Fatalf("inline %v err %v", inline, err)
	}
	got, _, err := plug.Put("a.txt", []byte("hi"), nil)
	want := easyrest.FormatDataURL("text/plain; charset=utf-8", []byte("hi"))
	if err != nil || got != want {
		t.Fatalf("stored %q err %v", got, err)
	}
	body, _, _, err := plug.GetBin("a.txt", nil)
	if err != nil || string(body) != "hi" {
		t.Fatalf("body %q err %v", body, err)
	}
	typed, _, err := plug.Put("b.bin", []byte{0x00, 0x01}, map[string]any{easyrest.CtxStorageMIME: "image/png"})
	if err != nil || typed != easyrest.FormatDataURL("image/png", []byte{0x00, 0x01}) {
		t.Fatalf("typed %q err %v", typed, err)
	}

	plain := New()
	info, err = plain.Init(map[string]any{"name": "memory"}, easyrest.HostRPC{})
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
	if got := readMemStream(t, plug, 0); got != "hello" {
		t.Fatalf("body %q", got)
	}
	if got := readMemStream(t, plug, 4); got != "o" {
		t.Fatalf("suffix %q", got)
	}
}

func readMemStream(t *testing.T, plug *Plugin, offset int64) string {
	t.Helper()
	rc, _, _, err := plug.GetStream("docs/note.txt", offset, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	body, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestPutGetBin(t *testing.T) {
	plug := newTestPlugin(t)
	rel, ctx, err := plug.Put("docs/note.txt", []byte("hello"), map[string]any{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	if rel != "docs/note.txt" || ctx["k"] != "v" {
		t.Fatalf("rel %q ctx %#v", rel, ctx)
	}
	body, mimeType, _, err := plug.GetBin("docs/note.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" || mimeType != "text/plain; charset=utf-8" {
		t.Fatalf("body %q mime %q", body, mimeType)
	}
}

func TestMetadataCreatedStays(t *testing.T) {
	plug := newTestPlugin(t)
	if _, _, err := plug.Put("docs/note.txt", []byte("hello"), nil); err != nil {
		t.Fatal(err)
	}
	first, err := plug.GetMetadata("docs/note.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, _, err := plug.Put("docs/note.txt", []byte("hello!"), nil); err != nil {
		t.Fatal(err)
	}
	second, err := plug.GetMetadata("docs/note.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.Size != 6 || !second.Created.Equal(first.Created) || !second.ModTime.After(first.ModTime) {
		t.Fatalf("first %#v second %#v", first, second)
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
		{URL: "https://example.com:8433/someapp/media/memory/docs/note.txt", Mime: "text/plain; charset=utf-8"},
		{URL: "https://example.com:8433/someapp/media/memory/docs/sub/b.txt", Mime: "text/plain; charset=utf-8"},
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
