package static

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestStatic_DefaultDir(t *testing.T) {
	info, err := New().Init(nil, easyrest.HostRPC{})
	root, inline := info.Root, info.Inline
	if err != nil || inline {
		t.Fatalf("Init() = %q %v %v", root, inline, err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if root != filepath.Join(wd, "static") {
		t.Fatalf("root = %q", root)
	}
}

func TestGetStreamDiskOffset(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "note.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	plug := New()
	if _, err := plug.Init(map[string]any{"path": dir}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	if got := readStaticStream(t, plug, 0); got != "hello" {
		t.Fatalf("body %q", got)
	}
	if got := readStaticStream(t, plug, 4); got != "o" {
		t.Fatalf("suffix %q", got)
	}
}

func readStaticStream(t *testing.T, plug *Plugin, offset int64) string {
	t.Helper()
	rc, _, _, err := plug.GetStream("note.txt", offset, nil)
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

func TestStatic_EmbedFallback(t *testing.T) {
	plug := New()
	if _, err := plug.Init(map[string]any{"path": t.TempDir()}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	body, mimeType, _, err := plug.GetBin("swagger-ui.css", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 || !strings.Contains(mimeType, "text/css") {
		t.Fatalf("mime %q len %d", mimeType, len(body))
	}
}

func TestStatic_SwaggerUIVersion(t *testing.T) {
	plug := New()
	if _, err := plug.Init(map[string]any{"path": t.TempDir()}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	body, _, _, err := plug.GetBin("swagger-ui-bundle.js", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `PACKAGE_VERSION:"5.35.1"`) {
		t.Fatal("embedded Swagger UI bundle is not v5.35.1")
	}
}

func TestStatic_DirectoryOverridesEmbed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "swagger-ui.css"), []byte("local-css"), 0o644); err != nil {
		t.Fatal(err)
	}
	plug := New()
	if _, err := plug.Init(map[string]any{"path": dir}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	body, _, _, err := plug.GetBin("swagger-ui.css", nil)
	if err != nil || string(body) != "local-css" {
		t.Fatalf("body %q err %v", body, err)
	}
}

func TestStatic_PutRejected(t *testing.T) {
	plug := New()
	if _, err := plug.Init(map[string]any{"path": t.TempDir()}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := plug.Put("swagger-ui.css", []byte("x"), nil); err == nil {
		t.Fatal("expected put error")
	}
}

func TestStatic_DeleteRejected(t *testing.T) {
	plug := New()
	if _, err := plug.Init(map[string]any{"path": t.TempDir()}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	if err := plug.Delete("swagger-ui.css", nil); err == nil {
		t.Fatal("expected delete error")
	}
}
