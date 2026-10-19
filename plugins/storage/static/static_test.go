package static

import (
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
