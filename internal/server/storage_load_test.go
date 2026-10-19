package server

import (
	"path/filepath"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/config"
)

func TestLoadPlugins_Storage(t *testing.T) {
	orig := GetConfig()
	t.Cleanup(func() {
		SetConfig(orig)
		LoadPlugins()
	})

	dir := filepath.Join(t.TempDir(), "media")
	SetConfig(config.Config{
		StoragePlugins: map[string]config.StoragePluginConfig{
			"local":  {Settings: map[string]any{"dir": dir}},
			"memory": {},
			"custom": {Path: "/does/not/exist/easyrest-storage-custom"},
		},
	})
	LoadPlugins()

	loaded := storagePlugins.Load()
	localRef, ok := (*loaded)["local"]
	if !ok || localRef.Plugin == nil || localRef.Root != dir {
		t.Fatalf("local %#v", localRef)
	}
	memRef, ok := (*loaded)["memory"]
	if !ok || memRef.Plugin == nil || memRef.Root != "." {
		t.Fatalf("memory %#v", memRef)
	}
	if _, ok := (*loaded)["custom"]; ok {
		t.Fatal("missing executable should not load")
	}
}

func TestLoadPlugins_StorageDrivers(t *testing.T) {
	orig := GetConfig()
	t.Cleanup(func() {
		SetConfig(orig)
		LoadPlugins()
	})

	photos := filepath.Join(t.TempDir(), "photos")
	docs := filepath.Join(t.TempDir(), "docs")
	SetConfig(config.Config{
		StoragePlugins: map[string]config.StoragePluginConfig{
			"photos": {Plugin: "local", Settings: map[string]any{"dir": photos}},
			"docs":   {Plugin: "local", Settings: map[string]any{"dir": docs}},
			"memory": {},
			"custom": {Plugin: "local", Path: "/does/not/exist/easyrest-storage-local"},
		},
	})
	LoadPlugins()

	loaded := storagePlugins.Load()
	photosRef, ok := (*loaded)["photos"]
	if !ok || photosRef.Root != photos {
		t.Fatalf("photos %#v", photosRef)
	}
	docsRef, ok := (*loaded)["docs"]
	if !ok || docsRef.Root != docs {
		t.Fatalf("docs %#v", docsRef)
	}
	if (*loaded)["memory"].Plugin == nil || (*loaded)["memory"].Root != "." {
		t.Fatalf("memory %#v", (*loaded)["memory"])
	}
	if _, ok := (*loaded)["custom"]; ok {
		t.Fatal("missing executable should not load")
	}
}
