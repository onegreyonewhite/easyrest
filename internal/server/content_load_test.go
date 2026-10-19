package server

import (
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestLoadPlugins_DefaultContentPlugins(t *testing.T) {
	orig := GetConfig()
	t.Cleanup(func() {
		SetConfig(orig)
		LoadPlugins()
	})

	SetConfig(config.Config{})
	LoadPlugins()
	cfg := GetConfig()
	for _, name := range easyrest.StandardContentNames() {
		plug, ok := cfg.ContentPlugins[name]
		if !ok || plug.Path != "" {
			t.Fatalf("content plugin %s = %#v present=%v", name, plug, ok)
		}
		loaded := contentPlugins.Load()
		ref, ok := (*loaded)[name]
		if !ok || ref.Plugin == nil || ref.Format != name {
			t.Fatalf("loaded %s %#v", name, ref)
		}
	}

	SetConfig(config.Config{ContentPlugins: map[string]config.ExternalPlugin{
		"custom": {Path: "/does/not/exist/easyrest-content-custom"},
	}})
	LoadPlugins()
	cfg = GetConfig()
	if _, ok := cfg.ContentPlugins["custom"]; !ok {
		t.Fatal("custom content plugin was dropped")
	}
	if _, ok := cfg.ContentPlugins["json"]; !ok {
		t.Fatal("json was not merged next to custom")
	}
	if _, ok := (*contentPlugins.Load())["custom"]; ok {
		t.Fatal("missing executable should not load")
	}
	if (*contentPlugins.Load())["json"].Plugin == nil {
		t.Fatal("json should still load")
	}
}

func TestLoadHTMLContentPlugin(t *testing.T) {
	orig := GetConfig()
	t.Cleanup(func() {
		SetConfig(orig)
		LoadPlugins()
	})
	SetConfig(config.Config{ContentPlugins: map[string]config.ExternalPlugin{
		"html": {},
	}})
	LoadPlugins()
	ref, ok := (*contentPlugins.Load())["html"]
	if !ok || ref.RenderMedia != easyrest.MediaTypeHTML || ref.ParserMedia != "" || ref.Format != "html" {
		t.Fatalf("html plugin %#v present=%v", ref, ok)
	}
	for _, name := range easyrest.StandardContentNames() {
		if name == "html" {
			t.Fatal("html is a standard name")
		}
	}
}
