package config

import (
	"strings"
	"testing"
)

func TestLoad_StorageAuth(t *testing.T) {
	okPath := writeConfig(t, "ok.yaml", `
auth_plugins:
  jwt: {}
storage_plugins:
  files:
    auth: [jwt]
`)
	cfg := mustLoad(t, []string{okPath}, "")
	if len(cfg.StoragePlugins["files"].Auth) != 1 || cfg.StoragePlugins["files"].Auth[0] != "jwt" {
		t.Fatalf("auth %#v", cfg.StoragePlugins["files"].Auth)
	}

	badPath := writeConfig(t, "bad.yaml", `
auth_plugins:
  jwt: {}
storage_plugins:
  files:
    auth: [missing]
`)
	if _, err := Load([]string{badPath}, ""); err == nil || !strings.Contains(err.Error(), "auth") {
		t.Fatalf("unknown auth err = %v", err)
	}
}
