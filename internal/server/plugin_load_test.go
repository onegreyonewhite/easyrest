package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandHomePath(t *testing.T) {
	plain := "/usr/bin/easyrest-auth-jwt"
	got, err := expandHomePath(plain)
	if err != nil || got != plain {
		t.Fatalf("plain path: %q %v", got, err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	got, err = expandHomePath("~/bin/plugin")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, "bin/plugin")
	if got != want {
		t.Fatalf("tilde: got %q want %q", got, want)
	}
}

func TestResolveNamedPluginPath_MissingDefault(t *testing.T) {
	_, origin, err := resolveNamedPluginPath("missing", "", "easyrest-middleware-does-not-exist")
	if err == nil {
		t.Fatal("expected missing executable error")
	}
	if origin != "easyrest-middleware-does-not-exist" {
		t.Fatalf("origin: %q", origin)
	}
	if !strings.Contains(err.Error(), "default executable") {
		t.Fatalf("error: %v", err)
	}
}

func TestResolveNamedPluginPath_MissingConfigured(t *testing.T) {
	configured := "/tmp/easyrest-not-a-real-plugin-bin"
	_, origin, err := resolveNamedPluginPath("x", configured, "easyrest-middleware-x")
	if err == nil {
		t.Fatal("expected missing path error")
	}
	if origin != configured {
		t.Fatalf("origin: %q", origin)
	}
}

func TestCheckFileAndFindPluginPath(t *testing.T) {
	dir := t.TempDir()
	name := "easyrest-plugin-faketestcov"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := checkFile(path); err != nil || got != path {
		t.Fatalf("checkFile exec: %q %v", got, err)
	}

	notExec := filepath.Join(dir, "notexec")
	if err := os.WriteFile(notExec, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := checkFile(notExec); err == nil {
		t.Fatal("expected not executable")
	}
	if _, err := checkFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected missing file")
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	got, err := findPluginPath(name)
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Fatalf("findPluginPath: %q want %q", got, path)
	}

	abs, origin, err := resolveNamedPluginPath("x", path, "unused")
	if err != nil {
		t.Fatal(err)
	}
	if origin != path {
		t.Fatalf("origin: %q", origin)
	}
	if abs == "" {
		t.Fatal("expected abs path")
	}

	if _, err := findPluginPath("easyrest-plugin-does-not-exist-xyz"); err == nil {
		t.Fatal("expected not found")
	}

	_, _, err = startPluginRPCClient(path, nil, true)
	if err == nil {
		t.Fatal("expected rpc client start to fail for a shell script")
	}
}
