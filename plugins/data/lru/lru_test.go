package cache

import (
	"testing"
	"time"
)

func TestSimpleCachePlugin_BasicSetGet(t *testing.T) {
	plugin := NewSimpleCachePlugin()
	if err := plugin.InitConnection(""); err != nil {
		t.Fatalf("InitConnection failed: %v", err)
	}

	key := "foo"
	value := "bar"
	if err := plugin.Set(key, value, 2*time.Second); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	got, err := plugin.Get(key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got != value {
		t.Errorf("Get returned %q, want %q", got, value)
	}
}

func TestSimpleCachePlugin_Expiration(t *testing.T) {
	plugin := NewSimpleCachePlugin()
	if err := plugin.InitConnection(""); err != nil {
		t.Fatalf("InitConnection failed: %v", err)
	}

	key := "expiring"
	value := "soon"
	if err := plugin.Set(key, value, 100*time.Millisecond); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	_, err := plugin.Get(key)
	if err == nil {
		t.Errorf("Expected error for expired key, got nil")
	}
}

func TestSimpleCachePlugin_DefaultExpiration(t *testing.T) {
	plugin := NewSimpleCachePlugin()
	if err := plugin.InitConnection(""); err != nil {
		t.Fatalf("InitConnection failed: %v", err)
	}

	key := "defaultTTL"
	value := "baz"
	if err := plugin.Set(key, value, 0); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	got, err := plugin.Get(key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got != value {
		t.Errorf("Get returned %q, want %q", got, value)
	}
}

func TestSimpleCachePlugin_MissingKey(t *testing.T) {
	plugin := NewSimpleCachePlugin()
	if err := plugin.InitConnection(""); err != nil {
		t.Fatalf("InitConnection failed: %v", err)
	}

	_, err := plugin.Get("notfound")
	if err == nil {
		t.Errorf("Expected error for missing key, got nil")
	}
}

func TestSimpleCachePluginClose(t *testing.T) {
	plugin := NewSimpleCachePlugin()
	if err := plugin.InitConnection(""); err != nil {
		t.Fatalf("InitConnection failed: %v", err)
	}
	if err := plugin.Set("key", "value", time.Minute); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	plugin.Close()
	if plugin.cache != nil {
		t.Fatal("expected cache to be nil after Close")
	}
}

func TestSimpleCachePlugin_URIQueryParams(t *testing.T) {
	plugin := NewSimpleCachePlugin()
	if err := plugin.InitConnection("memory:///?cleanupInterval=1s&maxOpenConns=1s"); err != nil {
		t.Fatalf("InitConnection failed: %v", err)
	}
	if plugin.cache == nil {
		t.Fatal("expected cache to be initialized from URI query params")
	}
	if err := plugin.Set("k", "v", 0); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	got, err := plugin.Get("k")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got != "v" {
		t.Errorf("Get returned %q, want v", got)
	}
}

func TestSimpleCachePlugin_MalformedURIDoesNotPanic(t *testing.T) {
	plugin := NewSimpleCachePlugin()
	if err := plugin.InitConnection("://%zz"); err != nil {
		t.Fatalf("InitConnection should ignore parse errors, got %v", err)
	}
	if plugin.cache == nil {
		t.Fatal("expected cache to fall back to defaults")
	}
}

func TestSimpleCachePlugin_GetNonStringValue(t *testing.T) {
	plugin := NewSimpleCachePlugin()
	if err := plugin.InitConnection(""); err != nil {
		t.Fatal(err)
	}
	plugin.cache.Set("bad", 123, time.Minute)
	_, err := plugin.Get("bad")
	if err == nil {
		t.Fatal("expected type error for non-string cached value")
	}
}
