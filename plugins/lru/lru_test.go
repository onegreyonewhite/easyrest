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
