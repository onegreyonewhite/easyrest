package plugin

import "testing"

func TestStorageFileURL(t *testing.T) {
	ctx := map[string]any{
		"request": map[string]any{
			"scheme": "https",
			"host":   "example.com:8433",
			"prefix": "/someapp",
		},
	}
	got := StorageFileURL(ctx, "local", "a/b.txt")
	want := "https://example.com:8433/someapp/media/local/a/b.txt"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
