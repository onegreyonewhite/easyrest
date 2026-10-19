package responseheaders

import (
	"strings"
	"testing"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func mustInit(t *testing.T, settings map[string]any) *Plugin {
	t.Helper()
	p := New()
	if _, err := p.Init(settings, easyrest.HostRPC{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return p
}

func TestInit(t *testing.T) {
	p := mustInit(t, map[string]any{
		"headers": map[string]any{"X-Test": "1"},
	})
	if p.mode != modeSkip {
		t.Fatalf("default mode: got %v want skip", p.mode)
	}
	if len(p.headers) != 1 || p.headers[0].name != "X-Test" || p.headers[0].value != "1" {
		t.Fatalf("headers: %#v", p.headers)
	}

	p2 := mustInit(t, map[string]any{
		"headers":     map[string]any{"A": "b"},
		"on_conflict": "overwrite",
	})
	if p2.mode != modeOverwrite {
		t.Fatalf("mode: %v", p2.mode)
	}

	errCases := []struct {
		name     string
		settings map[string]any
		contains string
	}{
		{
			name:     "unknown on_conflict",
			settings: map[string]any{"headers": map[string]any{"X": "1"}, "on_conflict": "merge"},
			contains: "on_conflict",
		},
		{
			name:     "missing headers",
			settings: map[string]any{},
			contains: "headers",
		},
		{
			name:     "empty header name",
			settings: map[string]any{"headers": map[string]any{"": "x"}},
			contains: "header name",
		},
		{
			name:     "non-string value",
			settings: map[string]any{"headers": map[string]any{"X": 1}},
			contains: "string",
		},
		{
			name: "duplicate canonical",
			settings: map[string]any{
				"headers": map[string]any{
					"Cache-Control": "a",
					"cache-control": "b",
				},
			},
			contains: "duplicate",
		},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			p := New()
			_, err := p.Init(tc.settings, easyrest.HostRPC{})
			if err == nil {
				t.Fatal("expected error")
			}
			if tc.contains != "" && !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("error %q should contain %q", err.Error(), tc.contains)
			}
		})
	}
}

func TestPreRequest(t *testing.T) {
	p := mustInit(t, map[string]any{"headers": map[string]any{"X-A": "1"}})
	ctx := map[string]any{"method": "GET"}
	got, status, err := p.PreRequest("db", ctx)
	if status != nil || err != nil {
		t.Fatalf("unexpected status/err: %v %v", status, err)
	}
	ctx["__probe"] = true
	if got["__probe"] != true {
		t.Fatal("expected same context map")
	}
	delete(ctx, "__probe")
	if _, ok := got["response.header.X-A"]; ok {
		t.Fatal("PreRequest must not set response headers")
	}
}

func TestPostRequest(t *testing.T) {
	t.Run("absent sets header", func(t *testing.T) {
		p := mustInit(t, map[string]any{"headers": map[string]any{"X-New": "v"}})
		ctx := map[string]any{}
		_, err := p.PostRequest("db", ctx)
		if err != nil {
			t.Fatal(err)
		}
		if ctx["response.header.X-New"] != "v" {
			t.Fatalf("got %#v", ctx)
		}
	})

	t.Run("skip keeps response.header", func(t *testing.T) {
		p := mustInit(t, map[string]any{
			"headers":     map[string]any{"X-Keep": "new"},
			"on_conflict": "skip",
		})
		ctx := map[string]any{"response.header.X-Keep": "old"}
		_, _ = p.PostRequest("db", ctx)
		if ctx["response.header.X-Keep"] != "old" {
			t.Fatalf("got %#v", ctx)
		}
	})

	t.Run("skip keeps response.headers", func(t *testing.T) {
		p := mustInit(t, map[string]any{
			"headers":     map[string]any{"X-Array": "new"},
			"on_conflict": "skip",
		})
		ctx := map[string]any{
			"response.headers": []map[string]any{{"X-Array": "from-sql"}},
		}
		_, _ = p.PostRequest("db", ctx)
		arr := ctx["response.headers"].([]map[string]any)
		if arr[0]["X-Array"] != "from-sql" {
			t.Fatalf("got %#v", ctx)
		}
		if _, ok := ctx["response.header.X-Array"]; ok {
			t.Fatal("should not add prefix key when array has value")
		}
	})

	t.Run("overwrite replaces both sources", func(t *testing.T) {
		p := mustInit(t, map[string]any{
			"headers":     map[string]any{"X-One": "cfg"},
			"on_conflict": "overwrite",
		})
		ctx := map[string]any{
			"response.header.X-One": "old",
			"response.headers":      []map[string]any{{"X-One": "sql"}},
		}
		_, _ = p.PostRequest("db", ctx)
		if ctx["response.header.X-One"] != "cfg" {
			t.Fatalf("prefix: %#v", ctx)
		}
		if raw, ok := ctx["response.headers"]; ok {
			arr, _ := raw.([]map[string]any)
			for _, obj := range arr {
				if _, ok := obj["X-One"]; ok {
					t.Fatalf("array should not contain X-One: %#v", ctx)
				}
			}
		}
	})

	t.Run("append joins", func(t *testing.T) {
		p := mustInit(t, map[string]any{
			"headers":     map[string]any{"X-Multi": "c"},
			"on_conflict": "append",
		})
		ctx := map[string]any{"response.header.X-Multi": "a"}
		_, _ = p.PostRequest("db", ctx)
		if ctx["response.header.X-Multi"] != "a, c" {
			t.Fatalf("got %#v", ctx)
		}
	})

	t.Run("canonical cache-control", func(t *testing.T) {
		p := mustInit(t, map[string]any{
			"headers":     map[string]any{"cache-control": "public"},
			"on_conflict": "overwrite",
		})
		ctx := map[string]any{"response.header.Cache-Control": "private"}
		_, _ = p.PostRequest("db", ctx)
		if ctx["response.header.Cache-Control"] != "public" {
			t.Fatalf("got %#v", ctx)
		}
	})
}

func TestPostRequestChain(t *testing.T) {
	security := mustInit(t, map[string]any{
		"on_conflict": "skip",
		"headers": map[string]any{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
		},
	})
	cachePublic := mustInit(t, map[string]any{
		"on_conflict": "overwrite",
		"headers": map[string]any{
			"Cache-Control": "public, max-age=3600",
		},
	})
	cacheRevalidate := mustInit(t, map[string]any{
		"on_conflict": "append",
		"headers": map[string]any{
			"Cache-Control": "must-revalidate",
		},
	})

	ctx := map[string]any{
		"response.header.Cache-Control":   "private",
		"response.header.X-Frame-Options": "SAMEORIGIN",
	}
	for _, p := range []*Plugin{security, cachePublic, cacheRevalidate} {
		if _, err := p.PostRequest("app", ctx); err != nil {
			t.Fatal(err)
		}
	}
	if ctx["response.header.X-Content-Type-Options"] != "nosniff" {
		t.Fatalf("security header: %#v", ctx)
	}
	if ctx["response.header.X-Frame-Options"] != "SAMEORIGIN" {
		t.Fatalf("skip should keep frame options: %#v", ctx)
	}
	wantCC := "public, max-age=3600, must-revalidate"
	if ctx["response.header.Cache-Control"] != wantCC {
		t.Fatalf("cache chain: got %q want %q", ctx["response.header.Cache-Control"], wantCC)
	}
}
