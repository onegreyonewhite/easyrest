package dbqueryhook

import (
	"testing"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func mustInit(t *testing.T, settings map[string]any) *Plugin {
	t.Helper()
	p := New()
	if err := p.Init(settings); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return p
}

func TestInitEmpty(t *testing.T) {
	p := mustInit(t, nil)
	if p.byType == nil || p.byKey == nil {
		t.Fatal("expected compiled maps")
	}
	ctx := map[string]any{easyrest.CtxDBType: "mysql"}
	got, status, err := p.PreRequest("orders", ctx)
	if err != nil || status != nil {
		t.Fatalf("PreRequest: %v %v", status, err)
	}
	if _, ok := got[easyrest.CtxDBPreRequest]; ok {
		t.Fatalf("expected no hooks: %#v", got)
	}
	got["marker"] = true
	if ctx["marker"] != true {
		t.Fatal("expected same ctx map when no rules apply")
	}
}

func TestInitPostgreSQLAliasAndYAML(t *testing.T) {
	p := mustInit(t, map[string]any{
		"by_type": map[string]any{
			"postgresql": map[string]any{
				"pre_request":  "custom_headers",
				"post_request": "after_hook",
			},
		},
	})
	if _, ok := p.byType["postgres"]; !ok {
		t.Fatalf("expected postgres alias, got %#v", p.byType)
	}
	if p.byType == nil {
		t.Fatal("maps must be Init-built")
	}
}

func TestInitInvalidRoutine(t *testing.T) {
	p := New()
	err := p.Init(map[string]any{
		"by_type": map[string]any{
			"mysql": map[string]any{"pre_request": "foo-bar"},
		},
	})
	if err == nil {
		t.Fatal("expected Init error")
	}
}

func TestPreRequestTypeOnly(t *testing.T) {
	p := mustInit(t, map[string]any{
		"by_type": map[string]any{
			"mysql": map[string]any{
				"pre_request":  "custom_headers",
				"post_request": "after_hook",
			},
		},
	})
	mysql := map[string]any{easyrest.CtxDBType: "mysql"}
	got, _, err := p.PreRequest("any", mysql)
	if err != nil {
		t.Fatal(err)
	}
	if got[easyrest.CtxDBPreRequest] != "custom_headers" || got[easyrest.CtxDBPostRequest] != "after_hook" {
		t.Fatalf("mysql hooks: %#v", got)
	}
	if _, ok := mysql[easyrest.CtxDBPreRequest]; ok {
		t.Fatal("PreRequest must copy-on-write, not mutate the input map")
	}
	sqlite := map[string]any{easyrest.CtxDBType: "sqlite"}
	got, _, err = p.PreRequest("any", sqlite)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[easyrest.CtxDBPreRequest]; ok {
		t.Fatalf("sqlite should be unchanged: %#v", got)
	}
}

func TestPreRequestKeyOverridesPreOnly(t *testing.T) {
	p := mustInit(t, map[string]any{
		"by_type": map[string]any{
			"mysql": map[string]any{
				"pre_request":  "type_pre",
				"post_request": "type_post",
			},
		},
		"by_key": map[string]any{
			"Orders": map[string]any{
				"pre_request": "orders_headers",
			},
		},
	})
	ctx := map[string]any{easyrest.CtxDBType: "mysql"}
	got, _, err := p.PreRequest("ORDERS", ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got[easyrest.CtxDBPreRequest] != "orders_headers" {
		t.Fatalf("pre: %#v", got[easyrest.CtxDBPreRequest])
	}
	if got[easyrest.CtxDBPostRequest] != "type_post" {
		t.Fatalf("post should stay from type: %#v", got[easyrest.CtxDBPostRequest])
	}
}

func TestPreRequestKeyEmptyClearsTypePre(t *testing.T) {
	p := mustInit(t, map[string]any{
		"by_type": map[string]any{
			"mysql": map[string]any{
				"pre_request":  "type_pre",
				"post_request": "type_post",
			},
		},
		"by_key": map[string]any{
			"orders": map[string]any{
				"pre_request": "",
			},
		},
	})
	ctx := map[string]any{easyrest.CtxDBType: "mysql"}
	got, _, err := p.PreRequest("orders", ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[easyrest.CtxDBPreRequest]; ok {
		t.Fatalf("pre should be cleared: %#v", got)
	}
	if got[easyrest.CtxDBPostRequest] != "type_post" {
		t.Fatalf("post: %#v", got[easyrest.CtxDBPostRequest])
	}
}

func TestPreRequestKeyOnlyWithoutType(t *testing.T) {
	p := mustInit(t, map[string]any{
		"by_key": map[string]any{
			"test": map[string]any{"pre_request": "schema.hook"},
		},
	})
	got, _, err := p.PreRequest("test", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if got[easyrest.CtxDBPreRequest] != "schema.hook" {
		t.Fatalf("got %#v", got)
	}
}

func TestPreRequestDoesNotRecreateMaps(t *testing.T) {
	p := mustInit(t, map[string]any{
		"by_key": map[string]any{
			"test": map[string]any{"pre_request": "hook"},
		},
	})
	orig := p.byKey
	_, _, err := p.PreRequest("test", map[string]any{easyrest.CtxDBType: "mysql"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.byKey) != 1 || orig["test"].pre.val != "hook" {
		t.Fatal("PreRequest must not rebuild Init maps")
	}
}

func TestPostRequestNoHeaders(t *testing.T) {
	p := mustInit(t, nil)
	headers, err := p.PostRequest("test", nil)
	if err != nil || headers != nil {
		t.Fatalf("PostRequest: %v %v", headers, err)
	}
}
