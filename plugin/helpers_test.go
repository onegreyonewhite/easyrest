package plugin

import "testing"

func TestMergeResponseSettings_Empty(t *testing.T) {
	ctx := map[string]any{"timezone": "UTC"}
	if got := MergeResponseSettings(ctx, nil); got != nil {
		t.Fatalf("nil settings: %#v", got)
	}
	if got := MergeResponseSettings(ctx, map[string]string{}); got != nil {
		t.Fatalf("empty settings: %#v", got)
	}
	if ctx["timezone"] != "UTC" || len(ctx) != 1 {
		t.Fatalf("incoming ctx must stay untouched: %#v", ctx)
	}
}

func TestMergeResponseSettings_MergeKeepsTimezone(t *testing.T) {
	ctx := map[string]any{"timezone": "UTC", "claims": map[string]any{"sub": "u1"}}
	got := MergeResponseSettings(ctx, map[string]string{
		"response.headers": `[{"X-From-Sql":"1"}]`,
	})
	if got == nil {
		t.Fatal("expected merged ctx")
	}
	if got["timezone"] != "UTC" {
		t.Fatalf("timezone: %#v", got["timezone"])
	}
	if got["response.headers"] != `[{"X-From-Sql":"1"}]` {
		t.Fatalf("headers: %#v", got["response.headers"])
	}
	if got["timezone"] != ctx["timezone"] {
		t.Fatal("expected same map pointer")
	}
	ctx["timezone"] = "Europe/Paris"
	if got["timezone"] != "Europe/Paris" {
		t.Fatal("merge must mutate incoming ctx in place")
	}
}

func TestMergeResponseSettings_SkipBlanks(t *testing.T) {
	ctx := map[string]any{"timezone": "UTC"}
	if got := MergeResponseSettings(ctx, map[string]string{"": "x", "response.status": ""}); got != nil {
		t.Fatalf("only blanks should yield nil: %#v", got)
	}
	if len(ctx) != 1 {
		t.Fatalf("ctx mutated: %#v", ctx)
	}
}

func TestContextRoutineName(t *testing.T) {
	if got := ContextRoutineName(nil, CtxDBPreRequest); got != "" {
		t.Fatalf("nil ctx: %q", got)
	}
	if got := ContextRoutineName(map[string]any{}, CtxDBPreRequest); got != "" {
		t.Fatalf("missing: %q", got)
	}
	if got := ContextRoutineName(map[string]any{CtxDBPreRequest: ""}, CtxDBPreRequest); got != "" {
		t.Fatalf("empty: %q", got)
	}
	if got := ContextRoutineName(map[string]any{CtxDBPreRequest: 1}, CtxDBPreRequest); got != "" {
		t.Fatalf("non-string: %q", got)
	}
	if got := ContextRoutineName(map[string]any{CtxDBPreRequest: "custom_headers"}, CtxDBPreRequest); got != "custom_headers" {
		t.Fatalf("ident: %q", got)
	}
	if got := ContextRoutineName(map[string]any{CtxDBPostRequest: "public.custom_headers"}, CtxDBPostRequest); got != "public.custom_headers" {
		t.Fatalf("schema.ident: %q", got)
	}
	if got := ContextRoutineName(map[string]any{CtxDBPreRequest: "foo.bar.baz"}, CtxDBPreRequest); got != "" {
		t.Fatalf("too many dots: %q", got)
	}
	if got := ContextRoutineName(map[string]any{CtxDBPreRequest: "foo-bar"}, CtxDBPreRequest); got != "" {
		t.Fatalf("hyphen: %q", got)
	}
	if got := ContextRoutineName(map[string]any{CtxDBPreRequest: "foo;drop"}, CtxDBPreRequest); got != "" {
		t.Fatalf("unsafe: %q", got)
	}
	if !IsContextRoutineKey(CtxDBPreRequest) || !IsContextRoutineKey(CtxDBPostRequest) {
		t.Fatal("expected hook keys")
	}
	if IsContextRoutineKey("timezone") {
		t.Fatal("timezone is not a hook key")
	}
}

func TestSkipDBSessionKey(t *testing.T) {
	skip := []string{
		"response.header.Resource-Version",
		"response.header.ETag",
		"response.headers",
		"response.status",
		CtxCacheInvalidate,
		CtxCacheETagVariant,
		CtxDBPreRequest,
		CtxDBPostRequest,
		"_",
		"_mw.trace",
		"_internal",
	}
	for _, k := range skip {
		if !SkipDBSessionKey(k) {
			t.Fatalf("expected skip %q", k)
		}
	}
	keep := []string{"timezone", "claims", "headers", "prefer", "table", "foo_bar"}
	for _, k := range keep {
		if SkipDBSessionKey(k) {
			t.Fatalf("must inject %q", k)
		}
	}
}

func TestCacheInvalidateNames(t *testing.T) {
	if got := CacheInvalidateNames(nil); got != nil {
		t.Fatalf("nil ctx: %#v", got)
	}
	if got := CacheInvalidateNames(map[string]any{}); got != nil {
		t.Fatalf("missing: %#v", got)
	}
	if got := CacheInvalidateNames(map[string]any{CtxCacheInvalidate: 1}); got != nil {
		t.Fatalf("non-string: %#v", got)
	}
	if got := CacheInvalidateNames(map[string]any{CtxCacheInvalidate: "  , , "}); got != nil {
		t.Fatalf("blank tokens: %#v", got)
	}
	got := CacheInvalidateNames(map[string]any{
		CtxCacheInvalidate: " users, orders ,v_stats, foo-bar, public.v_users, a.b.c ",
	})
	if len(got) != 4 || got[0] != "users" || got[1] != "orders" || got[2] != "v_stats" || got[3] != "public.v_users" {
		t.Fatalf("parsed: %#v", got)
	}
}

func TestDBTypeFromURI(t *testing.T) {
	if got := URIScheme("mysql://user@host/db"); got != "mysql" {
		t.Fatalf("scheme: %q", got)
	}
	if got := URIScheme("not-a-uri"); got != "" {
		t.Fatalf("missing scheme: %q", got)
	}
	if got := CanonicalDBType("PostgreSQL"); got != "postgres" {
		t.Fatalf("alias: %q", got)
	}
	if got := CanonicalDBType("mysql"); got != "mysql" {
		t.Fatalf("mysql: %q", got)
	}
	if got := CanonicalDBType(""); got != "" {
		t.Fatalf("empty: %q", got)
	}
	if got := DBTypeFromURI("postgres://localhost/db"); got != "postgres" {
		t.Fatalf("postgres uri: %q", got)
	}
	if got := DBTypeFromURI("postgresql://localhost/db"); got != "postgres" {
		t.Fatalf("postgresql uri: %q", got)
	}
	if got := DBTypeFromURI("sqlite:///tmp/x.db"); got != "sqlite" {
		t.Fatalf("sqlite uri: %q", got)
	}
	if got := DBTypeFromURI(""); got != "" {
		t.Fatalf("empty uri: %q", got)
	}
}

func TestMergeResponseSettings_NilIncoming(t *testing.T) {
	got := MergeResponseSettings(nil, map[string]string{
		"response.status": "418",
		"":                "skip",
		"response.empty":  "",
	})
	if got == nil || got["response.status"] != "418" {
		t.Fatalf("nil ctx + settings: %#v", got)
	}
	if _, ok := got["response.empty"]; ok {
		t.Fatalf("empty value must be skipped: %#v", got)
	}
	if len(got) != 1 {
		t.Fatalf("expected only response.status: %#v", got)
	}
}

func TestFormatToContext(t *testing.T) {
	got, err := FormatToContext(map[string]any{
		"User-Name": "alice",
		"nested":    map[string]any{"id": 7, "ok": true},
		"list":      []any{"a", 1.5},
		"skip":      "has;injection",
		"dash":      "has--comment",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got["user_name"] != "alice" {
		t.Fatalf("scalar: %#v", got)
	}
	if got["nested_id"] != "7" || got["nested_ok"] != "true" {
		t.Fatalf("nested: %#v", got)
	}
	if got["list_0"] != "a" || got["list_1"] != "1.5" {
		t.Fatalf("list: %#v", got)
	}
	if _, ok := got["skip"]; ok {
		t.Fatal("semicolon value must be skipped")
	}
	if _, ok := got["dash"]; ok {
		t.Fatal("comment value must be skipped")
	}
}

func TestFormatToContextSkipsHTTPAndCacheKeys(t *testing.T) {
	got, err := FormatToContext(map[string]any{
		"timezone":                         "UTC",
		"response.header.ETag":             `"abc"`,
		"response.header.Resource-Version": "abc",
		"response.headers":                 `[{"X":"1"}]`,
		"response.status":                  "200",
		CtxCacheInvalidate:                 "users",
		CtxCacheETagVariant:                "Accept=application/json",
		CtxDBPreRequest:                    "pre_hook",
		"_mw.secret":                       "nope",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got["timezone"] != "UTC" {
		t.Fatalf("timezone: %#v", got)
	}
	if len(got) != 1 {
		t.Fatalf("HTTP/cache keys must not flatten: %#v", got)
	}
}
