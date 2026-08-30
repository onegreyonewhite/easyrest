package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goccy/go-json"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

type mockMiddlewarePlugin struct {
	name       string
	callCount  *int
	dbKey      *string
	failErr    error
	failStatus *int
	updateKey  string
	updateVal  any
}

func (m *mockMiddlewarePlugin) Init(settings map[string]any) error {
	return nil
}

func (m *mockMiddlewarePlugin) PreRequest(dbKey string, ctx map[string]any) (map[string]any, *int, error) {
	if m.callCount != nil {
		*m.callCount++
	}
	if m.dbKey != nil {
		*m.dbKey = dbKey
	}
	if m.failStatus != nil || m.failErr != nil {
		return ctx, m.failStatus, m.failErr
	}
	if m.updateKey != "" {
		updated := make(map[string]any, len(ctx)+1)
		for k, v := range ctx {
			updated[k] = v
		}
		updated[m.updateKey] = m.updateVal
		return updated, nil, nil
	}
	return ctx, nil, nil
}

func (m *mockMiddlewarePlugin) PostRequest(dbKey string, ctx map[string]any) (map[string]string, error) {
	return nil, nil
}

type errTest string

func (e errTest) Error() string { return string(e) }

type recordingMiddlewarePlugin struct {
	label string
	order *[]string
}

func (p *recordingMiddlewarePlugin) Init(settings map[string]any) error { return nil }

func (p *recordingMiddlewarePlugin) PreRequest(dbKey string, ctx map[string]any) (map[string]any, *int, error) {
	*p.order = append(*p.order, p.label)
	return ctx, nil, nil
}

func (p *recordingMiddlewarePlugin) PostRequest(dbKey string, ctx map[string]any) (map[string]string, error) {
	*p.order = append(*p.order, p.label+"-post")
	return nil, nil
}

func TestBuildMiddlewareChains(t *testing.T) {
	globalPlug := &mockMiddlewarePlugin{name: "global_ok"}
	dbPlug := &mockMiddlewarePlugin{name: "db_ok"}
	cfg := config.Config{
		GlobalRequestMiddlewares: []string{"global_ok", "global_missing"},
		MiddlewarePlugins: map[string]config.MiddlewareConfig{
			"global_ok":  {},
			"db_ok":      {},
			"not_loaded": {},
		},
		PluginMap: map[string]config.PluginConfig{
			"test": {
				RequestMiddlewares: []string{"db_ok", "db_missing", "not_loaded"},
			},
			"empty": {},
		},
	}
	loaded := map[string]easyrest.MiddlewarePlugin{
		"global_ok": globalPlug,
		"db_ok":     dbPlug,
	}

	global, perDb := buildMiddlewareChains(cfg, loaded)
	if len(global) != 1 || global[0] != globalPlug {
		t.Fatalf("global chain: %#v", global)
	}
	testChain := perDb["test"]
	if len(testChain) != 2 || testChain[0] != globalPlug || testChain[1] != dbPlug {
		t.Fatalf("per-db chain: %#v", testChain)
	}
	if _, ok := perDb["empty"]; !ok {
		t.Fatal("expected empty db key to still get global chain")
	}
	if len(perDb["empty"]) != 1 || perDb["empty"][0] != globalPlug {
		t.Fatalf("empty db chain: %#v", perDb["empty"])
	}
}

func TestRunPreRequestMiddlewares_Passthrough(t *testing.T) {
	callCount := 0
	dbKeySeen := ""
	plug := &mockMiddlewarePlugin{callCount: &callCount, dbKey: &dbKeySeen}
	dbMiddlewareOrder.Store(&map[string][]easyrest.MiddlewarePlugin{
		"test": {plug},
	})
	emptyGlobal := []easyrest.MiddlewarePlugin{}
	globalMiddlewareChain.Store(&emptyGlobal)

	w := httptest.NewRecorder()
	ctx := map[string]any{"method": "GET"}
	out, ok := runPreRequestMiddlewares(w, "test", ctx)
	if !ok {
		t.Fatal("expected middleware chain to succeed")
	}
	if callCount != 1 {
		t.Fatalf("expected PreRequest to be called once, got %d", callCount)
	}
	if dbKeySeen != "test" {
		t.Fatalf("expected dbKey test, got %q", dbKeySeen)
	}
	if out["method"] != "GET" {
		t.Fatalf("expected passthrough context, got %#v", out)
	}
}

func TestRunPreRequestMiddlewares_ErrorAndStatus(t *testing.T) {
	status403 := 403
	errPlug := &mockMiddlewarePlugin{failErr: errTest("blocked")}
	statusPlug := &mockMiddlewarePlugin{
		failStatus: &status403,
		failErr:    errTest("forbidden"),
	}

	t.Run("error defaults to 400", func(t *testing.T) {
		dbMiddlewareOrder.Store(&map[string][]easyrest.MiddlewarePlugin{
			"test": {errPlug},
		})
		w := httptest.NewRecorder()
		_, ok := runPreRequestMiddlewares(w, "test", map[string]any{})
		if ok {
			t.Fatal("expected middleware to stop chain")
		}
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
		if w.Body.String() != "blocked" {
			t.Fatalf("unexpected body: %q", w.Body.String())
		}
	})

	t.Run("status short-circuits", func(t *testing.T) {
		dbMiddlewareOrder.Store(&map[string][]easyrest.MiddlewarePlugin{
			"test": {statusPlug},
		})
		w := httptest.NewRecorder()
		_, ok := runPreRequestMiddlewares(w, "test", map[string]any{})
		if ok {
			t.Fatal("expected middleware to stop chain")
		}
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
		if w.Body.String() != "forbidden" {
			t.Fatalf("unexpected body: %q", w.Body.String())
		}
	})
}

func TestRunPreRequestMiddlewares_ChainStopsOnError(t *testing.T) {
	firstCalls := 0
	secondCalls := 0
	first := &mockMiddlewarePlugin{callCount: &firstCalls, failErr: errTest("stop")}
	second := &mockMiddlewarePlugin{callCount: &secondCalls}
	dbMiddlewareOrder.Store(&map[string][]easyrest.MiddlewarePlugin{
		"test": {first, second},
	})

	w := httptest.NewRecorder()
	_, ok := runPreRequestMiddlewares(w, "test", map[string]any{})
	if ok {
		t.Fatal("expected chain to stop")
	}
	if firstCalls != 1 || secondCalls != 0 {
		t.Fatalf("first=%d second=%d", firstCalls, secondCalls)
	}
}

func TestRunPreRequestMiddlewares_GlobalThenPerDB(t *testing.T) {
	order := []string{}
	globalPlug := &recordingMiddlewarePlugin{label: "global", order: &order}
	dbPlug := &recordingMiddlewarePlugin{label: "db", order: &order}
	dbMiddlewareOrder.Store(&map[string][]easyrest.MiddlewarePlugin{
		"test": {globalPlug, dbPlug},
	})

	w := httptest.NewRecorder()
	_, ok := runPreRequestMiddlewares(w, "test", map[string]any{})
	if !ok {
		t.Fatal("expected success")
	}
	if len(order) != 2 || order[0] != "global" || order[1] != "db" {
		t.Fatalf("unexpected order: %#v", order)
	}
}

func TestRunPreRequestMiddlewares_UnknownDBKeyUsesGlobalChain(t *testing.T) {
	callCount := 0
	plug := &mockMiddlewarePlugin{callCount: &callCount}
	dbMiddlewareOrder.Store(&map[string][]easyrest.MiddlewarePlugin{})
	global := []easyrest.MiddlewarePlugin{plug}
	globalMiddlewareChain.Store(&global)

	w := httptest.NewRecorder()
	_, ok := runPreRequestMiddlewares(w, "mock", map[string]any{})
	if !ok {
		t.Fatal("expected success")
	}
	if callCount != 1 {
		t.Fatalf("expected global chain for unknown dbKey, got %d calls", callCount)
	}
}

type postHeaderPlugin struct {
	label   string
	order   *[]string
	calls   *int
	headers map[string]string
	err     error
}

func (p *postHeaderPlugin) Init(settings map[string]any) error { return nil }

func (p *postHeaderPlugin) PreRequest(dbKey string, ctx map[string]any) (map[string]any, *int, error) {
	return ctx, nil, nil
}

func (p *postHeaderPlugin) PostRequest(dbKey string, ctx map[string]any) (map[string]string, error) {
	if p.calls != nil {
		*p.calls++
	}
	if p.order != nil {
		*p.order = append(*p.order, p.label)
	}
	return p.headers, p.err
}

func TestRunPostRequestMiddlewares_AddAndOrder(t *testing.T) {
	order := []string{}
	globalPlug := &postHeaderPlugin{
		label:   "global",
		order:   &order,
		headers: map[string]string{"X-MW": "g", "": "skip"},
	}
	dbPlug := &postHeaderPlugin{
		label:   "db",
		order:   &order,
		headers: map[string]string{"X-MW": "d"},
	}
	dbMiddlewareOrder.Store(&map[string][]easyrest.MiddlewarePlugin{
		"test": {globalPlug, dbPlug},
	})

	w := httptest.NewRecorder()
	w.Header().Set("X-Existing", "keep")
	runPostRequestMiddlewares(w, "test", map[string]any{"method": "GET"})

	if len(order) != 2 || order[0] != "global" || order[1] != "db" {
		t.Fatalf("unexpected order: %#v", order)
	}
	if got := w.Header().Values("X-MW"); len(got) != 2 || got[0] != "g" || got[1] != "d" {
		t.Fatalf("expected Add order g then d, got %#v", got)
	}
	if w.Header().Get("X-Existing") != "keep" {
		t.Fatalf("existing header should survive Add, got %q", w.Header().Get("X-Existing"))
	}
	if _, ok := w.Header()[http.CanonicalHeaderKey("")]; ok {
		t.Fatal("empty header name should be skipped")
	}
}

func TestRunPostRequestMiddlewares_EmptyChain(t *testing.T) {
	empty := []easyrest.MiddlewarePlugin{}
	dbMiddlewareOrder.Store(&map[string][]easyrest.MiddlewarePlugin{})
	globalMiddlewareChain.Store(&empty)

	w := httptest.NewRecorder()
	runPostRequestMiddlewares(w, "missing", map[string]any{})
	if len(w.Header()) != 0 {
		t.Fatalf("expected no headers, got %#v", w.Header())
	}
}

func TestRunPostRequestMiddlewares_ErrorStillAddsHeaders(t *testing.T) {
	first := &postHeaderPlugin{
		headers: map[string]string{"X-First": "1"},
		err:     errTest("post failed"),
	}
	second := &postHeaderPlugin{
		headers: map[string]string{"X-Second": "2"},
	}
	dbMiddlewareOrder.Store(&map[string][]easyrest.MiddlewarePlugin{
		"test": {first, second},
	})

	w := httptest.NewRecorder()
	runPostRequestMiddlewares(w, "test", map[string]any{})
	if w.Header().Get("X-First") != "1" || w.Header().Get("X-Second") != "2" {
		t.Fatalf("headers: %#v", w.Header())
	}
}

func TestRunPreRequestMiddlewares_DoesNotCallPostRequest(t *testing.T) {
	postCalls := 0
	status403 := 403
	plug := &countingPostPlugin{failStatus: &status403, postCalls: &postCalls}
	dbMiddlewareOrder.Store(&map[string][]easyrest.MiddlewarePlugin{
		"test": {plug},
	})

	w := httptest.NewRecorder()
	_, ok := runPreRequestMiddlewares(w, "test", map[string]any{})
	if ok {
		t.Fatal("expected PreRequest to stop")
	}
	if postCalls != 0 {
		t.Fatalf("PostRequest should not run on PreRequest short-circuit, got %d", postCalls)
	}
}

func TestRunPreRequestMiddlewares_AppliesContextHeadersOnStatus(t *testing.T) {
	status403 := 403
	plug := &headerOnFailPlugin{
		failStatus: &status403,
		ctxKey:     "response.header.X-From-Ctx",
		ctxVal:     "yes",
	}
	dbMiddlewareOrder.Store(&map[string][]easyrest.MiddlewarePlugin{
		"test": {plug},
	})

	w := httptest.NewRecorder()
	_, ok := runPreRequestMiddlewares(w, "test", map[string]any{})
	if ok {
		t.Fatal("expected PreRequest to stop")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if got := w.Header().Get("X-From-Ctx"); got != "yes" {
		t.Fatalf("expected X-From-Ctx before WriteHeader, got %q", got)
	}
}

type countingPostPlugin struct {
	failStatus *int
	postCalls  *int
}

func (p *countingPostPlugin) Init(settings map[string]any) error { return nil }

func (p *countingPostPlugin) PreRequest(dbKey string, ctx map[string]any) (map[string]any, *int, error) {
	return ctx, p.failStatus, errTest("stop")
}

func (p *countingPostPlugin) PostRequest(dbKey string, ctx map[string]any) (map[string]string, error) {
	*p.postCalls++
	return map[string]string{"X-Should-Not": "1"}, nil
}

type headerOnFailPlugin struct {
	failStatus *int
	ctxKey     string
	ctxVal     any
}

func (p *headerOnFailPlugin) Init(settings map[string]any) error { return nil }

func (p *headerOnFailPlugin) PreRequest(dbKey string, ctx map[string]any) (map[string]any, *int, error) {
	if ctx == nil {
		ctx = map[string]any{}
	}
	ctx[p.ctxKey] = p.ctxVal
	return ctx, p.failStatus, errTest("forbidden")
}

func (p *headerOnFailPlugin) PostRequest(dbKey string, ctx map[string]any) (map[string]string, error) {
	return nil, nil
}

func TestApplyContextResponseHeaders_Prefix(t *testing.T) {
	w := httptest.NewRecorder()
	applyContextResponseHeaders(w, map[string]any{
		"response.header.X-Foo": "bar",
		"method":                "GET",
	})
	if w.Header().Get("X-Foo") != "bar" {
		t.Fatalf("X-Foo: %q", w.Header().Get("X-Foo"))
	}
}

func TestApplyContextResponseHeaders_JSONStringSameName(t *testing.T) {
	w := httptest.NewRecorder()
	applyContextResponseHeaders(w, map[string]any{
		"response.headers": `[{"Cache-Control": "public"}, {"Cache-Control": "max-age=259200"}]`,
	})
	if got := w.Header().Get("Cache-Control"); got != "public, max-age=259200" {
		t.Fatalf("Cache-Control: %q", got)
	}
	if len(w.Header().Values("Cache-Control")) != 1 {
		t.Fatalf("expected one Cache-Control entry, got %#v", w.Header().Values("Cache-Control"))
	}
}

func TestApplyContextResponseHeaders_JSONStringNoCache(t *testing.T) {
	w := httptest.NewRecorder()
	applyContextResponseHeaders(w, map[string]any{
		"response.headers": `[{"Cache-Control": "no-cache"}, {"Cache-Control": "no-store"}, {"Cache-Control": "must-revalidate"}]`,
	})
	if got := w.Header().Get("Cache-Control"); got != "no-cache, no-store, must-revalidate" {
		t.Fatalf("Cache-Control: %q", got)
	}
}

func TestApplyContextResponseHeaders_DifferentNames(t *testing.T) {
	w := httptest.NewRecorder()
	applyContextResponseHeaders(w, map[string]any{
		"response.headers": `[{"X-A": "1"}, {"X-B": "2"}]`,
	})
	if w.Header().Get("X-A") != "1" || w.Header().Get("X-B") != "2" {
		t.Fatalf("headers: %#v", w.Header())
	}
}

func TestApplyContextResponseHeaders_DecodedSlice(t *testing.T) {
	w := httptest.NewRecorder()
	applyContextResponseHeaders(w, map[string]any{
		"response.headers": []any{
			map[string]any{"X-Decoded": "yes"},
		},
	})
	if w.Header().Get("X-Decoded") != "yes" {
		t.Fatalf("X-Decoded: %q", w.Header().Get("X-Decoded"))
	}
}

func TestApplyContextResponseHeaders_InvalidJSON(t *testing.T) {
	w := httptest.NewRecorder()
	applyContextResponseHeaders(w, map[string]any{
		"response.headers": "{not-json",
	})
	if len(w.Header()) != 0 {
		t.Fatalf("expected no headers, got %#v", w.Header())
	}
}

func TestApplyReturnedPluginContext(t *testing.T) {
	current := map[string]any{"a": 1}
	kept := applyReturnedPluginContext(current, nil)
	if kept["a"] != 1 {
		t.Fatalf("nil returned should keep current: %#v", kept)
	}
	current["a"] = 2
	if kept["a"] != 2 {
		t.Fatalf("nil returned should be the same map pointer")
	}

	returned := map[string]any{"b": 3}
	got := applyReturnedPluginContext(current, returned)
	if got["b"] != 3 {
		t.Fatalf("non-nil should replace: %#v", got)
	}
	if _, ok := got["a"]; ok {
		t.Fatalf("replace must not merge: %#v", got)
	}
}

func TestApplyContextResponseHeaders_NilAndEmpty(t *testing.T) {
	w := httptest.NewRecorder()
	applyContextResponseHeaders(w, nil)
	applyContextResponseHeaders(w, map[string]any{})
	applyContextResponseHeaders(w, map[string]any{
		"response.header.": "",
		"response.headers": `[{"": "skip"}]`,
	})
	if len(w.Header()) != 0 {
		t.Fatalf("expected no headers, got %#v", w.Header())
	}
}

func TestApplyContextResponseHeaders_PrefixThenArrayJoin(t *testing.T) {
	w := httptest.NewRecorder()
	applyContextResponseHeaders(w, map[string]any{
		"response.header.Cache-Control": "public",
		"response.headers":              `[{"Cache-Control": "max-age=60"}]`,
	})
	if got := w.Header().Get("Cache-Control"); got != "public, max-age=60" {
		t.Fatalf("Cache-Control: %q", got)
	}
}

func TestMiddlewareWriteHeader_ContextAfterPostRequest(t *testing.T) {
	plug := &postHeaderPlugin{headers: map[string]string{"X-MW": "plugin"}}
	dbMiddlewareOrder.Store(&map[string][]easyrest.MiddlewarePlugin{
		"test": {plug},
	})
	emptyGlobal := []easyrest.MiddlewarePlugin{}
	globalMiddlewareChain.Store(&emptyGlobal)

	w := httptest.NewRecorder()
	ctx := map[string]any{"response.header.X-From-Ctx": "ctx"}
	middlewareWriteHeader(w, "test", ctx, http.StatusNoContent)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status: %d", w.Code)
	}
	if got := w.Header().Values("X-MW"); len(got) != 1 || got[0] != "plugin" {
		t.Fatalf("plugin header: %#v", w.Header().Values("X-MW"))
	}
	if w.Header().Get("X-From-Ctx") != "ctx" {
		t.Fatalf("context header: %q", w.Header().Get("X-From-Ctx"))
	}
}

func TestStatusFromPluginContext(t *testing.T) {
	if got := statusFromPluginContext(nil, 200); got != 200 {
		t.Fatalf("nil ctx: %d", got)
	}
	if got := statusFromPluginContext(map[string]any{}, 201); got != 201 {
		t.Fatalf("missing: %d", got)
	}
	if got := statusFromPluginContext(map[string]any{"response.status": "418"}, 200); got != 418 {
		t.Fatalf("string: %d", got)
	}
	if got := statusFromPluginContext(map[string]any{"response.status": 418}, 200); got != 418 {
		t.Fatalf("int: %d", got)
	}
	if got := statusFromPluginContext(map[string]any{"response.status": float64(418)}, 200); got != 418 {
		t.Fatalf("float64: %d", got)
	}
	if got := statusFromPluginContext(map[string]any{"response.status": "nope"}, 200); got != 500 {
		t.Fatalf("invalid: %d", got)
	}
	if got := statusFromPluginContext(map[string]any{"response.status": 0}, 200); got != 500 {
		t.Fatalf("zero: %d", got)
	}
	if got := statusFromPluginContext(map[string]any{"response.status": -1}, 200); got != 500 {
		t.Fatalf("negative: %d", got)
	}
}

func TestMiddlewareMakeResponse_StatusOverride(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/test/users/", nil)
	r.Header.Set("Accept", "application/json")
	ctx := map[string]any{"response.status": "418"}
	middlewareMakeResponse(w, r, "test", ctx, http.StatusOK, []map[string]any{{"ok": true}}, nil)
	if w.Code != 418 {
		t.Fatalf("status: %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"ok"`) {
		t.Fatalf("body: %s", w.Body.String())
	}
}

func TestMiddlewareWriteHeader_StatusOverride(t *testing.T) {
	w := httptest.NewRecorder()
	ctx := map[string]any{"response.status": 200}
	middlewareWriteHeader(w, "test", ctx, http.StatusNoContent)
	if w.Code != 200 {
		t.Fatalf("status: %d", w.Code)
	}
}

func TestMiddlewareRespondJSON_HeadersAndStatus(t *testing.T) {
	w := httptest.NewRecorder()
	ctx := map[string]any{
		"response.status":  "418",
		"response.headers": `[{"X-From-Sql":"1"}]`,
	}
	middlewareRespondJSON(w, "test", ctx, http.StatusOK, map[string]any{"ok": true})
	if w.Code != 418 {
		t.Fatalf("status: %d", w.Code)
	}
	if w.Header().Get("X-From-Sql") != "1" {
		t.Fatalf("header: %#v", w.Header())
	}
}

type statusCapturePlugin struct {
	statuses []int
}

func (p *statusCapturePlugin) Init(settings map[string]any) error { return nil }

func (p *statusCapturePlugin) PreRequest(dbKey string, ctx map[string]any) (map[string]any, *int, error) {
	return ctx, nil, nil
}

func (p *statusCapturePlugin) PostRequest(dbKey string, ctx map[string]any) (map[string]string, error) {
	if v, ok := ctx[easyrest.CtxHandlerStatus].(int); ok {
		p.statuses = append(p.statuses, v)
	}
	return nil, nil
}

func TestSetHandlerStatus_VisibleInPostRequest(t *testing.T) {
	plug := &statusCapturePlugin{}
	dbMiddlewareOrder.Store(&map[string][]easyrest.MiddlewarePlugin{
		"test": {plug},
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/test/users/", nil)
	r.Header.Set("Accept", "application/json")
	ctx := map[string]any{}
	middlewareMakeResponse(w, r, "test", ctx, http.StatusOK, map[string]any{"ok": true}, nil)
	if len(plug.statuses) != 1 || plug.statuses[0] != http.StatusOK {
		t.Fatalf("success: %#v", plug.statuses)
	}

	w = httptest.NewRecorder()
	ctx = map[string]any{}
	middlewareHTTPError(w, "test", ctx, "boom", http.StatusBadRequest)
	if len(plug.statuses) != 2 || plug.statuses[1] != http.StatusBadRequest {
		t.Fatalf("error: %#v", plug.statuses)
	}

	w = httptest.NewRecorder()
	ctx = map[string]any{}
	middlewareWriteHeader(w, "test", ctx, http.StatusNoContent)
	if len(plug.statuses) != 3 || plug.statuses[2] != http.StatusNoContent {
		t.Fatalf("write header: %#v", plug.statuses)
	}

	w = httptest.NewRecorder()
	ctx = map[string]any{}
	middlewareRespondJSON(w, "test", ctx, http.StatusCreated, map[string]any{"ok": true})
	if len(plug.statuses) != 4 || plug.statuses[3] != http.StatusCreated {
		t.Fatalf("respond json: %#v", plug.statuses)
	}
}

func TestHeaderValueString(t *testing.T) {
	if headerValueString("ok") != "ok" {
		t.Fatal("string")
	}
	if headerValueString(nil) != "" {
		t.Fatal("nil")
	}
	if headerValueString(12) != "12" {
		t.Fatal("int")
	}
}

func TestParseResponseHeadersArray(t *testing.T) {
	direct := []map[string]any{{"name": "X", "value": "1"}}
	got, err := parseResponseHeadersArray(direct)
	if err != nil || len(got) != 1 || got[0]["name"] != "X" {
		t.Fatalf("direct: %#v %v", got, err)
	}
	mixed, err := parseResponseHeadersArray([]any{map[string]any{"name": "A"}, struct{ Name string }{Name: "B"}})
	if err != nil || len(mixed) != 2 {
		t.Fatalf("mixed: %#v %v", mixed, err)
	}
	fromJSON, err := parseResponseHeadersArray(`[{"name":"C","value":"3"}]`)
	if err != nil || fromJSON[0]["name"] != "C" {
		t.Fatalf("json string: %#v %v", fromJSON, err)
	}
	fromBytes, err := parseResponseHeadersArray([]byte(`[{"name":"D"}]`))
	if err != nil || fromBytes[0]["name"] != "D" {
		t.Fatalf("json bytes: %#v %v", fromBytes, err)
	}
	if _, err := parseResponseHeadersArray("not-json"); err == nil {
		t.Fatal("expected invalid json error")
	}
}

func TestHTTPStatusCode(t *testing.T) {
	if code, ok := httpStatusCode(201); !ok || code != 201 {
		t.Fatal("int")
	}
	if code, ok := httpStatusCode(int64(204)); !ok || code != 204 {
		t.Fatal("int64")
	}
	if _, ok := httpStatusCode(200.5); ok {
		t.Fatal("fractional float")
	}
	if code, ok := httpStatusCode(200.0); !ok || code != 200 {
		t.Fatal("float")
	}
	if _, ok := httpStatusCode("99"); ok {
		t.Fatal("out of range")
	}
	if code, ok := httpStatusCode("404"); !ok || code != 404 {
		t.Fatal("string")
	}
	if _, ok := httpStatusCode(true); ok {
		t.Fatal("bool")
	}
	if code, ok := httpStatusCode(json.Number("201")); !ok || code != 201 {
		t.Fatal("json number")
	}
	if _, ok := httpStatusCode(json.Number("2.5")); ok {
		t.Fatal("json fractional")
	}
	if _, ok := httpStatusCode("nope"); ok {
		t.Fatal("bad string")
	}
	if statusFromPluginContext(nil, 200) != 200 {
		t.Fatal("nil ctx fallback")
	}
	if statusFromPluginContext(map[string]any{}, 200) != 200 {
		t.Fatal("missing status")
	}
	if statusFromPluginContext(map[string]any{"response.status": "nope"}, 200) != http.StatusInternalServerError {
		t.Fatal("invalid status")
	}
	if _, err := parseResponseHeadersArray(12); err == nil {
		t.Fatal("expected unmarshal error for scalar")
	}
}
