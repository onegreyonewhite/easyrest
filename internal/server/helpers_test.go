package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

type fakeDBPlugin struct {
	initErr error
}

func (f *fakeDBPlugin) InitConnection(uri string) error { return f.initErr }
func (f *fakeDBPlugin) TableGet(string, string, []string, map[string]any, []string, []string, int, int, map[string]any) ([]map[string]any, map[string]any, error) {
	return nil, nil, nil
}
func (f *fakeDBPlugin) TableCreate(string, string, []map[string]any, map[string]any) ([]map[string]any, map[string]any, error) {
	return nil, nil, nil
}
func (f *fakeDBPlugin) TableUpdate(string, string, map[string]any, map[string]any, map[string]any) (int, map[string]any, error) {
	return 0, nil, nil
}
func (f *fakeDBPlugin) TableDelete(string, string, map[string]any, map[string]any) (int, map[string]any, error) {
	return 0, nil, nil
}
func (f *fakeDBPlugin) CallFunction(string, string, map[string]any, map[string]any) (any, map[string]any, error) {
	return nil, nil, nil
}
func (f *fakeDBPlugin) GetSchema(map[string]any) (any, map[string]any, error) {
	return map[string]any{"tables": map[string]any{}}, nil, nil
}
func (f *fakeDBPlugin) Close() {}

type fakeQueryPlugin struct {
	initErr error
}

func (f *fakeQueryPlugin) InitConnection(string) error { return f.initErr }
func (f *fakeQueryPlugin) QueryCall(string, map[string]any) ([]map[string]any, error) {
	return nil, nil
}

type fakeAuthPlugin struct{}

func (f *fakeAuthPlugin) Init(map[string]any) (map[string]any, error) {
	return map[string]any{"type": "apiKey"}, nil
}
func (f *fakeAuthPlugin) Authenticate(map[string]string, string, string, string) (map[string]any, error) {
	return map[string]any{"sub": "u"}, nil
}

type failAuthPlugin struct{}

func (f *failAuthPlugin) Init(map[string]any) (map[string]any, error) {
	return nil, errors.New("auth init failed")
}
func (f *failAuthPlugin) Authenticate(map[string]string, string, string, string) (map[string]any, error) {
	return nil, nil
}

type fakeMWPlugin struct{ initErr error }

func (f *fakeMWPlugin) Init(map[string]any) error { return f.initErr }
func (f *fakeMWPlugin) PreRequest(string, map[string]any) (map[string]any, *int, error) {
	return map[string]any{}, nil, nil
}
func (f *fakeMWPlugin) PostRequest(string, map[string]any) (map[string]string, error) {
	return nil, nil
}

type fakeRPC struct {
	raw any
	err error
}

func (f fakeRPC) Close() error                         { return nil }
func (f fakeRPC) Ping() error                          { return nil }
func (f fakeRPC) Dispense(string) (interface{}, error) { return f.raw, f.err }

func TestProcessSelectAndWhere(t *testing.T) {
	fields, group, err := processSelectParam("", nil, nil)
	if err != nil || fields != nil || group != nil {
		t.Fatalf("empty: %v %#v %#v", err, fields, group)
	}
	fields, group, err = processSelectParam("id", nil, nil)
	if err != nil || len(fields) != 1 || fields[0] != "id" || len(group) != 1 || group[0] != "id" {
		t.Fatalf("single identifier: %v %#v %#v", err, fields, group)
	}
	fields, group, err = processSelectParam("id, name:alias, amount.sum(), count(), erctx.claims_sub", map[string]string{"claims_sub": "u1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(fields, "|")
	if !strings.Contains(joined, "id") || !strings.Contains(joined, "SUM(amount)") || !strings.Contains(joined, "COUNT(*)") {
		t.Fatalf("fields: %v", fields)
	}
	if len(group) == 0 {
		t.Fatal("expected group by raw fields")
	}
	if _, _, err := processSelectParam("bad;field", nil, nil); err == nil {
		t.Fatal("invalid field")
	}
	if _, _, err := processSelectParam("id.notafunc()", nil, nil); err == nil {
		t.Fatal("disallowed function")
	}
	if _, _, err := processSelectParam("id.()", nil, nil); err == nil {
		t.Fatal("invalid function syntax")
	}
	if _, _, err := processSelectParam(" , id, ", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := processSelectParam("bad-alias:amount.sum()", nil, nil); err == nil {
		t.Fatal("invalid function alias")
	}
	if _, _, err := processSelectParam("bad-alias:erctx.claims_sub", map[string]string{"claims_sub": "u"}, nil); err == nil {
		t.Fatal("invalid context alias")
	}
	if _, _, err := processSelectParam("bad-alias:id", nil, nil); err == nil {
		t.Fatal("invalid field alias")
	}
	if _, err := ParseWhereClause(map[string][]string{"where.eq.bad;id": {"1"}}, nil, nil); err == nil {
		t.Fatal("invalid where field")
	}
	fields, _, err = processSelectParam("total:count()", nil, nil)
	if err != nil || len(fields) != 1 || !strings.Contains(fields[0], "COUNT(*)") {
		t.Fatalf("count alias: %v %v", fields, err)
	}
	w := httptest.NewRecorder()
	healthHandler(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if w.Code != http.StatusOK || w.Body.String() != "OK" {
		t.Fatalf("health: %d %q", w.Code, w.Body.String())
	}

	where, err := ParseWhereClause(map[string][]string{
		"where.eq.id":      {"1"},
		"where.eq.name":    {"alice"},
		"where.gte.age":    {"18"},
		"where.in.tag":     {"a,b"},
		"where.ilike.note": {"%x%"},
		"where.not.eq.id":  {"2"},
		"other":            {"skip"},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if where["id"] == nil || where["name"] == nil || where["NOT id"] == nil {
		t.Fatalf("where: %#v", where)
	}
	if _, err := ParseWhereClause(map[string][]string{"where.id": {"1"}}, nil, nil); err == nil {
		t.Fatal("expected invalid where key")
	}
	if _, err := ParseWhereClause(map[string][]string{"where.nope.id": {"1"}}, nil, nil); err == nil {
		t.Fatal("expected unknown operator")
	}
}

func TestCheckScope(t *testing.T) {
	if CheckScope(nil, "users.read") {
		t.Fatal("nil claims")
	}
	if CheckScope(jwt.MapClaims{"scope": 1}, "users.read") {
		t.Fatal("non-string scope")
	}
	if !CheckScope(jwt.MapClaims{"scope": "users.read other"}, "users.read") {
		t.Fatal("exact")
	}
	if !CheckScope(jwt.MapClaims{"scope": "read"}, "users.read") {
		t.Fatal("generic read")
	}
	if !CheckScope(jwt.MapClaims{"scope": "write"}, "users.write") {
		t.Fatal("generic write")
	}
	if CheckScope(jwt.MapClaims{"scope": "other"}, "users.read") {
		t.Fatal("mismatch")
	}
}

func TestExtractUserIDFromClaims(t *testing.T) {
	if extractUserIDFromClaims(jwt.MapClaims{"sub": "abc"}, "sub") != "abc" {
		t.Fatal("string")
	}
	if extractUserIDFromClaims(jwt.MapClaims{"sub": 1.0}, "sub") != "1" {
		t.Fatal("float")
	}
	if extractUserIDFromClaims(jwt.MapClaims{"sub": true}, "sub") != "true" {
		t.Fatal("other")
	}
	if extractUserIDFromClaims(jwt.MapClaims{}, "sub") != "" {
		t.Fatal("missing")
	}
}

func TestGetNestedValueAndSubstitute(t *testing.T) {
	data := map[string]any{"a": map[string]any{"b": 3}}
	if _, ok := getNestedValue(data, "a.missing"); ok {
		t.Fatal("missing")
	}
	if _, ok := getNestedValue(data, "a.b.c"); ok {
		t.Fatal("non-map intermediate")
	}
	got, ok := getNestedValue(data, "a.b")
	if !ok || got != 3 {
		t.Fatalf("nested: %#v %v", got, ok)
	}
	flat := map[string]string{"claims_sub": "u1"}
	pluginCtx := map[string]any{"id": 9, "ok": true, "nested": map[string]any{"x": 1}}
	if substitutePluginContext("erctx.claims_sub", flat, pluginCtx) != "u1" {
		t.Fatal("erctx")
	}
	if substitutePluginContext("request.id", flat, pluginCtx) != "9" {
		t.Fatal("request int")
	}
	if substitutePluginContext("request.ok", flat, pluginCtx) != "true" {
		t.Fatal("request bool")
	}
	if substitutePluginContext("request.nested", flat, pluginCtx) != `{"x":1}` {
		t.Fatal("request map")
	}
	if substitutePluginContext("request.missing", flat, pluginCtx) != "request.missing" {
		t.Fatal("missing request")
	}
	out := substituteValue(map[string]any{"n": "erctx.claims_sub"}, flat, pluginCtx).(map[string]any)
	if out["n"] != "u1" {
		t.Fatalf("subst map: %#v", out)
	}
	arr := substituteValue([]any{"request.id", 1}, flat, pluginCtx).([]any)
	if arr[0] != "9" {
		t.Fatalf("subst slice: %#v", arr)
	}
}

func TestContextSubstNeeds(t *testing.T) {
	if queryNeedsContextSubst(map[string][]string{"select": {"id"}, "where.eq.name": {"Alice"}}) {
		t.Fatal("plain query values must not need flattening")
	}
	if !queryNeedsContextSubst(map[string][]string{"select": {"erctx.claims_sub"}}) {
		t.Fatal("erctx in query values must need flattening")
	}
	if !queryNeedsContextSubst(map[string][]string{"where.eq.name": {"request.claims.sub"}}) {
		t.Fatal("request. in query values must need flattening")
	}
	if valueNeedsContextSubst(map[string]any{"name": "Alice"}) {
		t.Fatal("plain body must not need flattening")
	}
	if !valueNeedsContextSubst(map[string]any{"name": "erctx.claims_sub"}) {
		t.Fatal("erctx in body must need flattening")
	}
	if !valueNeedsContextSubst([]map[string]any{{"nested": "request.claims.sub"}}) {
		t.Fatal("request. in row body must need flattening")
	}
}

func TestAuthPluginOrderSnapshotNil(t *testing.T) {
	prev := authPluginOrder.Load()
	authPluginOrder.Store(nil)
	t.Cleanup(func() { authPluginOrder.Store(prev) })
	order := authPluginOrderSnapshot()
	if order == nil {
		t.Fatal("expected fallback order")
	}
}

func TestLoadPluginsPreserved(t *testing.T) {
	origDB := PreservedDbPlugins
	origQuery := PreservedQueryPlugins
	origAuth := PreservedAuthPlugins
	origMW := PreservedMiddlewarePlugins
	origCfg := GetConfig()
	t.Cleanup(func() {
		PreservedDbPlugins = origDB
		PreservedQueryPlugins = origQuery
		PreservedAuthPlugins = origAuth
		PreservedMiddlewarePlugins = origMW
		SetConfig(origCfg)
		StopPlugins()
	})
	PreservedDbPlugins = map[string]PreservedPluginFactory[easyrest.DBPlugin]{
		"sqlite": func() easyrest.DBPlugin { return &fakeDBPlugin{} },
		"fail":   func() easyrest.DBPlugin { return &fakeDBPlugin{initErr: errors.New("db init")} },
	}
	PreservedQueryPlugins = map[string]PreservedPluginFactory[easyrest.DBQueryPlugin]{
		"sqlite": func() easyrest.DBQueryPlugin { return &fakeQueryPlugin{} },
	}
	PreservedAuthPlugins = map[string]PreservedPluginFactory[easyrest.AuthPlugin]{
		"jwt": func() easyrest.AuthPlugin { return &fakeAuthPlugin{} },
		"bad": func() easyrest.AuthPlugin { return &failAuthPlugin{} },
	}
	PreservedMiddlewarePlugins = map[string]PreservedPluginFactory[easyrest.MiddlewarePlugin]{
		"cache-lru": func() easyrest.MiddlewarePlugin { return &fakeMWPlugin{} },
		"broken":    func() easyrest.MiddlewarePlugin { return &fakeMWPlugin{initErr: errors.New("mw init")} },
	}

	SetConfig(config.Config{
		PluginMap: map[string]config.PluginConfig{
			"app":   {Uri: "sqlite:///tmp/x.db"},
			"query": {Uri: "sqlite:///tmp/q.db", UseQuery: true},
			"bad":   {Uri: "not-a-uri"},
			"fail":  {Uri: "fail:///tmp/x.db"},
		},
		AuthPlugins: map[string]config.AuthConfig{
			"jwt": {Settings: map[string]any{}},
			"bad": {Settings: map[string]any{}},
		},
		MiddlewarePlugins: map[string]config.MiddlewareConfig{
			"cache-lru": {},
			"broken":    {},
			"missing":   {},
		},
	})
	LoadPlugins()
	if _, ok := (*DbPlugins.Load())["app"]; !ok {
		t.Fatal("expected preserved db plugin")
	}
	if _, ok := (*QueryPlugins.Load())["query"]; !ok {
		t.Fatal("expected preserved query plugin")
	}
	if _, ok := (*AuthPlugins.Load())["jwt"]; !ok {
		t.Fatal("expected preserved auth plugin")
	}
	if _, ok := (*AuthPlugins.Load())["bad"]; ok {
		t.Fatal("failed auth init should not be stored")
	}
	if _, ok := (*MiddlewarePlugins.Load())["cache-lru"]; !ok {
		t.Fatal("expected preserved middleware")
	}
	if _, ok := (*MiddlewarePlugins.Load())["broken"]; ok {
		t.Fatal("failed middleware init should not be stored")
	}
}

func TestDispenseConnection(t *testing.T) {
	got, ok := dispenseConnection[easyrest.DBPlugin](fakeRPC{raw: &fakeDBPlugin{}}, "db", "sqlite://x", "c", "/p", "DB")
	if !ok || got == nil {
		t.Fatal("success")
	}
	if _, ok := dispenseConnection[easyrest.DBPlugin](fakeRPC{err: errors.New("unknown service")}, "db", "sqlite://x", "c", "/p", "DB"); ok {
		t.Fatal("unknown service")
	}
	if _, ok := dispenseConnection[easyrest.DBPlugin](fakeRPC{err: errors.New("dispense boom")}, "db", "sqlite://x", "c", "/p", "DB"); ok {
		t.Fatal("dispense error")
	}
	if _, ok := dispenseConnection[easyrest.DBPlugin](fakeRPC{raw: "not-a-plugin"}, "db", "sqlite://x", "c", "/p", "DB"); ok {
		t.Fatal("type assertion")
	}
	if _, ok := dispenseConnection[easyrest.DBPlugin](fakeRPC{raw: &fakeDBPlugin{initErr: errors.New("init")}}, "db", "sqlite://x", "c", "/p", "DB"); ok {
		t.Fatal("init error")
	}
}

func TestParseRequestAndMakeResponse(t *testing.T) {
	orig := GetConfig()
	t.Cleanup(func() { SetConfig(orig) })
	SetConfig(config.Config{Server: config.ServerConfig{MaxBodySize: 1 << 20}})

	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("name,age\na,1\n"))
	r.Header.Set("Content-Type", "text/csv")
	got, err := parseRequest(httptest.NewRecorder(), r, true)
	if err != nil {
		t.Fatal(err)
	}
	rows, ok := got.([]map[string]any)
	if !ok || len(rows) != 1 || rows[0]["name"] != "a" {
		t.Fatalf("csv: %#v", got)
	}

	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("name\nonly\n"))
	r.Header.Set("Content-Type", "text/csv")
	single, err := parseRequest(httptest.NewRecorder(), r, false)
	if err != nil {
		t.Fatal(err)
	}
	if obj, ok := single.(map[string]any); !ok || obj["name"] != "only" {
		t.Fatalf("csv single: %#v", single)
	}

	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("<items></items>"))
	r.Header.Set("Content-Type", "application/xml")
	if _, err := parseRequest(httptest.NewRecorder(), r, true); err != nil {
		t.Fatalf("xml array: %v", err)
	}

	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("not-xml"))
	r.Header.Set("Content-Type", "application/xml")
	if _, err := parseRequest(httptest.NewRecorder(), r, false); err == nil {
		t.Fatal("expected xml parse error")
	}

	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("a=1&b=2"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	form, err := parseRequest(httptest.NewRecorder(), r, false)
	if err != nil {
		t.Fatal(err)
	}
	if obj, ok := form.(map[string]any); !ok || obj["a"] != "1" {
		t.Fatalf("form: %#v", form)
	}

	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"a":1}`))
	r.Header.Set("Content-Type", "application/json")
	if _, err := parseRequest(httptest.NewRecorder(), r, false); err != nil {
		t.Fatal(err)
	}

	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("too-big"))
	SetConfig(config.Config{Server: config.ServerConfig{MaxBodySize: 2}})
	r.Header.Set("Content-Type", "application/json")
	if _, err := parseRequest(httptest.NewRecorder(), r, false); err == nil {
		t.Fatal("expected oversize error")
	}
	SetConfig(config.Config{Server: config.ServerConfig{MaxBodySize: 1 << 20}})

	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("x"))
	r.Header.Set("Content-Type", "text/plain")
	if _, err := parseRequest(httptest.NewRecorder(), r, false); err == nil {
		t.Fatal("expected unsupported content type")
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/?format=csv", nil)
	makeResponseWithQuery(w, req, http.StatusOK, map[string]any{"a": 1}, nil)
	if !strings.Contains(w.Header().Get("Content-Type"), "csv") {
		t.Fatalf("nil query URL format csv: %s", w.Header().Get("Content-Type"))
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/?format=csv", nil)
	makeResponseWithQuery(w, req, http.StatusOK, map[string]any{"a": 1}, url.Values{})
	if !strings.Contains(w.Header().Get("Content-Type"), "json") {
		t.Fatalf("empty query must not fall back to URL format: %s", w.Header().Get("Content-Type"))
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/?format=csv", nil)
	makeResponseWithQuery(w, req, http.StatusOK, map[string]any{"a": 1}, req.URL.Query())
	if !strings.Contains(w.Header().Get("Content-Type"), "csv") {
		t.Fatalf("csv content type: %s", w.Header().Get("Content-Type"))
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/?format=csv", nil)
	makeResponseWithQuery(w, req, http.StatusOK, []map[string]any{{"a": 1}}, req.URL.Query())
	if !strings.Contains(w.Body.String(), "a") {
		t.Fatalf("csv array body: %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/?format=xml", nil)
	makeResponseWithQuery(w, req, http.StatusOK, map[string]any{"a": 1}, req.URL.Query())
	if !strings.Contains(w.Body.String(), "<item>") {
		t.Fatalf("xml body: %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/?format=xml", nil)
	makeResponseWithQuery(w, req, http.StatusOK, []map[string]any{{"a": 1}}, req.URL.Query())
	if !strings.Contains(w.Body.String(), "<items>") {
		t.Fatalf("xml array body: %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/x-www-form-urlencoded")
	makeResponseWithQuery(w, req, http.StatusOK, map[string]any{"a": "b"}, url.Values{})
	if w.Body.String() != "a=b" {
		t.Fatalf("form: %q", w.Body.String())
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/?format=unknown", nil)
	makeResponseWithQuery(w, req, http.StatusOK, map[string]any{"a": 1}, req.URL.Query())
	if !strings.Contains(w.Header().Get("Content-Type"), "json") {
		t.Fatalf("unknown format fallback: %s", w.Header().Get("Content-Type"))
	}
}

func TestProxyHeadersAndSpanName(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Scheme != "https" || r.Host != "example.test" {
			t.Errorf("proxy rewrite: scheme=%s host=%s", r.URL.Scheme, r.Host)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	h := proxyHeadersHandler(inner)
	r := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "example.test")
	h.ServeHTTP(httptest.NewRecorder(), r)

	r = httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	r.Header.Set("X-Forwarded-Protocol", "https")
	proxyHeadersHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Scheme != "https" {
			t.Errorf("protocol header: %s", r.URL.Scheme)
		}
	})).ServeHTTP(httptest.NewRecorder(), r)

	rctx := chi.NewRouteContext()
	rctx.RoutePatterns = []string{"/api/{db}/{table}"}
	r = httptest.NewRequest(http.MethodGet, "/api/x/y", nil)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	spanNameMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(httptest.NewRecorder(), r)

	spanNameMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

func TestRespondJSONHTMLEscape(t *testing.T) {
	orig := GetConfig()
	t.Cleanup(func() { SetConfig(orig) })

	payload := map[string]any{"x": "<a>&"}

	SetConfig(config.Config{Server: config.ServerConfig{DisableHTMLEscape: false}})
	escaped := httptest.NewRecorder()
	respondJSON(escaped, http.StatusOK, payload)
	body := escaped.Body.String()
	if !strings.Contains(body, `\u003c`) || !strings.Contains(body, `\u0026`) {
		t.Fatalf("expected HTML-escaped JSON, got %q", body)
	}

	SetConfig(config.Config{Server: config.ServerConfig{DisableHTMLEscape: true}})
	raw := httptest.NewRecorder()
	respondJSON(raw, http.StatusOK, payload)
	body = raw.Body.String()
	if strings.Contains(body, `\u003c`) || strings.Contains(body, `\u0026`) {
		t.Fatalf("expected unescaped JSON, got %q", body)
	}
	if !strings.Contains(body, `<a>&`) {
		t.Fatalf("expected raw <>& in JSON, got %q", body)
	}
}
