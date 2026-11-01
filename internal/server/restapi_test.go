package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	lrustore "github.com/onegreyonewhite/easyrest/plugins/data/lru"
	cachemw "github.com/onegreyonewhite/easyrest/plugins/middleware/cache"
)

type restRecPlugin struct {
	fakeDBPlugin
	rows        []map[string]any
	created     []map[string]any
	updated     int
	getTable    string
	getWhere    map[string]any
	createTable string
	createData  []map[string]any
	updateWhere map[string]any
	updateData  map[string]any
	updateTable string
	deleteWhere map[string]any
	schemaCalls int
	schema      any
	funcName    string
	funcData    map[string]any
	funcResult  any
	creates     int
	updateCalls int
	deleteCalls int
	getErr      error
	getLimit    int
	getOffset   int
	getSelect   []string
	getOrder    []string
	getCalls    int
	getUser     string
	getCtx      map[string]any
	createCtx   map[string]any
	updateCtx   map[string]any
	deleteCtx   map[string]any
	funcCtx     map[string]any
	returned    map[string]any
	callErr     error
}

func (p *restRecPlugin) TableGet(userID string, table string, selectFields []string, where map[string]any, ordering []string, _ []string, limit, offset int, ctx map[string]any) ([]map[string]any, map[string]any, error) {
	p.getCalls++
	p.getUser = userID
	p.getCtx = ctx
	p.getTable = table
	p.getWhere = where
	p.getLimit = limit
	p.getOffset = offset
	p.getSelect = selectFields
	p.getOrder = ordering
	if p.getErr != nil {
		return nil, p.returned, p.getErr
	}
	return p.rows, p.returned, nil
}

func (p *restRecPlugin) TableCreate(_ string, table string, data []map[string]any, ctx map[string]any) ([]map[string]any, map[string]any, error) {
	p.creates++
	p.createTable = table
	p.createData = data
	p.createCtx = ctx
	if p.callErr != nil {
		return nil, p.returned, p.callErr
	}
	if p.created != nil {
		return p.created, p.returned, nil
	}
	return data, p.returned, nil
}

func (p *restRecPlugin) TableUpdate(_ string, table string, data map[string]any, where map[string]any, ctx map[string]any) (int, map[string]any, error) {
	p.updateCalls++
	p.updateTable = table
	p.updateData = data
	p.updateWhere = where
	p.updateCtx = ctx
	if p.callErr != nil {
		return 0, p.returned, p.callErr
	}
	return p.updated, p.returned, nil
}

func (p *restRecPlugin) TableDelete(_ string, _ string, where map[string]any, ctx map[string]any) (int, map[string]any, error) {
	p.deleteCalls++
	p.deleteWhere = where
	p.deleteCtx = ctx
	if p.callErr != nil {
		return 0, p.returned, p.callErr
	}
	return 1, p.returned, nil
}

func (p *restRecPlugin) CallFunction(_ string, name string, data map[string]any, ctx map[string]any) (any, map[string]any, error) {
	p.funcName = name
	p.funcData = data
	p.funcCtx = ctx
	if p.callErr != nil {
		return nil, p.returned, p.callErr
	}
	if p.funcResult != nil {
		return p.funcResult, p.returned, nil
	}
	return data, p.returned, nil
}

func (p *restRecPlugin) GetSchema(map[string]any) (any, map[string]any, error) {
	p.schemaCalls++
	if p.schema != nil {
		return p.schema, nil, nil
	}
	return map[string]any{"tables": map[string]any{}, "views": map[string]any{}, "rpc": map[string]any{}}, nil, nil
}

func serveRest(t *testing.T, cfg config.Config, plugins map[string]easyrest.DBPlugin) http.Handler {
	t.Helper()
	origCfg := GetConfig()
	origDB := DbPlugins.Load()
	t.Cleanup(func() {
		SetConfig(origCfg)
		DbPlugins.Store(origDB)
	})
	if cfg.AnonClaims == nil {
		cfg.AnonClaims = map[string]any{"sub": "tester", "scope": "read write"}
	}
	SetConfig(cfg)
	DbPlugins.Store(&plugins)
	chi.RegisterMethod("QUERY")
	r := chi.NewRouter()
	mountRestAPI(r)
	publishRestAPI()
	return r
}

func restUsersConfig() config.Config {
	return config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {},
				},
			},
		},
	}
}

func TestRestAPI_SecurityDefinitions(t *testing.T) {
	prev := AuthSecurityDefinitions.Load()
	t.Cleanup(func() { AuthSecurityDefinitions.Store(prev) })
	defs := map[string]map[string]any{
		"jwt":   {"type": "apiKey"},
		"basic": {"type": "basic"},
	}
	AuthSecurityDefinitions.Store(&defs)

	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users":  {},
					"status": {Public: true},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/restapi/v1/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var spec map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	secDefs, _ := spec["securityDefinitions"].(map[string]any)
	if secDefs["jwt"] == nil || secDefs["basic"] == nil {
		t.Fatalf("securityDefinitions %#v", spec["securityDefinitions"])
	}
	paths, _ := spec["paths"].(map[string]any)
	users, _ := paths["/users/"].(map[string]any)
	list, _ := users["get"].(map[string]any)
	if !restSecurityHas(list["security"], "jwt", "basic") {
		t.Fatalf("users security %#v", list["security"])
	}
	status, _ := paths["/status/"].(map[string]any)
	statusGet, _ := status["get"].(map[string]any)
	got, _ := statusGet["security"].([]any)
	if len(got) != 0 {
		t.Fatalf("public security %#v", statusGet["security"])
	}
}

func TestRestAPI_OperationAuthSecurity(t *testing.T) {
	prev := AuthSecurityDefinitions.Load()
	t.Cleanup(func() { AuthSecurityDefinitions.Store(prev) })
	defs := map[string]map[string]any{
		"jwt":   {"type": "apiKey"},
		"oauth": {"type": "oauth2"},
		"basic": {"type": "basic"},
	}
	AuthSecurityDefinitions.Store(&defs)

	listed := []string{"oauth", "jwt"}
	jwtOnly := []string{"jwt"}
	none := []string{}
	cfg := config.Config{
		CheckScope: true,
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Auth:   &listed,
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						RequiredScopes: []string{"orders-read", "admin"},
						Actions: map[string]config.RestAction{
							"list":   {},
							"create": {RequiredScopes: []string{"orders-write"}},
						},
					},
					"orders":  {},
					"notes":   {Auth: &none},
					"secrets": {Auth: &jwtOnly},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	spec := restSpec(t, router, "/restapi/v1/")
	secDefs, _ := spec["securityDefinitions"].(map[string]any)
	if _, ok := secDefs["basic"]; ok || secDefs["oauth"] == nil || secDefs["jwt"] == nil {
		t.Fatalf("securityDefinitions %#v", secDefs)
	}
	paths, _ := spec["paths"].(map[string]any)
	users, _ := paths["/users/"].(map[string]any)
	listScopes, ok := restSecurityScopes(users["get"].(map[string]any)["security"], "oauth")
	if !ok || !slices.Equal(listScopes, []string{"orders-read", "admin"}) {
		t.Fatalf("list oauth scopes %#v", users["get"])
	}
	jwtScopes, ok := restSecurityScopes(users["get"].(map[string]any)["security"], "jwt")
	if !ok || len(jwtScopes) != 0 {
		t.Fatalf("list jwt scopes %#v", users["get"])
	}
	createScopes, ok := restSecurityScopes(users["post"].(map[string]any)["security"], "oauth")
	if !ok || !slices.Equal(createScopes, []string{"orders-write"}) {
		t.Fatalf("create oauth scopes %#v", users["post"])
	}
	orders, _ := paths["/orders/"].(map[string]any)
	orderScopes, ok := restSecurityScopes(orders["get"].(map[string]any)["security"], "oauth")
	if !ok || !slices.Equal(orderScopes, []string{"orders-read"}) {
		t.Fatalf("standard oauth scopes %#v", orders["get"])
	}
	notes, _ := paths["/notes/"].(map[string]any)
	noteSec, _ := notes["get"].(map[string]any)["security"].([]any)
	if len(noteSec) != 0 {
		t.Fatalf("empty auth security %#v", notes["get"])
	}
	secrets, _ := paths["/secrets/"].(map[string]any)
	if _, ok := restSecurityScopes(secrets["get"].(map[string]any)["security"], "oauth"); ok {
		t.Fatalf("endpoint auth security %#v", secrets["get"])
	}
	if _, ok := restSecurityScopes(secrets["get"].(map[string]any)["security"], "jwt"); !ok {
		t.Fatalf("endpoint jwt security %#v", secrets["get"])
	}

	cfg.CheckScope = false
	unchecked := restSpec(t, serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}}), "/restapi/v1/")
	uncheckedPaths, _ := unchecked["paths"].(map[string]any)
	uncheckedUsers, _ := uncheckedPaths["/users/"].(map[string]any)
	uncheckedScopes, ok := restSecurityScopes(uncheckedUsers["get"].(map[string]any)["security"], "oauth")
	if !ok || len(uncheckedScopes) != 0 {
		t.Fatalf("unchecked oauth scopes %#v", uncheckedUsers["get"])
	}
}

func restSecurityHas(raw any, keys ...string) bool {
	items, _ := raw.([]any)
	found := map[string]bool{}
	for _, item := range items {
		obj, _ := item.(map[string]any)
		for key := range obj {
			found[key] = true
		}
	}
	for _, key := range keys {
		if !found[key] {
			return false
		}
	}
	return len(found) == len(keys)
}

func restSpec(t *testing.T, router http.Handler, path string) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var spec map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	return spec
}

func restSecurityScopes(raw any, name string) ([]string, bool) {
	items, _ := raw.([]any)
	for _, item := range items {
		obj, _ := item.(map[string]any)
		scopes, ok := obj[name]
		if !ok {
			continue
		}
		arr, _ := scopes.([]any)
		out := make([]string, 0, len(arr))
		for _, v := range arr {
			s, _ := v.(string)
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

func TestRestAPI_InternalSource(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1), "name": "ada"}}}
	cfg := restUsersConfig()
	cfg.PluginMap = map[string]config.PluginConfig{
		"db": {Uri: "sqlite://memory", Internal: true},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	req := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if plugin.getCalls != 1 {
		t.Fatalf("TableGet calls = %d, want 1", plugin.getCalls)
	}
}

func TestApplicationYAMLServesRestPath(t *testing.T) {
	cfg, err := config.Load(nil, `
plugins:
  db:
    uri: sqlite://memory
anon_claims:
  sub: tester
  scope: read write
application:
  source: db
  public: true
  api:
    v1:
      endpoints:
        users: {}
`)
	if err != nil {
		t.Fatal(err)
	}
	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1), "name": "ada"}}}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "ada") {
		t.Fatalf("body %q", w.Body.String())
	}
}

func TestRestAPI_NoTrailingSlashEndpoint(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1), "name": "ada"}}}
	cfg := restUsersConfig()
	ep := cfg.RestAPI["v1"].Endpoints["users"]
	ep.NoTrailingSlash = true
	cfg.RestAPI["v1"].Endpoints["users"] = ep
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	ok := httptest.NewRecorder()
	router.ServeHTTP(ok, httptest.NewRequest(http.MethodGet, "/restapi/v1/users", nil))
	if ok.Code != http.StatusOK {
		t.Fatalf("list without slash: status %d body %q", ok.Code, ok.Body.String())
	}
	slash := httptest.NewRecorder()
	router.ServeHTTP(slash, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if slash.Code != http.StatusNotFound {
		t.Fatalf("list with slash: status %d body %q", slash.Code, slash.Body.String())
	}
	one := httptest.NewRecorder()
	router.ServeHTTP(one, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/1", nil))
	if one.Code != http.StatusOK {
		t.Fatalf("detail without slash: status %d body %q", one.Code, one.Body.String())
	}

	specW := httptest.NewRecorder()
	router.ServeHTTP(specW, httptest.NewRequest(http.MethodGet, "/restapi/v1/?format=json", nil))
	var spec map[string]any
	if err := json.Unmarshal(specW.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths, _ := spec["paths"].(map[string]any)
	if _, ok := paths["/users"]; !ok {
		t.Fatalf("spec paths %#v", paths)
	}
	if _, ok := paths["/users/"]; ok {
		t.Fatalf("slashed spec path still present %#v", paths)
	}

	plain := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})
	kept := httptest.NewRecorder()
	plain.ServeHTTP(kept, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if kept.Code != http.StatusOK {
		t.Fatalf("default list: status %d body %q", kept.Code, kept.Body.String())
	}
	bare := httptest.NewRecorder()
	plain.ServeHTTP(bare, httptest.NewRequest(http.MethodGet, "/restapi/v1/users", nil))
	if bare.Code != http.StatusNotFound {
		t.Fatalf("default list without slash: status %d", bare.Code)
	}
}

func TestRestAPI_AppAuthList(t *testing.T) {
	plugins := map[string]easyrest.AuthPlugin{
		"jwt":   namedAuthPlugin{name: "jwt"},
		"basic": namedAuthPlugin{name: "basic"},
	}
	prev := AuthPlugins.Load()
	prevOrder := authPluginOrder.Load()
	t.Cleanup(func() {
		AuthPlugins.Store(prev)
		authPluginOrder.Store(prevOrder)
	})
	AuthPlugins.Store(&plugins)
	setAuthPluginOrder(plugins)

	basic := []string{"basic"}
	cfg := restUsersConfig()
	cfg.TokenUserSearch = "sub"
	app := cfg.RestAPI["v1"]
	app.Auth = &basic
	cfg.RestAPI["v1"] = app
	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if plugin.getUser != "basic" {
		t.Fatalf("user %q, want the listed auth plugin", plugin.getUser)
	}
}

func TestRestAPI_EmptyAuthSkipsPlugins(t *testing.T) {
	plugins := map[string]easyrest.AuthPlugin{
		"jwt":   namedAuthPlugin{name: "jwt"},
		"basic": namedAuthPlugin{name: "basic"},
	}
	prev := AuthPlugins.Load()
	prevOrder := authPluginOrder.Load()
	t.Cleanup(func() {
		AuthPlugins.Store(prev)
		authPluginOrder.Store(prevOrder)
	})
	AuthPlugins.Store(&plugins)
	setAuthPluginOrder(plugins)

	all := restUsersConfig()
	all.TokenUserSearch = "sub"
	allPlugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}
	allRouter := serveRest(t, all, map[string]easyrest.DBPlugin{"db": allPlugin})
	allW := httptest.NewRecorder()
	allRouter.ServeHTTP(allW, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if allW.Code != http.StatusOK || allPlugin.getUser != "jwt" {
		t.Fatalf("nil auth status %d user %q", allW.Code, allPlugin.getUser)
	}

	none := []string{}
	withAnon := restUsersConfig()
	withAnon.TokenUserSearch = "sub"
	withAnon.AnonClaims = map[string]any{}
	app := withAnon.RestAPI["v1"]
	app.Auth = &none
	app.AnonClaims = map[string]any{"sub": "anon-user", "scope": "read write"}
	withAnon.RestAPI["v1"] = app
	anonPlugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}
	anonRouter := serveRest(t, withAnon, map[string]easyrest.DBPlugin{"db": anonPlugin})
	anonW := httptest.NewRecorder()
	anonRouter.ServeHTTP(anonW, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if anonW.Code != http.StatusOK || anonPlugin.getUser != "anon-user" {
		t.Fatalf("empty auth status %d user %q body %q", anonW.Code, anonPlugin.getUser, anonW.Body.String())
	}

	open := restUsersConfig()
	open.TokenUserSearch = "sub"
	open.AnonClaims = map[string]any{}
	openApp := open.RestAPI["v1"]
	openApp.Auth = &none
	open.RestAPI["v1"] = openApp
	openPlugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}
	openRouter := serveRest(t, open, map[string]easyrest.DBPlugin{"db": openPlugin})
	openW := httptest.NewRecorder()
	openRouter.ServeHTTP(openW, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if openW.Code != http.StatusOK || openPlugin.getUser != "" {
		t.Fatalf("no anon status %d user %q body %q", openW.Code, openPlugin.getUser, openW.Body.String())
	}
}

func TestRestAPI_AuthOverride(t *testing.T) {
	plugins := map[string]easyrest.AuthPlugin{
		"jwt":   namedAuthPlugin{name: "jwt"},
		"basic": namedAuthPlugin{name: "basic"},
	}
	prev := AuthPlugins.Load()
	prevOrder := authPluginOrder.Load()
	t.Cleanup(func() {
		AuthPlugins.Store(prev)
		authPluginOrder.Store(prevOrder)
	})
	AuthPlugins.Store(&plugins)
	setAuthPluginOrder(plugins)

	appAuth := []string{"basic"}
	endpointAuth := []string{"jwt"}
	none := []string{}
	cfg := config.Config{
		TokenUserSearch: "sub",
		AnonClaims:      map[string]any{},
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Auth:   &appAuth,
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Auth: &endpointAuth,
						Actions: map[string]config.RestAction{
							"list":     {},
							"create":   {Auth: &none},
							"retrieve": {Auth: &appAuth},
						},
						ListActions: map[string]config.RestCallAction{
							"export": {Func: "export_users", Auth: &none},
						},
					},
				},
			},
		},
	}
	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	list := httptest.NewRecorder()
	router.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if list.Code != http.StatusOK || plugin.getUser != "jwt" {
		t.Fatalf("endpoint auth status %d user %q body %q", list.Code, plugin.getUser, list.Body.String())
	}

	export := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/export/", strings.NewReader(`{}`))
	export.Header.Set("Content-Type", "application/json")
	exportW := httptest.NewRecorder()
	restLastAuth = ""
	router.ServeHTTP(exportW, export)
	if exportW.Code != http.StatusOK || restLastAuth != "" {
		t.Fatalf("empty action auth status %d plugin %q body %q", exportW.Code, restLastAuth, exportW.Body.String())
	}

	retrieve := httptest.NewRecorder()
	restLastAuth = ""
	router.ServeHTTP(retrieve, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/1/", nil))
	if retrieve.Code != http.StatusOK || restLastAuth != "basic" {
		t.Fatalf("action auth status %d plugin %q body %q", retrieve.Code, restLastAuth, retrieve.Body.String())
	}
}

func TestRestAPI_AppAnonClaimsReplaceGlobal(t *testing.T) {
	plugins := map[string]easyrest.AuthPlugin{"jwt": denyAuthPlugin{}}
	prev := AuthPlugins.Load()
	prevOrder := authPluginOrder.Load()
	t.Cleanup(func() {
		AuthPlugins.Store(prev)
		authPluginOrder.Store(prevOrder)
	})
	AuthPlugins.Store(&plugins)
	setAuthPluginOrder(plugins)

	listed := []string{"jwt"}
	appClaims := map[string]any{"sub": "app-anon", "scope": "read write"}
	cfg := restUsersConfig()
	cfg.TokenUserSearch = "sub"
	cfg.AnonClaims = map[string]any{"sub": "global-anon", "scope": "read write"}
	app := cfg.RestAPI["v1"]
	app.Auth = &listed
	app.AnonClaims = appClaims
	cfg.RestAPI["v1"] = app
	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if w.Code != http.StatusOK || plugin.getUser != "app-anon" {
		t.Fatalf("app anon status %d user %q body %q", w.Code, plugin.getUser, w.Body.String())
	}

	cfg.RestAPI["v1"] = config.RestAPIApp{Source: "db", Auth: &listed, Endpoints: app.Endpoints}
	globalPlugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}
	globalRouter := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": globalPlugin})
	globalW := httptest.NewRecorder()
	globalRouter.ServeHTTP(globalW, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if globalW.Code != http.StatusOK || globalPlugin.getUser != "global-anon" {
		t.Fatalf("global anon status %d user %q body %q", globalW.Code, globalPlugin.getUser, globalW.Body.String())
	}

	emptyApp := cfg.RestAPI["v1"]
	emptyApp.AnonClaims = map[string]any{}
	cfg.RestAPI["v1"] = emptyApp
	emptyPlugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}
	emptyRouter := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": emptyPlugin})
	emptyW := httptest.NewRecorder()
	emptyRouter.ServeHTTP(emptyW, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if emptyW.Code != http.StatusUnauthorized {
		t.Fatalf("empty app anon status %d body %q", emptyW.Code, emptyW.Body.String())
	}
}

type denyAuthPlugin struct{}

func (denyAuthPlugin) Init(map[string]any, easyrest.HostRPC) (easyrest.AuthInfo, error) {
	return easyrest.NewAuthInfo(map[string]any{"type": "apiKey"}), nil
}

func (denyAuthPlugin) Authenticate(map[string]string, string, string, string) (map[string]any, error) {
	return nil, errors.New("denied")
}

func TestRestAPI_RequiredScopes(t *testing.T) {
	none := []string{}
	base := func(scope string, public bool, check bool, createScopes []string) (http.Handler, *restRecPlugin) {
		cfg := restUsersConfig()
		cfg.CheckScope = check
		cfg.TokenUserSearch = "sub"
		cfg.AnonClaims = map[string]any{}
		app := cfg.RestAPI["v1"]
		app.Auth = &none
		app.AnonClaims = map[string]any{"sub": "u", "scope": scope}
		ep := app.Endpoints["users"]
		ep.Public = public
		ep.RequiredScopes = []string{"orders-read", "admin"}
		ep.Actions = map[string]config.RestAction{
			"list":   {},
			"create": {RequiredScopes: createScopes},
		}
		app.Endpoints["users"] = ep
		cfg.RestAPI["v1"] = app
		plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}
		return serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin}), plugin
	}
	get := func(h http.Handler) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
		return w
	}
	post := func(h http.Handler) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"name":"ada"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	partial, _ := base("read", false, true, []string{"orders-write"})
	if get(partial).Code != http.StatusForbidden {
		t.Fatalf("partial scopes status %d", get(partial).Code)
	}
	full, _ := base("read admin", false, true, []string{"orders-write"})
	if get(full).Code != http.StatusOK {
		t.Fatalf("full scopes status %d body %q", get(full).Code, get(full).Body.String())
	}
	if post(full).Code != http.StatusForbidden {
		t.Fatalf("action scopes status %d body %q", post(full).Code, post(full).Body.String())
	}
	writer, _ := base("write", false, true, []string{"orders-write"})
	if post(writer).Code != http.StatusCreated {
		t.Fatalf("write scope status %d body %q", post(writer).Code, post(writer).Body.String())
	}
	open, _ := base("read", true, true, nil)
	if get(open).Code != http.StatusOK {
		t.Fatalf("public status %d body %q", get(open).Code, get(open).Body.String())
	}
	unchecked, _ := base("read", false, false, nil)
	if get(unchecked).Code != http.StatusOK {
		t.Fatalf("check_scope false status %d body %q", get(unchecked).Code, get(unchecked).Body.String())
	}
}

type namedAuthPlugin struct{ name string }

var restLastAuth string

func (p namedAuthPlugin) Init(map[string]any, easyrest.HostRPC) (easyrest.AuthInfo, error) {
	return easyrest.NewAuthInfo(map[string]any{"type": "apiKey"}), nil
}

func (p namedAuthPlugin) Authenticate(map[string]string, string, string, string) (map[string]any, error) {
	restLastAuth = p.name
	return map[string]any{"sub": p.name}, nil
}

func TestRestAPI_NoTrailingSlashAction(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{
		"id":     float64(1),
		"name":   "ada",
		"avatar": map[string]any{"name": "pic"},
	}}}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Actions: map[string]config.RestAction{
							"list":   {NoTrailingSlash: true},
							"create": {},
						},
						ListActions: map[string]config.RestCallAction{
							"export": {Func: "export_users", Fields: restActionFields(), NoTrailingSlash: true},
						},
						DetailActions: map[string]config.RestCallAction{
							"archive": {Func: "archive_user", Fields: restActionFields()},
						},
						StateActions: map[string]config.RestStateAction{
							"avatar": {SourceField: "avatar", Fields: restStateFields(), NoTrailingSlash: true},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	list := httptest.NewRecorder()
	router.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/restapi/v1/users", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("list without slash: status %d body %q", list.Code, list.Body.String())
	}
	listSlash := httptest.NewRecorder()
	router.ServeHTTP(listSlash, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if listSlash.Code != http.StatusMethodNotAllowed {
		t.Fatalf("list with slash: status %d", listSlash.Code)
	}
	create := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{}`))
	createReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(create, createReq)
	if create.Code == http.StatusNotFound {
		t.Fatalf("create lost its slash: body %q", create.Body.String())
	}

	export := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/export", strings.NewReader(`{"reason":"x"}`))
	export.Header.Set("Content-Type", "application/json")
	exportW := httptest.NewRecorder()
	router.ServeHTTP(exportW, export)
	if exportW.Code != http.StatusOK {
		t.Fatalf("export without slash: status %d body %q", exportW.Code, exportW.Body.String())
	}
	exportSlash := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/export/", strings.NewReader(`{"reason":"x"}`))
	exportSlash.Header.Set("Content-Type", "application/json")
	exportSlashW := httptest.NewRecorder()
	router.ServeHTTP(exportSlashW, exportSlash)
	if exportSlashW.Code != http.StatusNotFound {
		t.Fatalf("export with slash: status %d", exportSlashW.Code)
	}

	archive := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/1/archive/", strings.NewReader(`{"reason":"x"}`))
	archive.Header.Set("Content-Type", "application/json")
	archiveW := httptest.NewRecorder()
	router.ServeHTTP(archiveW, archive)
	if archiveW.Code != http.StatusOK {
		t.Fatalf("archive with slash: status %d body %q", archiveW.Code, archiveW.Body.String())
	}

	state := httptest.NewRecorder()
	router.ServeHTTP(state, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/1/avatar", nil))
	if state.Code != http.StatusOK {
		t.Fatalf("state get without slash: status %d body %q", state.Code, state.Body.String())
	}
	statePut := httptest.NewRequest(http.MethodPut, "/restapi/v1/users/1/avatar", strings.NewReader(`{"name":"pic"}`))
	statePut.Header.Set("Content-Type", "application/json")
	statePutW := httptest.NewRecorder()
	router.ServeHTTP(statePutW, statePut)
	if statePutW.Code == http.StatusNotFound {
		t.Fatalf("state put without slash: body %q", statePutW.Body.String())
	}
	stateSlash := httptest.NewRecorder()
	router.ServeHTTP(stateSlash, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/1/avatar/", nil))
	if stateSlash.Code != http.StatusNotFound {
		t.Fatalf("state with slash: status %d", stateSlash.Code)
	}
}

func TestRestAPI_ListReturnsRows(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1), "name": "ada"}}}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})

	req := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %v body %q", err, w.Body.String())
	}
	rows, _ := body["results"].([]any)
	if len(rows) != 1 {
		t.Fatalf("body %#v", body)
	}
	row, _ := rows[0].(map[string]any)
	if row["name"] != "ada" {
		t.Fatalf("body %#v", body)
	}
}

func TestRestAPI_ListOmitsNullFields(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"name": "ada", "note": nil}}}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})

	req := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %v body %q", err, w.Body.String())
	}
	rows, _ := body["results"].([]any)
	row, _ := rows[0].(map[string]any)
	if row["name"] != "ada" {
		t.Fatalf("body %#v", body)
	}
	if _, ok := row["note"]; ok {
		t.Fatalf("null note present %#v", body)
	}
}

func TestRestAPI_ListLimitOffset(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})

	paged := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?limit=2&offset=5", nil)
	pagedW := httptest.NewRecorder()
	router.ServeHTTP(pagedW, paged)
	if pagedW.Code != http.StatusOK {
		t.Fatalf("status %d body %q", pagedW.Code, pagedW.Body.String())
	}
	if plugin.getLimit != 2 || plugin.getOffset != 5 {
		t.Fatalf("limit %d offset %d", plugin.getLimit, plugin.getOffset)
	}

	negative := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?offset=-3", nil)
	negativeW := httptest.NewRecorder()
	router.ServeHTTP(negativeW, negative)
	if negativeW.Code != http.StatusOK {
		t.Fatalf("status %d body %q", negativeW.Code, negativeW.Body.String())
	}
	if plugin.getLimit != 0 || plugin.getOffset != 0 {
		t.Fatalf("negative offset limit %d offset %d", plugin.getLimit, plugin.getOffset)
	}
}

func TestRestAPI_ListDefaultLimit(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}
	cfg := restUsersConfig()
	cfg.PluginMap = map[string]config.PluginConfig{
		"db": {DefaultLimit: 10},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	plain := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	plainW := httptest.NewRecorder()
	router.ServeHTTP(plainW, plain)
	if plainW.Code != http.StatusOK {
		t.Fatalf("status %d body %q", plainW.Code, plainW.Body.String())
	}
	if plugin.getLimit != 10 {
		t.Fatalf("default limit %d", plugin.getLimit)
	}

	prefer := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	prefer.Header.Set("Prefer", "page_size=3")
	preferW := httptest.NewRecorder()
	router.ServeHTTP(preferW, prefer)
	if preferW.Code != http.StatusOK {
		t.Fatalf("status %d body %q", preferW.Code, preferW.Body.String())
	}
	if plugin.getLimit != 3 {
		t.Fatalf("prefer limit %d", plugin.getLimit)
	}
}

type totalRestPlugin struct {
	fakeDBPlugin
	rows []map[string]any
}

func (p *totalRestPlugin) TableGet(string, string, []string, map[string]any, []string, []string, int, int, map[string]any) ([]map[string]any, map[string]any, error) {
	return p.rows, map[string]any{"total": int64(9)}, nil
}

func TestRestAPI_ListCount(t *testing.T) {
	withTotal := &totalRestPlugin{rows: []map[string]any{{"id": float64(1)}}}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": withTotal})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %v body %q", err, w.Body.String())
	}
	if body["count"] != float64(9) {
		t.Fatalf("count %#v body %#v", body["count"], body)
	}

	plain := &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}
	plainRouter := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plain})
	plainW := httptest.NewRecorder()
	plainRouter.ServeHTTP(plainW, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if plainW.Code != http.StatusOK {
		t.Fatalf("status %d body %q", plainW.Code, plainW.Body.String())
	}
	var plainBody map[string]any
	if err := json.Unmarshal(plainW.Body.Bytes(), &plainBody); err != nil {
		t.Fatalf("decode %v body %q", err, plainW.Body.String())
	}
	if _, ok := plainBody["count"]; ok {
		t.Fatalf("count present %#v", plainBody)
	}
}

func TestRestAPI_ListPageLinks(t *testing.T) {
	plugin := &totalRestPlugin{rows: []map[string]any{{"id": float64(1)}}}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})

	paged := httptest.NewRecorder()
	pagedReq := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?city=Berlin&limit=2&offset=2", nil)
	pagedReq.Header.Set("X-Forwarded-Proto", "https")
	pagedReq.Header.Set("X-Forwarded-Host", "example.com:8433")
	pagedReq.Header.Set("X-Forwarded-Prefix", "/someapp")
	router.ServeHTTP(paged, pagedReq)
	if paged.Code != http.StatusOK {
		t.Fatalf("status %d body %q", paged.Code, paged.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(paged.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %v body %q", err, paged.Body.String())
	}
	if body["previous"] != "https://example.com:8433/someapp/restapi/v1/users/?city=Berlin&limit=2&offset=0" {
		t.Fatalf("previous %#v", body["previous"])
	}
	prev := restLinkQuery(t, body["previous"])
	if prev.Get("city") != "Berlin" || prev.Get("limit") != "2" || prev.Get("offset") != "0" {
		t.Fatalf("previous %#v", body["previous"])
	}
	next := restLinkQuery(t, body["next"])
	if next.Get("city") != "Berlin" || next.Get("limit") != "2" || next.Get("offset") != "4" {
		t.Fatalf("next %#v", body["next"])
	}

	first := httptest.NewRecorder()
	router.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?limit=2", nil))
	var firstBody map[string]any
	if err := json.Unmarshal(first.Body.Bytes(), &firstBody); err != nil {
		t.Fatalf("decode %v body %q", err, first.Body.String())
	}
	if _, ok := firstBody["previous"]; !ok || firstBody["previous"] != nil {
		t.Fatalf("previous %#v", firstBody["previous"])
	}

	last := httptest.NewRecorder()
	router.ServeHTTP(last, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?limit=2&offset=8", nil))
	var lastBody map[string]any
	if err := json.Unmarshal(last.Body.Bytes(), &lastBody); err != nil {
		t.Fatalf("decode %v body %q", err, last.Body.String())
	}
	if _, ok := lastBody["next"]; !ok || lastBody["next"] != nil {
		t.Fatalf("next %#v", lastBody["next"])
	}
}

func restLinkQuery(t *testing.T, raw any) url.Values {
	t.Helper()
	link, ok := raw.(string)
	if !ok {
		t.Fatalf("link %#v", raw)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse %q: %v", link, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		t.Fatalf("link %q", link)
	}
	return parsed.Query()
}

func TestRestAPI_ListContentRangeUsesTotal(t *testing.T) {
	plugin := &totalRestPlugin{rows: []map[string]any{{"id": float64(1)}}}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})
	req := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if got := w.Header().Get("Content-Range"); got != "0-0/9" {
		t.Fatalf("Content-Range = %q, want 0-0/9", got)
	}
}

func TestRestAPI_ListRange(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})

	ranged := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?limit=99", nil)
	ranged.Header.Set("Range", "2-4")
	ranged.Header.Set("Range-Unit", "items")
	rangedW := httptest.NewRecorder()
	router.ServeHTTP(rangedW, ranged)
	if rangedW.Code != http.StatusOK {
		t.Fatalf("status %d body %q", rangedW.Code, rangedW.Body.String())
	}
	if plugin.getOffset != 2 || plugin.getLimit != 3 {
		t.Fatalf("limit %d offset %d", plugin.getLimit, plugin.getOffset)
	}
	if rangedW.Header().Get("Content-Range") == "" || rangedW.Header().Get("Range-Unit") != "items" || rangedW.Header().Get("Accept-Ranges") != "items" {
		t.Fatalf("headers %#v", rangedW.Header())
	}

	plain := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	plainW := httptest.NewRecorder()
	router.ServeHTTP(plainW, plain)
	if plainW.Header().Get("Content-Range") == "" || plainW.Header().Get("Range-Unit") != "items" || plainW.Header().Get("Accept-Ranges") != "items" {
		t.Fatalf("plain headers %#v", plainW.Header())
	}
	if got := plainW.Header().Get("Content-Range"); got != "0-0/*" {
		t.Fatalf("list without total Content-Range = %q", got)
	}

	plugin.rows = nil
	past := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	past.Header.Set("Range", "10-12")
	past.Header.Set("Range-Unit", "items")
	pastW := httptest.NewRecorder()
	router.ServeHTTP(pastW, past)
	if pastW.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("status %d body %q", pastW.Code, pastW.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(pastW.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %v body %q", err, pastW.Body.String())
	}
	results, _ := body["results"].([]any)
	if len(results) != 0 {
		t.Fatalf("body %#v", body)
	}
}

func TestRestAPI_ListSelectFields(t *testing.T) {
	plugin := &restRecPlugin{
		rows: []map[string]any{{"name": "ada"}},
		schema: map[string]any{
			"tables": map[string]any{
				"users": map[string]any{
					"properties": map[string]any{
						"email": map[string]any{"type": "string"},
						"name":  map[string]any{"type": "string"},
					},
				},
			},
		},
	}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"picked": {
						Table: "users",
						Actions: map[string]config.RestAction{
							"list": {Fields: []string{"name"}},
						},
					},
					"all": {Table: "users"},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	picked := httptest.NewRecorder()
	router.ServeHTTP(picked, httptest.NewRequest(http.MethodGet, "/restapi/v1/picked/", nil))
	if picked.Code != http.StatusOK {
		t.Fatalf("status %d body %q", picked.Code, picked.Body.String())
	}
	if len(plugin.getSelect) != 1 || plugin.getSelect[0] != "name" {
		t.Fatalf("select %#v", plugin.getSelect)
	}

	all := httptest.NewRecorder()
	router.ServeHTTP(all, httptest.NewRequest(http.MethodGet, "/restapi/v1/all/", nil))
	if all.Code != http.StatusOK {
		t.Fatalf("status %d body %q", all.Code, all.Body.String())
	}
	if len(plugin.getSelect) != 2 || plugin.getSelect[0] != "email" || plugin.getSelect[1] != "name" {
		t.Fatalf("select %#v", plugin.getSelect)
	}
}

func TestRestAPI_ListOrdering(t *testing.T) {
	plugin := &restRecPlugin{
		rows: []map[string]any{{"name": "ada"}},
		schema: map[string]any{
			"tables": map[string]any{
				"users": map[string]any{
					"properties": map[string]any{
						"name":  map[string]any{"type": "string"},
						"email": map[string]any{"type": "string"},
					},
				},
			},
		},
	}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Filters: map[string]config.RestFilter{
							"email": {Op: "eq"},
						},
						Actions: map[string]config.RestAction{
							"list": {Fields: []string{"name"}},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	okReq := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?ordering=name,-name", nil)
	okW := httptest.NewRecorder()
	router.ServeHTTP(okW, okReq)
	if okW.Code != http.StatusOK {
		t.Fatalf("status %d body %q", okW.Code, okW.Body.String())
	}
	if len(plugin.getOrder) != 2 || plugin.getOrder[0] != "name" || plugin.getOrder[1] != "name DESC" {
		t.Fatalf("ordering %#v", plugin.getOrder)
	}

	calls := plugin.getCalls
	bad := httptest.NewRecorder()
	router.ServeHTTP(bad, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?ordering=email", nil))
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "invalid ordering") {
		t.Fatalf("status %d body %q", bad.Code, bad.Body.String())
	}
	if plugin.getCalls != calls {
		t.Fatalf("TableGet calls %d want %d", plugin.getCalls, calls)
	}
}

func TestRestAPI_ListSwaggerParams(t *testing.T) {
	plugin := &restRecPlugin{
		schema: map[string]any{
			"tables": map[string]any{
				"users": map[string]any{
					"properties": map[string]any{
						"name": map[string]any{"type": "string"},
					},
				},
			},
		},
	}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/restapi/v1/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	var spec map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths, _ := spec["paths"].(map[string]any)
	users, _ := paths["/users/"].(map[string]any)
	list, _ := users["get"].(map[string]any)
	params, _ := list["parameters"].([]any)
	limit := restSpecParam(t, params, "limit", "query")
	offset := restSpecParam(t, params, "offset", "query")
	ordering := restSpecParam(t, params, "ordering", "query")
	if limit["type"] != "integer" || offset["type"] != "integer" {
		t.Fatalf("paging %#v %#v", limit, offset)
	}
	items, _ := ordering["items"].(map[string]any)
	enum, _ := items["enum"].([]any)
	if len(enum) != 2 || enum[0] != "name" || enum[1] != "-name" {
		t.Fatalf("ordering %#v", ordering)
	}
	if restSpecParam(t, params, "Range", "header") == nil || restSpecParam(t, params, "Range-Unit", "header") == nil {
		t.Fatal("missing range headers")
	}
	responses, _ := list["responses"].(map[string]any)
	ok, _ := responses["200"].(map[string]any)
	schema, _ := ok["schema"].(map[string]any)
	props, _ := schema["properties"].(map[string]any)
	results, _ := props["results"].(map[string]any)
	itemSchema, _ := results["items"].(map[string]any)
	itemProps, _ := itemSchema["properties"].(map[string]any)
	if schema["type"] != "object" || results["type"] != "array" || itemProps["name"] == nil {
		t.Fatalf("schema %#v", schema)
	}
	count, _ := props["count"].(map[string]any)
	next, _ := props["next"].(map[string]any)
	previous, _ := props["previous"].(map[string]any)
	if count["type"] != "integer" || next["type"] != "string" || previous["type"] != "string" {
		t.Fatalf("page fields %#v", props)
	}
}

type markMiddleware struct {
	key     string
	pre     int
	post    int
	postCtx map[string]any
	header  string
}

func (m *markMiddleware) Init(map[string]any, easyrest.HostRPC) (easyrest.MiddlewareInfo, error) {
	return easyrest.NewMiddlewareInfo(), nil
}

func (m *markMiddleware) PreRequest(_ string, ctx map[string]any) (map[string]any, *int, error) {
	m.pre++
	if ctx == nil {
		ctx = map[string]any{}
	}
	ctx[m.key] = "yes"
	return ctx, nil, nil
}

func (m *markMiddleware) PostRequest(_ string, ctx map[string]any) (map[string]string, error) {
	m.post++
	m.postCtx = ctx
	if m.header == "" {
		return nil, nil
	}
	return map[string]string{m.header: "seen"}, nil
}

func installMarkMiddleware(t *testing.T, cfg *config.Config, mw *markMiddleware) {
	t.Helper()
	orig := MiddlewarePlugins.Load()
	t.Cleanup(func() { MiddlewarePlugins.Store(orig) })
	MiddlewarePlugins.Store(&map[string]easyrest.MiddlewarePlugin{"mark": mw})
	cfg.GlobalRequestMiddlewares = []string{"mark"}
	cfg.MiddlewarePlugins = map[string]config.MiddlewareConfig{"mark": {}}
}

func assertWriteContext(t *testing.T, ctx map[string]any, method, table string) {
	t.Helper()
	if ctx["method"] != method || ctx[easyrest.CtxTable] != table || ctx["mw"] != "yes" {
		t.Fatalf("ctx %#v", ctx)
	}
}

func TestRestAPI_CreateContext(t *testing.T) {
	mw := &markMiddleware{key: "mw"}
	plugin := &restRecPlugin{}
	cfg := restUsersConfig()
	installMarkMiddleware(t, &cfg, mw)
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	req := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"name":"ada"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated || mw.pre != 1 {
		t.Fatalf("status %d pre %d body %q", w.Code, mw.pre, w.Body.String())
	}
	assertWriteContext(t, plugin.createCtx, http.MethodPost, "users")

	fnPlugin := &restRecPlugin{funcResult: map[string]any{"sku": "a"}}
	fnMW := &markMiddleware{key: "mw"}
	fnCfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"invoice_lines": {
						Table: "add_invoice_line",
						Actions: map[string]config.RestAction{
							"create": {Type: "func"},
						},
					},
				},
			},
		},
	}
	installMarkMiddleware(t, &fnCfg, fnMW)
	fnRouter := serveRest(t, fnCfg, map[string]easyrest.DBPlugin{"db": fnPlugin})
	fnReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/invoice_lines/", strings.NewReader(`{"sku":"a"}`))
	fnReq.Header.Set("Content-Type", "application/json")
	fnW := httptest.NewRecorder()
	fnRouter.ServeHTTP(fnW, fnReq)
	if fnW.Code != http.StatusCreated || fnMW.pre != 1 {
		t.Fatalf("func status %d pre %d body %q", fnW.Code, fnMW.pre, fnW.Body.String())
	}
	if fnPlugin.funcCtx[easyrest.CtxFunction] != "add_invoice_line" || fnPlugin.funcCtx["mw"] != "yes" || fnPlugin.funcCtx["method"] != http.MethodPost {
		t.Fatalf("func ctx %#v", fnPlugin.funcCtx)
	}
}

func TestRestAPI_UpdateDestroyContext(t *testing.T) {
	mw := &markMiddleware{key: "mw"}
	plugin := &restRecPlugin{updated: 1}
	cfg := restUsersConfig()
	installMarkMiddleware(t, &cfg, mw)
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	patch := httptest.NewRequest(http.MethodPatch, "/restapi/v1/users/5/", strings.NewReader(`{"name":"ada"}`))
	patch.Header.Set("Content-Type", "application/json")
	patchW := httptest.NewRecorder()
	router.ServeHTTP(patchW, patch)
	if patchW.Code != http.StatusOK || mw.pre != 1 {
		t.Fatalf("patch status %d pre %d body %q", patchW.Code, mw.pre, patchW.Body.String())
	}
	assertWriteContext(t, plugin.updateCtx, http.MethodPatch, "users")

	del := httptest.NewRequest(http.MethodDelete, "/restapi/v1/users/5/", nil)
	delW := httptest.NewRecorder()
	router.ServeHTTP(delW, del)
	if delW.Code != http.StatusNoContent || mw.pre != 2 {
		t.Fatalf("delete status %d pre %d", delW.Code, mw.pre)
	}
	assertWriteContext(t, plugin.deleteCtx, http.MethodDelete, "users")
}

func TestRestAPI_CallContext(t *testing.T) {
	mw := &markMiddleware{key: "mw"}
	plugin := &restRecPlugin{funcResult: map[string]any{"ok": true}}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						DetailActions: map[string]config.RestCallAction{
							"archive": {Func: "archive_user"},
						},
						ListActions: map[string]config.RestCallAction{
							"export": {Func: "export_users"},
						},
					},
				},
			},
		},
	}
	installMarkMiddleware(t, &cfg, mw)
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	detail := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/5/archive/", strings.NewReader(`{"reason":"x"}`))
	detail.Header.Set("Content-Type", "application/json")
	detailW := httptest.NewRecorder()
	router.ServeHTTP(detailW, detail)
	if detailW.Code != http.StatusOK || mw.pre != 1 {
		t.Fatalf("detail status %d pre %d body %q", detailW.Code, mw.pre, detailW.Body.String())
	}
	if plugin.funcCtx[easyrest.CtxFunction] != "archive_user" || plugin.funcCtx["method"] != http.MethodPost || plugin.funcCtx["mw"] != "yes" {
		t.Fatalf("detail ctx %#v", plugin.funcCtx)
	}

	list := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/export/", strings.NewReader(`{"reason":"x"}`))
	list.Header.Set("Content-Type", "application/json")
	listW := httptest.NewRecorder()
	router.ServeHTTP(listW, list)
	if listW.Code != http.StatusOK || mw.pre != 2 {
		t.Fatalf("list status %d pre %d body %q", listW.Code, mw.pre, listW.Body.String())
	}
	if plugin.funcCtx[easyrest.CtxFunction] != "export_users" || plugin.funcCtx["method"] != http.MethodPost || plugin.funcCtx["mw"] != "yes" {
		t.Fatalf("list ctx %#v", plugin.funcCtx)
	}
}

func TestRestAPI_StateContext(t *testing.T) {
	mw := &markMiddleware{key: "mw"}
	plugin := &restRecPlugin{
		rows:       []map[string]any{{"avatar": map[string]any{"name": "pic"}}},
		funcResult: map[string]any{"name": "ada"},
		updated:    1,
	}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						StateActions: map[string]config.RestStateAction{
							"avatar":   {SourceField: "avatar", Fields: restStateFields()},
							"settings": {Func: "load_settings", Fields: restStateFields()},
						},
					},
				},
			},
		},
	}
	installMarkMiddleware(t, &cfg, mw)
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	get := httptest.NewRecorder()
	router.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/5/avatar/", nil))
	if get.Code != http.StatusOK || mw.pre != 1 {
		t.Fatalf("column get status %d pre %d body %q", get.Code, mw.pre, get.Body.String())
	}
	assertWriteContext(t, plugin.getCtx, http.MethodGet, "users")

	fnGet := httptest.NewRecorder()
	router.ServeHTTP(fnGet, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/settings/", nil))
	if fnGet.Code != http.StatusOK || mw.pre != 2 {
		t.Fatalf("func get status %d pre %d body %q", fnGet.Code, mw.pre, fnGet.Body.String())
	}
	if plugin.funcCtx[easyrest.CtxFunction] != "load_settings" || plugin.funcCtx["method"] != http.MethodGet || plugin.funcCtx["mw"] != "yes" {
		t.Fatalf("func get ctx %#v", plugin.funcCtx)
	}

	put := httptest.NewRequest(http.MethodPut, "/restapi/v1/users/5/avatar/", strings.NewReader(`{"name":"pic"}`))
	put.Header.Set("Content-Type", "application/json")
	putW := httptest.NewRecorder()
	router.ServeHTTP(putW, put)
	if putW.Code != http.StatusOK || mw.pre != 3 {
		t.Fatalf("column put status %d pre %d body %q", putW.Code, mw.pre, putW.Body.String())
	}
	assertWriteContext(t, plugin.updateCtx, http.MethodPut, "users")

	fnPut := httptest.NewRequest(http.MethodPut, "/restapi/v1/users/settings/", strings.NewReader(`{"name":"ada"}`))
	fnPut.Header.Set("Content-Type", "application/json")
	fnPutW := httptest.NewRecorder()
	router.ServeHTTP(fnPutW, fnPut)
	if fnPutW.Code != http.StatusOK || mw.pre != 4 {
		t.Fatalf("func put status %d pre %d body %q", fnPutW.Code, mw.pre, fnPutW.Body.String())
	}
	if plugin.funcName != "load_settings" || plugin.funcCtx[easyrest.CtxFunction] != "load_settings" || plugin.funcCtx["method"] != http.MethodPut || plugin.funcCtx["mw"] != "yes" {
		t.Fatalf("func put %q ctx %#v", plugin.funcName, plugin.funcCtx)
	}
}

func TestRestAPI_StateURL(t *testing.T) {
	plugin := &restRecPlugin{funcResult: map[string]any{"name": "ada"}}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"discovery": {
						URL:     ".well-known",
						Actions: map[string]config.RestAction{"placeholder": {}},
						StateActions: map[string]config.RestStateAction{
							"openid_configuration": {
								Func:            "app.openid_configuration",
								URL:             "openid-configuration",
								NoTrailingSlash: true,
								Fields:          restStateFields(),
							},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	get := httptest.NewRecorder()
	router.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/restapi/v1/.well-known/openid-configuration", nil))
	if get.Code != http.StatusOK || plugin.funcName != "app.openid_configuration" {
		t.Fatalf("get status %d func %q body %q", get.Code, plugin.funcName, get.Body.String())
	}

	put := httptest.NewRequest(http.MethodPut, "/restapi/v1/.well-known/openid-configuration", strings.NewReader(`{"name":"ada"}`))
	put.Header.Set("Content-Type", "application/json")
	putW := httptest.NewRecorder()
	router.ServeHTTP(putW, put)
	if putW.Code != http.StatusOK || plugin.funcCtx["method"] != http.MethodPut {
		t.Fatalf("put status %d method %#v body %q", putW.Code, plugin.funcCtx["method"], putW.Body.String())
	}

	keyPath := httptest.NewRecorder()
	router.ServeHTTP(keyPath, httptest.NewRequest(http.MethodGet, "/restapi/v1/.well-known/openid_configuration", nil))
	if keyPath.Code != http.StatusNotFound {
		t.Fatalf("key path status %d body %q", keyPath.Code, keyPath.Body.String())
	}

	spec := restSpec(t, router, "/restapi/v1/")
	paths, _ := spec["paths"].(map[string]any)
	item, _ := paths["/.well-known/openid-configuration"].(map[string]any)
	if item["get"] == nil || item["put"] == nil {
		t.Fatalf("spec %#v", item)
	}
	if _, ok := paths["/.well-known/openid_configuration"]; ok {
		t.Fatalf("key path in spec %#v", paths)
	}

	skipped := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Actions: map[string]config.RestAction{"placeholder": {}},
						StateActions: map[string]config.RestStateAction{
							"settings": {Func: "load_settings", URL: "a/b", Fields: restStateFields()},
						},
					},
				},
			},
		},
	}
	skippedRouter := serveRest(t, skipped, map[string]easyrest.DBPlugin{"db": plugin})
	miss := httptest.NewRecorder()
	skippedRouter.ServeHTTP(miss, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/settings/", nil))
	if miss.Code != http.StatusNotFound {
		t.Fatalf("invalid segment status %d body %q", miss.Code, miss.Body.String())
	}
}

func TestRestAPI_CallURL(t *testing.T) {
	plugin := &restRecPlugin{funcResult: map[string]any{"reason": "x", "done": true}}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Actions: map[string]config.RestAction{"placeholder": {}},
						ListActions: map[string]config.RestCallAction{
							"export": {Func: "export_users", URL: "pull", Fields: restActionFields()},
						},
						DetailActions: map[string]config.RestCallAction{
							"archive": {Func: "archive_user", URL: "store", Fields: restActionFields()},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	list := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/pull/", strings.NewReader(`{"reason":"x"}`))
	list.Header.Set("Content-Type", "application/json")
	listW := httptest.NewRecorder()
	router.ServeHTTP(listW, list)
	if listW.Code != http.StatusOK || plugin.funcName != "export_users" {
		t.Fatalf("list status %d func %q body %q", listW.Code, plugin.funcName, listW.Body.String())
	}

	detail := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/5/store/", strings.NewReader(`{"reason":"x"}`))
	detail.Header.Set("Content-Type", "application/json")
	detailW := httptest.NewRecorder()
	router.ServeHTTP(detailW, detail)
	if detailW.Code != http.StatusOK || plugin.funcName != "archive_user" {
		t.Fatalf("detail status %d func %q body %q", detailW.Code, plugin.funcName, detailW.Body.String())
	}

	key := httptest.NewRecorder()
	router.ServeHTTP(key, httptest.NewRequest(http.MethodPost, "/restapi/v1/users/export/", strings.NewReader(`{"reason":"x"}`)))
	if key.Code != http.StatusNotFound {
		t.Fatalf("key path status %d", key.Code)
	}

	spec := restSpec(t, router, "/restapi/v1/")
	paths, _ := spec["paths"].(map[string]any)
	listItem, _ := paths["/users/pull/"].(map[string]any)
	detailItem, _ := paths["/users/{id}/store/"].(map[string]any)
	if listItem["post"] == nil || detailItem["post"] == nil {
		t.Fatalf("list %#v detail %#v", listItem, detailItem)
	}
	if _, ok := paths["/users/export/"]; ok {
		t.Fatalf("key path in spec")
	}
}

func TestRestAPI_StatePost(t *testing.T) {
	plugin := &restRecPlugin{funcResult: map[string]any{"name": "ada"}, updated: 1}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Actions: map[string]config.RestAction{"placeholder": {}},
						StateActions: map[string]config.RestStateAction{
							"settings": {Func: "load_settings", Post: true, Fields: restStateFields()},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	get := httptest.NewRecorder()
	router.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/settings/", nil))
	if get.Code != http.StatusOK || plugin.funcName != "load_settings" || plugin.funcCtx["method"] != http.MethodGet {
		t.Fatalf("get status %d func %q method %#v body %q", get.Code, plugin.funcName, plugin.funcCtx["method"], get.Body.String())
	}

	post := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/settings/", strings.NewReader(`{"name":"ada"}`))
	post.Header.Set("Content-Type", "application/json")
	postW := httptest.NewRecorder()
	router.ServeHTTP(postW, post)
	if postW.Code != http.StatusOK || plugin.funcCtx["method"] != http.MethodPost || plugin.funcData["name"] != "ada" {
		t.Fatalf("post status %d method %#v data %#v body %q", postW.Code, plugin.funcCtx["method"], plugin.funcData, postW.Body.String())
	}

	putW := httptest.NewRecorder()
	put := httptest.NewRequest(http.MethodPut, "/restapi/v1/users/settings/", strings.NewReader(`{"name":"ada"}`))
	put.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(putW, put)
	if putW.Code != http.StatusMethodNotAllowed {
		t.Fatalf("put status %d body %q", putW.Code, putW.Body.String())
	}

	spec := restSpec(t, router, "/restapi/v1/")
	paths, _ := spec["paths"].(map[string]any)
	item, _ := paths["/users/settings/"].(map[string]any)
	if item["get"] == nil || item["post"] == nil || item["put"] != nil {
		t.Fatalf("spec %#v", item)
	}

	column := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Actions: map[string]config.RestAction{"placeholder": {}},
						StateActions: map[string]config.RestStateAction{
							"avatar": {SourceField: "avatar", Post: true, Fields: restStateFields()},
						},
					},
				},
			},
		},
	}
	columnRouter := serveRest(t, column, map[string]easyrest.DBPlugin{"db": plugin})
	columnPut := httptest.NewRequest(http.MethodPut, "/restapi/v1/users/5/avatar/", strings.NewReader(`{"name":"pic"}`))
	columnPut.Header.Set("Content-Type", "application/json")
	columnW := httptest.NewRecorder()
	columnRouter.ServeHTTP(columnW, columnPut)
	if columnW.Code != http.StatusOK {
		t.Fatalf("column put status %d body %q", columnW.Code, columnW.Body.String())
	}
	columnSpec := restSpec(t, columnRouter, "/restapi/v1/")
	columnPaths, _ := columnSpec["paths"].(map[string]any)
	columnItem, _ := columnPaths["/users/{id}/avatar/"].(map[string]any)
	if columnItem["put"] == nil || columnItem["post"] != nil {
		t.Fatalf("column spec %#v", columnItem)
	}
}

func TestRestAPI_ReturnedContext(t *testing.T) {
	mw := &markMiddleware{key: "mw", header: "X-Seen"}
	plugin := &restRecPlugin{
		rows:       []map[string]any{{"avatar": map[string]any{"name": "pic"}}},
		funcResult: map[string]any{"name": "ada"},
		updated:    1,
		returned: map[string]any{
			"response.header.X-From-Db": "1",
			"response.status":           202,
			"db.mark":                   "from-plugin",
		},
	}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						DetailActions: map[string]config.RestCallAction{
							"archive": {Func: "archive_user"},
						},
						ListActions: map[string]config.RestCallAction{
							"export": {Func: "export_users"},
						},
						StateActions: map[string]config.RestStateAction{
							"avatar": {SourceField: "avatar", Fields: restStateFields()},
						},
					},
				},
			},
		},
	}
	installMarkMiddleware(t, &cfg, mw)
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	assertReturned := func(w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusAccepted || w.Header().Get("X-From-Db") != "1" || w.Header().Get("X-Seen") != "seen" {
			t.Fatalf("status %d headers %#v body %q", w.Code, w.Header(), w.Body.String())
		}
		if mw.postCtx["db.mark"] != "from-plugin" {
			t.Fatalf("post ctx %#v", mw.postCtx)
		}
	}

	create := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"name":"ada"}`))
	create.Header.Set("Content-Type", "application/json")
	createW := httptest.NewRecorder()
	router.ServeHTTP(createW, create)
	assertReturned(createW)

	plugin.returned = nil
	kept := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"name":"ada"}`))
	kept.Header.Set("Content-Type", "application/json")
	keptW := httptest.NewRecorder()
	router.ServeHTTP(keptW, kept)
	if keptW.Code != http.StatusCreated || mw.postCtx["mw"] != "yes" || mw.postCtx["db.mark"] != nil {
		t.Fatalf("kept status %d post %#v body %q", keptW.Code, mw.postCtx, keptW.Body.String())
	}

	plugin.callErr = errors.New("db down")
	plugin.returned = map[string]any{"response.header.X-From-Db": "1"}
	bad := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"name":"ada"}`))
	bad.Header.Set("Content-Type", "application/json")
	badW := httptest.NewRecorder()
	router.ServeHTTP(badW, bad)
	if badW.Code != http.StatusInternalServerError || !strings.Contains(badW.Body.String(), "db down") || badW.Header().Get("X-From-Db") != "1" {
		t.Fatalf("error status %d header %q body %q", badW.Code, badW.Header().Get("X-From-Db"), badW.Body.String())
	}

	plugin.callErr = nil
	plugin.returned = map[string]any{
		"response.header.X-From-Db": "1",
		"response.status":           202,
		"db.mark":                   "from-plugin",
	}
	patch := httptest.NewRequest(http.MethodPatch, "/restapi/v1/users/5/", strings.NewReader(`{"name":"ada"}`))
	patch.Header.Set("Content-Type", "application/json")
	patchW := httptest.NewRecorder()
	router.ServeHTTP(patchW, patch)
	assertReturned(patchW)

	delW := httptest.NewRecorder()
	router.ServeHTTP(delW, httptest.NewRequest(http.MethodDelete, "/restapi/v1/users/5/", nil))
	assertReturned(delW)

	detail := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/5/archive/", strings.NewReader(`{"reason":"x"}`))
	detail.Header.Set("Content-Type", "application/json")
	detailW := httptest.NewRecorder()
	router.ServeHTTP(detailW, detail)
	assertReturned(detailW)

	list := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/export/", strings.NewReader(`{"reason":"x"}`))
	list.Header.Set("Content-Type", "application/json")
	listW := httptest.NewRecorder()
	router.ServeHTTP(listW, list)
	assertReturned(listW)

	stateGet := httptest.NewRecorder()
	router.ServeHTTP(stateGet, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/5/avatar/", nil))
	assertReturned(stateGet)

	statePut := httptest.NewRequest(http.MethodPut, "/restapi/v1/users/5/avatar/", strings.NewReader(`{"name":"pic"}`))
	statePut.Header.Set("Content-Type", "application/json")
	statePutW := httptest.NewRecorder()
	router.ServeHTTP(statePutW, statePut)
	assertReturned(statePutW)
}

func TestRestAPI_ListPluginContext(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"name": "ada"}}}
	cfg := restUsersConfig()
	cfg.TokenUserSearch = "sub"
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	req := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	req.Header.Set("Prefer", "timezone=UTC")
	req = req.WithContext(context.WithValue(req.Context(), TokenClaimsKey, jwt.MapClaims{"sub": "ada"}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if plugin.getUser != "ada" {
		t.Fatalf("user %q", plugin.getUser)
	}
	if plugin.getCtx["table"] != "users" || plugin.getCtx["method"] != "GET" || plugin.getCtx["path"] != "/restapi/v1/users/" || plugin.getCtx["timezone"] != "UTC" {
		t.Fatalf("ctx %#v", plugin.getCtx)
	}
	claims, _ := plugin.getCtx["claims"].(map[string]any)
	if claims["sub"] != "ada" {
		t.Fatalf("claims %#v", plugin.getCtx["claims"])
	}
}

func restSpecParam(t *testing.T, params []any, name, in string) map[string]any {
	t.Helper()
	for _, raw := range params {
		param, _ := raw.(map[string]any)
		if param["name"] == name && param["in"] == in {
			return param
		}
	}
	t.Fatalf("missing %s %s in %#v", in, name, params)
	return nil
}

func TestRestAPI_CreateReturnsCreated(t *testing.T) {
	plugin := &restRecPlugin{created: []map[string]any{{"id": float64(2), "name": "ada"}}}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})

	req := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"name":"ada"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode %v body %q", err, w.Body.String())
	}
	if len(rows) != 1 || rows[0]["name"] != "ada" {
		t.Fatalf("rows %#v", rows)
	}
}

func TestRestAPI_CreateAcceptsObjectArray(t *testing.T) {
	plugin := &restRecPlugin{}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})

	req := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`[{"name":"ada"},{"name":"bea"}]`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if plugin.creates != 1 || len(plugin.createData) != 2 || plugin.createData[0]["name"] != "ada" || plugin.createData[1]["name"] != "bea" {
		t.Fatalf("creates %d data %#v", plugin.creates, plugin.createData)
	}
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode %v body %q", err, w.Body.String())
	}
	if len(rows) != 2 || rows[0]["name"] != "ada" || rows[1]["name"] != "bea" {
		t.Fatalf("rows %#v", rows)
	}
}

func TestRestAPI_CreateRejectsEmptyArray(t *testing.T) {
	plugin := &restRecPlugin{}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})

	req := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`[]`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Invalid data format") {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if plugin.creates != 0 {
		t.Fatalf("creates %d", plugin.creates)
	}
}

func TestRestAPI_CreateRejectsNonObjectArray(t *testing.T) {
	plugin := &restRecPlugin{}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})

	req := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`[1,{"name":"ada"}]`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Invalid data format") {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if plugin.creates != 0 {
		t.Fatalf("creates %d", plugin.creates)
	}
}

func TestRestAPI_UpdateRejectsObjectArray(t *testing.T) {
	plugin := &restRecPlugin{updated: 1}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})

	req := httptest.NewRequest(http.MethodPatch, "/restapi/v1/users/5/", strings.NewReader(`[{"name":"ada"},{"name":"bea"}]`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if plugin.updateCalls != 0 {
		t.Fatalf("updates %d", plugin.updateCalls)
	}
}

func TestRestAPI_RetrieveReturnsObject(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(5), "name": "ada"}}}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})

	req := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/5/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	var row map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &row); err != nil {
		t.Fatalf("decode %v body %q", err, w.Body.String())
	}
	if row["name"] != "ada" {
		t.Fatalf("row %#v", row)
	}
}

func TestRestAPI_RetrieveSkipsCount(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(5), "name": "ada"}}}
	cfg := restUsersConfig()
	cfg.PluginMap = map[string]config.PluginConfig{
		"db": {DbPreferCount: "exact"},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	req := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/5/", nil)
	req.Header.Set("Prefer", "count=exact")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if easyrest.CountPreference(plugin.getCtx) != "" {
		t.Fatalf("retrieve counted: %#v", plugin.getCtx["prefer"])
	}
}

func TestRestAPI_RetrieveSelectLimit(t *testing.T) {
	plugin := &restRecPlugin{
		rows: []map[string]any{{"name": "ada", "email": "a@b.c"}},
		schema: map[string]any{
			"tables": map[string]any{
				"users": map[string]any{
					"properties": map[string]any{
						"email": map[string]any{"type": "string"},
						"name":  map[string]any{"type": "string"},
					},
				},
			},
		},
	}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/5/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if plugin.getLimit != 2 || len(plugin.getSelect) != 2 || plugin.getSelect[0] != "email" || plugin.getSelect[1] != "name" {
		t.Fatalf("limit %d select %#v", plugin.getLimit, plugin.getSelect)
	}
	var row map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &row); err != nil {
		t.Fatalf("decode %v body %q", err, w.Body.String())
	}
	if row["name"] != "ada" {
		t.Fatalf("row %#v", row)
	}
}

func TestRestAPI_RetrieveMissing(t *testing.T) {
	cases := []struct {
		name string
		rows []map[string]any
		want int
	}{
		{name: "none", rows: []map[string]any{}, want: http.StatusNotFound},
		{name: "many", rows: []map[string]any{{"id": float64(1)}, {"id": float64(2)}}, want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plugin := &restRecPlugin{rows: tc.rows}
			router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})
			req := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/5/", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status %d body %q", w.Code, w.Body.String())
			}
		})
	}
}

func TestRestAPI_UpdateReturnsCount(t *testing.T) {
	plugin := &restRecPlugin{updated: 1}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})

	req := httptest.NewRequest(http.MethodPatch, "/restapi/v1/users/5/", strings.NewReader(`{"name":"ada"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %v body %q", err, w.Body.String())
	}
	if body["updated"] != float64(1) {
		t.Fatalf("body %#v", body)
	}
}

func TestRestAPI_UpdateIfMatch(t *testing.T) {
	cachePlug := cachemw.New(lrustore.NewSimpleCachePlugin())
	if _, err := cachePlug.Init(map[string]any{"ttl": "24h"}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	origMW := MiddlewarePlugins.Load()
	t.Cleanup(func() { MiddlewarePlugins.Store(origMW) })
	MiddlewarePlugins.Store(&map[string]easyrest.MiddlewarePlugin{"cache-lru": cachePlug})

	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(5), "name": "ada"}}, updated: 1}
	cfg := config.Config{
		CheckScope: false,
		AnonClaims: map[string]any{"sub": "u"},
		MiddlewarePlugins: map[string]config.MiddlewareConfig{
			"cache-lru": {},
		},
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source:      "db",
				Middlewares: []string{"cache-lru"},
				Endpoints: map[string]config.RestEndpoint{
					"users": {Source: "db", Table: "people"},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	got := httptest.NewRecorder()
	router.ServeHTTP(got, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/5/", nil))
	etag := got.Header().Get("ETag")
	if got.Code != http.StatusOK || etag == "" {
		t.Fatalf("status %d etag %q body %q", got.Code, etag, got.Body.String())
	}

	matched := httptest.NewRecorder()
	matchReq := httptest.NewRequest(http.MethodPatch, "/restapi/v1/users/5/", strings.NewReader(`{"name":"ada"}`))
	matchReq.Header.Set("Content-Type", "application/json")
	matchReq.Header.Set("If-Match", etag)
	router.ServeHTTP(matched, matchReq)
	if matched.Code != http.StatusOK {
		t.Fatalf("status %d body %q", matched.Code, matched.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(matched.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %v body %q", err, matched.Body.String())
	}
	if body["updated"] != float64(1) || plugin.updateCalls != 1 {
		t.Fatalf("body %#v calls %d", body, plugin.updateCalls)
	}
	rev := got.Header().Get("Resource-Version")
	if !strings.HasPrefix(matched.Header().Get("ETag"), `W/"`) || matched.Header().Get("Resource-Version") == "" || matched.Header().Get("Resource-Version") == rev {
		t.Fatalf("etag %q rev %q previous %q", matched.Header().Get("ETag"), matched.Header().Get("Resource-Version"), rev)
	}

	current := httptest.NewRecorder()
	router.ServeHTTP(current, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/5/", nil))
	snapshot := current.Header().Get("ETag")
	if current.Code != http.StatusOK || snapshot == "" || snapshot == etag {
		t.Fatalf("status %d etag %q previous %q", current.Code, snapshot, etag)
	}

	stale := httptest.NewRecorder()
	staleReq := httptest.NewRequest(http.MethodPatch, "/restapi/v1/users/5/", strings.NewReader(`{"name":"ada"}`))
	staleReq.Header.Set("Content-Type", "application/json")
	staleReq.Header.Set("If-Match", `"stale"`)
	router.ServeHTTP(stale, staleReq)
	if stale.Code != http.StatusPreconditionFailed || plugin.updateCalls != 1 {
		t.Fatalf("status %d calls %d body %q", stale.Code, plugin.updateCalls, stale.Body.String())
	}

	again := httptest.NewRecorder()
	router.ServeHTTP(again, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/5/", nil))
	if again.Header().Get("ETag") != snapshot {
		t.Fatalf("etag %q want %q", again.Header().Get("ETag"), snapshot)
	}
}

func TestRestAPI_DestroyNoContent(t *testing.T) {
	plugin := &restRecPlugin{}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})

	req := httptest.NewRequest(http.MethodDelete, "/restapi/v1/users/5/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if w.Body.Len() != 0 {
		t.Fatalf("body %q", w.Body.String())
	}
}

func TestRestAPI_DestroyIfResourceVersion(t *testing.T) {
	cachePlug := cachemw.New(lrustore.NewSimpleCachePlugin())
	if _, err := cachePlug.Init(map[string]any{"ttl": "24h"}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	origMW := MiddlewarePlugins.Load()
	t.Cleanup(func() { MiddlewarePlugins.Store(origMW) })
	MiddlewarePlugins.Store(&map[string]easyrest.MiddlewarePlugin{"cache-lru": cachePlug})

	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(5), "name": "ada"}}}
	cfg := config.Config{
		CheckScope: false,
		AnonClaims: map[string]any{"sub": "u"},
		MiddlewarePlugins: map[string]config.MiddlewareConfig{
			"cache-lru": {},
		},
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source:      "db",
				Middlewares: []string{"cache-lru"},
				Endpoints: map[string]config.RestEndpoint{
					"users": {Source: "db", Table: "people"},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	got := httptest.NewRecorder()
	router.ServeHTTP(got, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/5/", nil))
	rev := got.Header().Get("Resource-Version")
	if got.Code != http.StatusOK || rev == "" {
		t.Fatalf("status %d rev %q body %q", got.Code, rev, got.Body.String())
	}

	stale := httptest.NewRecorder()
	staleReq := httptest.NewRequest(http.MethodDelete, "/restapi/v1/users/5/", nil)
	staleReq.Header.Set("If-Resource-Version", "stale")
	router.ServeHTTP(stale, staleReq)
	if stale.Code != http.StatusPreconditionFailed || plugin.deleteCalls != 0 {
		t.Fatalf("status %d calls %d body %q", stale.Code, plugin.deleteCalls, stale.Body.String())
	}

	matched := httptest.NewRecorder()
	matchReq := httptest.NewRequest(http.MethodDelete, "/restapi/v1/users/5/", nil)
	matchReq.Header.Set("If-Resource-Version", rev)
	router.ServeHTTP(matched, matchReq)
	if matched.Code != http.StatusNoContent || matched.Body.Len() != 0 {
		t.Fatalf("status %d body %q", matched.Code, matched.Body.String())
	}
	if matched.Header().Get("Resource-Version") == "" || matched.Header().Get("Resource-Version") == rev {
		t.Fatalf("rev %q previous %q", matched.Header().Get("Resource-Version"), rev)
	}
}

func TestRestAPI_WriteCacheSkippedWithoutTable(t *testing.T) {
	cachePlug := cachemw.New(lrustore.NewSimpleCachePlugin())
	if _, err := cachePlug.Init(map[string]any{"ttl": "24h"}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	origMW := MiddlewarePlugins.Load()
	t.Cleanup(func() { MiddlewarePlugins.Store(origMW) })
	MiddlewarePlugins.Store(&map[string]easyrest.MiddlewarePlugin{"cache-lru": cachePlug})

	plugin := &restRecPlugin{updated: 1}
	cfg := config.Config{
		CheckScope: false,
		AnonClaims: map[string]any{"sub": "u"},
		MiddlewarePlugins: map[string]config.MiddlewareConfig{
			"cache-lru": {},
		},
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source:      "db",
				Middlewares: []string{"cache-lru"},
				Endpoints: map[string]config.RestEndpoint{
					"notes": {Source: "db"},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	patched := httptest.NewRecorder()
	patchReq := httptest.NewRequest(http.MethodPatch, "/restapi/v1/notes/5/", strings.NewReader(`{"name":"ada"}`))
	patchReq.Header.Set("Content-Type", "application/json")
	patchReq.Header.Set("If-Match", `"stale"`)
	router.ServeHTTP(patched, patchReq)
	if patched.Code != http.StatusOK || patched.Header().Get("ETag") != "" || plugin.updateCalls != 1 {
		t.Fatalf("status %d etag %q calls %d body %q", patched.Code, patched.Header().Get("ETag"), plugin.updateCalls, patched.Body.String())
	}

	deleted := httptest.NewRecorder()
	deleteReq := httptest.NewRequest(http.MethodDelete, "/restapi/v1/notes/5/", nil)
	deleteReq.Header.Set("If-Match", `"stale"`)
	router.ServeHTTP(deleted, deleteReq)
	if deleted.Code != http.StatusNoContent || deleted.Header().Get("ETag") != "" || plugin.deleteCalls != 1 || deleted.Body.Len() != 0 {
		t.Fatalf("status %d etag %q calls %d body %q", deleted.Code, deleted.Header().Get("ETag"), plugin.deleteCalls, deleted.Body.String())
	}
}

func TestRestAPI_PathFiltersList(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{}}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {URL: "orgs/{org_id}/users"},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})
	req := httptest.NewRequest(http.MethodGet, "/restapi/v1/orgs/7/users/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	got, _ := plugin.getWhere["org_id"].(map[string]any)
	if got["="] != "7" {
		t.Fatalf("where %#v", plugin.getWhere)
	}
	if _, ok := plugin.getWhere["city"]; ok {
		t.Fatalf("unexpected query filter %#v", plugin.getWhere)
	}
}

func TestRestAPI_PathWrittenOnCreate(t *testing.T) {
	plugin := &restRecPlugin{}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						URL: "orgs/{org_id}/users",
						Actions: map[string]config.RestAction{
							"create": {Fields: []string{"name", "email"}},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})
	body := `{"name":"a","email":"a@b.c","org_id":"9"}`
	req := httptest.NewRequest(http.MethodPost, "/restapi/v1/orgs/7/users/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if len(plugin.createData) != 1 {
		t.Fatalf("data %#v", plugin.createData)
	}
	row := plugin.createData[0]
	if row["org_id"] != "7" || row["name"] != "a" || row["email"] != "a@b.c" {
		t.Fatalf("row %#v", row)
	}
}

func TestRestAPI_PathFiltersDetail(t *testing.T) {
	plugin := &restRecPlugin{
		rows:    []map[string]any{{"id": "5", "name": "a"}},
		updated: 1,
	}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {URL: "orgs/{org_id}/users"},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	getReq := httptest.NewRequest(http.MethodGet, "/restapi/v1/orgs/7/users/5/", nil)
	getW := httptest.NewRecorder()
	router.ServeHTTP(getW, getReq)
	if getW.Code != http.StatusOK {
		t.Fatalf("retrieve status %d body %q", getW.Code, getW.Body.String())
	}
	assertEqWhere(t, plugin.getWhere, "org_id", "7")
	assertEqWhere(t, plugin.getWhere, "id", "5")

	patchReq := httptest.NewRequest(http.MethodPatch, "/restapi/v1/orgs/7/users/5/", strings.NewReader(`{"name":"b"}`))
	patchReq.Header.Set("Content-Type", "application/json")
	patchW := httptest.NewRecorder()
	router.ServeHTTP(patchW, patchReq)
	if patchW.Code != http.StatusOK {
		t.Fatalf("update status %d body %q", patchW.Code, patchW.Body.String())
	}
	assertEqWhere(t, plugin.updateWhere, "org_id", "7")
	assertEqWhere(t, plugin.updateWhere, "id", "5")

	delReq := httptest.NewRequest(http.MethodDelete, "/restapi/v1/orgs/7/users/5/", nil)
	delW := httptest.NewRecorder()
	router.ServeHTTP(delW, delReq)
	if delW.Code != http.StatusNoContent {
		t.Fatalf("delete status %d body %q", delW.Code, delW.Body.String())
	}
	assertEqWhere(t, plugin.deleteWhere, "org_id", "7")
	assertEqWhere(t, plugin.deleteWhere, "id", "5")
}

func TestRestAPI_ActionTable(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Table: "users",
						Actions: map[string]config.RestAction{
							"list":   {},
							"create": {Table: "user_inbox"},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	listReq := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	listW := httptest.NewRecorder()
	router.ServeHTTP(listW, listReq)
	if plugin.getTable != "users" {
		t.Fatalf("list table %q", plugin.getTable)
	}

	createReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"name":"a"}`))
	createReq.Header.Set("Content-Type", "application/json")
	createW := httptest.NewRecorder()
	router.ServeHTTP(createW, createReq)
	if createW.Code != http.StatusCreated {
		t.Fatalf("status %d body %q", createW.Code, createW.Body.String())
	}
	if plugin.createTable != "user_inbox" {
		t.Fatalf("create table %q", plugin.createTable)
	}
}

func TestRestAPI_ExtraField(t *testing.T) {
	plugin := &restRecPlugin{}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Actions: map[string]config.RestAction{
							"create": {
								Fields: []string{"name", "email"},
								ExtraFields: map[string]any{
									"note": map[string]any{"type": "string"},
								},
							},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	okReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"name":"a","email":"a@b.c","note":"hi"}`))
	okReq.Header.Set("Content-Type", "application/json")
	okW := httptest.NewRecorder()
	router.ServeHTTP(okW, okReq)
	if okW.Code != http.StatusCreated {
		t.Fatalf("status %d body %q", okW.Code, okW.Body.String())
	}
	if plugin.createData[0]["note"] != "hi" {
		t.Fatalf("row %#v", plugin.createData[0])
	}

	badReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"name":"a","rank":"x"}`))
	badReq.Header.Set("Content-Type", "application/json")
	badW := httptest.NewRecorder()
	router.ServeHTTP(badW, badReq)
	if badW.Code != http.StatusBadRequest {
		t.Fatalf("unknown key status %d body %q", badW.Code, badW.Body.String())
	}
}

func TestRestAPI_ReadOnlyRejected(t *testing.T) {
	plugin := &restRecPlugin{}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						URL: "orgs/{org_id}/users",
						Actions: map[string]config.RestAction{
							"create": {
								Fields: []string{"name"},
								ExtraFields: map[string]any{
									"note":   map[string]any{"type": "string", "readOnly": true},
									"org_id": map[string]any{"type": "string", "readOnly": true},
								},
							},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	notedReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/orgs/7/users/", strings.NewReader(`{"name":"a","note":"x"}`))
	notedReq.Header.Set("Content-Type", "application/json")
	notedW := httptest.NewRecorder()
	router.ServeHTTP(notedW, notedReq)
	if notedW.Code != http.StatusCreated {
		t.Fatalf("status %d body %q", notedW.Code, notedW.Body.String())
	}
	if _, ok := plugin.createData[0]["note"]; ok || plugin.createData[0]["org_id"] != "7" || plugin.createData[0]["name"] != "a" {
		t.Fatalf("row %#v", plugin.createData[0])
	}

	okReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/orgs/7/users/", strings.NewReader(`{"name":"a"}`))
	okReq.Header.Set("Content-Type", "application/json")
	okW := httptest.NewRecorder()
	router.ServeHTTP(okW, okReq)
	if okW.Code != http.StatusCreated {
		t.Fatalf("status %d body %q", okW.Code, okW.Body.String())
	}
	if plugin.createData[0]["org_id"] != "7" {
		t.Fatalf("row %#v", plugin.createData[0])
	}
}

func TestRestAPI_SwaggerRoot(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{}}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})
	before := plugin.schemaCalls

	req := httptest.NewRequest(http.MethodGet, "/restapi/v1/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	var spec map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatalf("decode %v body %q", err, w.Body.String())
	}
	if spec["swagger"] != "2.0" || spec["basePath"] != "/restapi/v1" {
		t.Fatalf("spec %#v", spec)
	}
	if plugin.schemaCalls != before {
		t.Fatalf("GetSchema calls %d before %d", plugin.schemaCalls, before)
	}
}

func TestRestAPI_SwaggerTypes(t *testing.T) {
	plugin := &restRecPlugin{
		schema: map[string]any{
			"tables": map[string]any{
				"users": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"name":  map[string]any{"type": "integer"},
						"email": map[string]any{"type": "string"},
					},
				},
			},
		},
	}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Actions: map[string]config.RestAction{
							"create": {
								Fields: []string{"name"},
								ExtraFields: map[string]any{
									"note": map[string]any{"type": "string"},
								},
							},
						},
					},
					"invoice_lines": {
						Table: "add_invoice_line",
						Actions: map[string]config.RestAction{
							"create": {
								Type: "func",
								ExtraFields: map[string]any{
									"sku": map[string]any{"type": "string"},
									"qty": map[string]any{"type": "integer", "format": "int32"},
								},
							},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})
	req := httptest.NewRequest(http.MethodGet, "/restapi/v1/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	var spec map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	defs, _ := spec["definitions"].(map[string]any)
	userCreate, _ := defs["users_create"].(map[string]any)
	userProps, _ := userCreate["properties"].(map[string]any)
	nameProp, _ := userProps["name"].(map[string]any)
	noteProp, _ := userProps["note"].(map[string]any)
	if nameProp["type"] != "integer" || noteProp["type"] != "string" {
		t.Fatalf("users create %#v", userCreate)
	}
	if _, ok := userProps["email"]; ok {
		t.Fatalf("email should be omitted %#v", userProps)
	}
	funcCreate, _ := defs["invoice_lines_create"].(map[string]any)
	funcProps, _ := funcCreate["properties"].(map[string]any)
	sku, _ := funcProps["sku"].(map[string]any)
	if sku["type"] != "string" || len(funcProps) != 2 {
		t.Fatalf("func create %#v", funcCreate)
	}
	if _, ok := funcProps["name"]; ok {
		t.Fatalf("func schema included table columns %#v", funcProps)
	}
}

func TestRestAPI_SwaggerText(t *testing.T) {
	plugin := &restRecPlugin{}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						URL:         "orgs/{org_id}/users",
						Description: "Org users",
						Actions: map[string]config.RestAction{
							"list":   {Description: "List users in an org"},
							"create": {Description: "Create a user in the org"},
						},
					},
					"orders": {
						Description: "Orders",
						Actions:     map[string]config.RestAction{"list": {}},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})
	req := httptest.NewRequest(http.MethodGet, "/restapi/v1/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	var spec map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths, _ := spec["paths"].(map[string]any)
	users, _ := paths["/orgs/{org_id}/users/"].(map[string]any)
	list, _ := users["get"].(map[string]any)
	create, _ := users["post"].(map[string]any)
	if list["description"] != "List users in an org" {
		t.Fatalf("list %#v", list)
	}
	if create["description"] != "Create a user in the org" {
		t.Fatalf("create %#v", create)
	}
	if create["x-label"] != "New User" {
		t.Fatalf("label %#v", create)
	}
	orders, _ := paths["/orders/"].(map[string]any)
	orderList, _ := orders["get"].(map[string]any)
	if orderList["description"] != "Orders" {
		t.Fatalf("orders %#v", orderList)
	}
}

func TestRestAPI_FuncCreate(t *testing.T) {
	plugin := &restRecPlugin{}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"invoice_lines": {
						URL:   "invoices/{invoice_id}/lines",
						Table: "add_invoice_line",
						Actions: map[string]config.RestAction{
							"create": {
								Type: "func",
								ExtraFields: map[string]any{
									"sku": map[string]any{"type": "string"},
									"qty": map[string]any{"type": "integer", "format": "int32"},
								},
							},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})
	req := httptest.NewRequest(http.MethodPost, "/restapi/v1/invoices/3/lines/", strings.NewReader(`{"sku":"a","qty":1}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if plugin.creates != 0 {
		t.Fatalf("TableCreate calls %d", plugin.creates)
	}
	if plugin.funcName != "add_invoice_line" {
		t.Fatalf("func %q data %#v", plugin.funcName, plugin.funcData)
	}
	if plugin.funcData["invoice_id"] != "3" || plugin.funcData["sku"] != "a" || plugin.funcData["qty"] != float64(1) {
		t.Fatalf("data %#v", plugin.funcData)
	}
}

func TestRestAPI_DetailActionCallsFunction(t *testing.T) {
	plugin := &restRecPlugin{}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						DetailActions: map[string]config.RestCallAction{
							"archive": {
								Func: "archive_user",
								Fields: map[string]any{
									"reason": map[string]any{"type": "string"},
								},
							},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})
	req := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/5/archive/", strings.NewReader(`{"reason":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if plugin.creates != 0 {
		t.Fatalf("TableCreate calls %d", plugin.creates)
	}
	if plugin.funcName != "archive_user" || plugin.funcData["id"] != "5" || plugin.funcData["reason"] != "x" {
		t.Fatalf("func %q data %#v", plugin.funcName, plugin.funcData)
	}
}

func TestRestAPI_DetailActionReadOnly(t *testing.T) {
	plugin := &restRecPlugin{funcResult: map[string]any{"reason": "x", "done": true}}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						DetailActions: map[string]config.RestCallAction{
							"archive": {
								Func: "archive_user",
								Fields: map[string]any{
									"reason": map[string]any{"type": "string"},
									"done":   map[string]any{"type": "boolean", "readOnly": true},
								},
							},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	withDone := httptest.NewRecorder()
	withDoneReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/5/archive/", strings.NewReader(`{"reason":"x","done":true}`))
	withDoneReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(withDone, withDoneReq)
	if withDone.Code != http.StatusOK || plugin.funcName != "archive_user" {
		t.Fatalf("status %d func %q body %q", withDone.Code, plugin.funcName, withDone.Body.String())
	}
	if _, ok := plugin.funcData["done"]; ok {
		t.Fatalf("data %#v", plugin.funcData)
	}
	var sent map[string]any
	if err := json.Unmarshal(withDone.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode %v body %q", err, withDone.Body.String())
	}
	if sent["done"] != true {
		t.Fatalf("body %#v", sent)
	}

	okW := httptest.NewRecorder()
	okReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/5/archive/", strings.NewReader(`{"reason":"x"}`))
	okReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(okW, okReq)
	if okW.Code != http.StatusOK {
		t.Fatalf("status %d body %q", okW.Code, okW.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(okW.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %v body %q", err, okW.Body.String())
	}
	if body["done"] != true {
		t.Fatalf("body %#v", body)
	}
}

func TestRestAPI_DetailActionWriteOnly(t *testing.T) {
	plugin := &restRecPlugin{funcResult: map[string]any{"reason": "x", "token": "secret"}}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						DetailActions: map[string]config.RestCallAction{
							"archive": {
								Func: "archive_user",
								Fields: map[string]any{
									"reason": map[string]any{"type": "string"},
									"token":  map[string]any{"type": "string", "writeOnly": true},
								},
							},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})
	req := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/5/archive/", strings.NewReader(`{"reason":"x","token":"secret"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if plugin.funcData["token"] != "secret" {
		t.Fatalf("data %#v", plugin.funcData)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %v body %q", err, w.Body.String())
	}
	if _, ok := body["token"]; ok || body["reason"] != "x" {
		t.Fatalf("body %#v", body)
	}

	raw := &restRecPlugin{funcResult: "nope"}
	rawRouter := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": raw})
	rawReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/5/archive/", strings.NewReader(`{"reason":"x","token":"secret"}`))
	rawReq.Header.Set("Content-Type", "application/json")
	rawW := httptest.NewRecorder()
	rawRouter.ServeHTTP(rawW, rawReq)
	if rawW.Code != http.StatusInternalServerError {
		t.Fatalf("status %d body %q", rawW.Code, rawW.Body.String())
	}
}

func TestRestAPI_DetailActionRejectsPrimaryKey(t *testing.T) {
	plugin := &restRecPlugin{}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						DetailActions: map[string]config.RestCallAction{
							"bad": {
								Func: "takes_id",
								Fields: map[string]any{
									"id": map[string]any{"type": "string"},
								},
							},
							"archive": {
								Func: "archive_user",
								Fields: map[string]any{
									"reason": map[string]any{"type": "string"},
								},
							},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	missing := httptest.NewRecorder()
	router.ServeHTTP(missing, httptest.NewRequest(http.MethodPost, "/restapi/v1/users/5/bad/", strings.NewReader(`{}`)))
	if missing.Code != http.StatusNotFound || plugin.funcName != "" {
		t.Fatalf("status %d func %q body %q", missing.Code, plugin.funcName, missing.Body.String())
	}

	bad := httptest.NewRecorder()
	badReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/5/archive/", strings.NewReader(`{"id":"9","reason":"x"}`))
	badReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(bad, badReq)
	if bad.Code != http.StatusBadRequest || plugin.funcName != "" {
		t.Fatalf("status %d func %q body %q", bad.Code, plugin.funcName, bad.Body.String())
	}
}

func TestRestAPI_ListActionOmitsPrimaryKey(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(9), "name": "ada"}}}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						URL: "orgs/{org_id}/users",
						ListActions: map[string]config.RestCallAction{
							"export": {
								Func: "export_users",
								Fields: map[string]any{
									"format": map[string]any{"type": "string"},
								},
							},
						},
						DetailActions: map[string]config.RestCallAction{
							"archive": {
								Func: "archive_user",
								Fields: map[string]any{
									"reason": map[string]any{"type": "string"},
								},
							},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	exported := httptest.NewRecorder()
	exportReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/orgs/7/users/export/", strings.NewReader(`{"format":"csv"}`))
	exportReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(exported, exportReq)
	if exported.Code != http.StatusOK {
		t.Fatalf("status %d body %q", exported.Code, exported.Body.String())
	}
	if _, ok := plugin.funcData["id"]; ok || plugin.funcName != "export_users" || plugin.funcData["org_id"] != "7" || plugin.funcData["format"] != "csv" {
		t.Fatalf("func %q data %#v", plugin.funcName, plugin.funcData)
	}

	archived := httptest.NewRecorder()
	archiveReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/orgs/7/users/9/archive/", strings.NewReader(`{"reason":"x"}`))
	archiveReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(archived, archiveReq)
	if archived.Code != http.StatusOK {
		t.Fatalf("status %d body %q", archived.Code, archived.Body.String())
	}
	if plugin.funcName != "archive_user" || plugin.funcData["org_id"] != "7" || plugin.funcData["id"] != "9" || plugin.funcData["reason"] != "x" {
		t.Fatalf("func %q data %#v", plugin.funcName, plugin.funcData)
	}

	got := httptest.NewRecorder()
	router.ServeHTTP(got, httptest.NewRequest(http.MethodGet, "/restapi/v1/orgs/7/users/9/", nil))
	if got.Code != http.StatusOK {
		t.Fatalf("status %d body %q", got.Code, got.Body.String())
	}
	var row map[string]any
	if err := json.Unmarshal(got.Body.Bytes(), &row); err != nil {
		t.Fatalf("decode %v body %q", err, got.Body.String())
	}
	if row["name"] != "ada" {
		t.Fatalf("row %#v", row)
	}
}

func TestRestAPI_ActionSwagger(t *testing.T) {
	plugin := &restRecPlugin{}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						DetailActions: map[string]config.RestCallAction{
							"archive": {Func: "archive_user", Fields: restActionFields()},
						},
						ListActions: map[string]config.RestCallAction{
							"export": {Func: "export_users", Fields: restActionFields()},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/restapi/v1/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	var spec map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths, _ := spec["paths"].(map[string]any)
	restAssertCallSchema(t, paths, "/users/{id}/archive/")
	restAssertCallSchema(t, paths, "/users/export/")
}

func restStateFields() map[string]any {
	return map[string]any{
		"name":  map[string]any{"type": "string"},
		"token": map[string]any{"type": "string", "writeOnly": true},
	}
}

func restActionFields() map[string]any {
	return map[string]any{
		"reason": map[string]any{"type": "string"},
		"done":   map[string]any{"type": "boolean", "readOnly": true},
		"token":  map[string]any{"type": "string", "writeOnly": true},
	}
}

func restAssertCallSchema(t *testing.T, paths map[string]any, path string) {
	t.Helper()
	item, _ := paths[path].(map[string]any)
	op, _ := item["post"].(map[string]any)
	params, _ := op["parameters"].([]any)
	if len(params) == 0 {
		t.Fatalf("%s parameters %#v", path, op)
	}
	bodyParam, _ := params[0].(map[string]any)
	schema, _ := bodyParam["schema"].(map[string]any)
	reqProps, _ := schema["properties"].(map[string]any)
	if reqProps["reason"] == nil || reqProps["token"] == nil || reqProps["done"] != nil {
		t.Fatalf("%s request %#v", path, reqProps)
	}
	responses, _ := op["responses"].(map[string]any)
	ok, _ := responses["200"].(map[string]any)
	respSchema, _ := ok["schema"].(map[string]any)
	respProps, _ := respSchema["properties"].(map[string]any)
	if respProps["reason"] == nil || respProps["done"] == nil || respProps["token"] != nil {
		t.Fatalf("%s response %#v", path, respProps)
	}
}

func TestRestAPI_StateFuncGet(t *testing.T) {
	plugin := &restRecPlugin{funcResult: map[string]any{"name": "ada", "token": "secret"}}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						StateActions: map[string]config.RestStateAction{
							"settings": {Func: "load_settings", Fields: restStateFields()},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/settings/", nil))
	if w.Code != http.StatusOK || plugin.funcName != "load_settings" {
		t.Fatalf("status %d func %q body %q", w.Code, plugin.funcName, w.Body.String())
	}
	if _, ok := plugin.funcData["id"]; ok || len(plugin.funcData) != 0 {
		t.Fatalf("path data %#v", plugin.funcData)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %v body %q", err, w.Body.String())
	}
	if body["name"] != "ada" || body["token"] != nil {
		t.Fatalf("body %#v", body)
	}
}

func TestRestAPI_StateFuncPut(t *testing.T) {
	plugin := &restRecPlugin{funcResult: map[string]any{
		"name":  "ada",
		"note":  "kept",
		"token": "secret",
	}}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						URL: "orgs/{org_id}/users",
						StateActions: map[string]config.RestStateAction{
							"settings": {
								Func: "save_settings",
								Fields: map[string]any{
									"name":  map[string]any{"type": "string"},
									"note":  map[string]any{"type": "string", "readOnly": true},
									"token": map[string]any{"type": "string", "writeOnly": true},
								},
							},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	unknown := httptest.NewRequest(http.MethodPut, "/restapi/v1/orgs/7/users/settings/", strings.NewReader(`{"name":"ada","extra":"no"}`))
	unknown.Header.Set("Content-Type", "application/json")
	unknownW := httptest.NewRecorder()
	router.ServeHTTP(unknownW, unknown)
	if unknownW.Code != http.StatusBadRequest || plugin.funcName != "" {
		t.Fatalf("unknown status %d func %q body %q", unknownW.Code, plugin.funcName, unknownW.Body.String())
	}

	req := httptest.NewRequest(http.MethodPut, "/restapi/v1/orgs/7/users/settings/", strings.NewReader(`{"name":"ada","note":"x","token":"s"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK || plugin.funcName != "save_settings" {
		t.Fatalf("status %d func %q body %q", w.Code, plugin.funcName, w.Body.String())
	}
	if plugin.funcData["name"] != "ada" || plugin.funcData["token"] != "s" || plugin.funcData["org_id"] != "7" {
		t.Fatalf("call %#v", plugin.funcData)
	}
	if _, ok := plugin.funcData["note"]; ok {
		t.Fatalf("readOnly sent %#v", plugin.funcData)
	}
	if _, ok := plugin.funcData["id"]; ok {
		t.Fatalf("id sent %#v", plugin.funcData)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %v body %q", err, w.Body.String())
	}
	if body["name"] != "ada" || body["note"] != "kept" || body["token"] != nil {
		t.Fatalf("body %#v", body)
	}
}

func TestRestAPI_StateGet(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{
		"profile": map[string]any{"name": "ada", "token": "secret"},
	}}}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						StateActions: map[string]config.RestStateAction{
							"profile": {
								Table:       "user_profile",
								SourceField: "profile",
								Fields:      restStateFields(),
							},
						},
					},
					"notes": {
						Table: "people",
						StateActions: map[string]config.RestStateAction{
							"profile": {
								SourceField: "profile",
								Fields:      restStateFields(),
							},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	notes := httptest.NewRecorder()
	router.ServeHTTP(notes, httptest.NewRequest(http.MethodGet, "/restapi/v1/notes/5/profile/", nil))
	if notes.Code != http.StatusOK || plugin.getTable != "people" {
		t.Fatalf("status %d table %q body %q", notes.Code, plugin.getTable, notes.Body.String())
	}

	users := httptest.NewRecorder()
	router.ServeHTTP(users, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/5/profile/", nil))
	if users.Code != http.StatusOK || plugin.getTable != "user_profile" || len(plugin.getSelect) != 1 || plugin.getSelect[0] != "profile" {
		t.Fatalf("status %d table %q select %#v body %q", users.Code, plugin.getTable, plugin.getSelect, users.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(users.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %v body %q", err, users.Body.String())
	}
	if body["name"] != "ada" || body["token"] != nil {
		t.Fatalf("body %#v", body)
	}

	empty := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	missing := httptest.NewRecorder()
	empty.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/5/profile/", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("status %d body %q", missing.Code, missing.Body.String())
	}
}

func TestRestAPI_StatePutReplacesField(t *testing.T) {
	plugin := &restRecPlugin{updated: 1}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						StateActions: map[string]config.RestStateAction{
							"profile": {
								Table:       "user_profile",
								SourceField: "profile",
								Fields: map[string]any{
									"name":  map[string]any{"type": "string"},
									"note":  map[string]any{"type": "string", "readOnly": true},
									"token": map[string]any{"type": "string", "writeOnly": true},
								},
							},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	noted := httptest.NewRecorder()
	notedReq := httptest.NewRequest(http.MethodPut, "/restapi/v1/users/5/profile/", strings.NewReader(`{"name":"ada","note":"x"}`))
	notedReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(noted, notedReq)
	if noted.Code != http.StatusOK || plugin.updateCalls != 1 {
		t.Fatalf("status %d calls %d body %q", noted.Code, plugin.updateCalls, noted.Body.String())
	}
	notedColumn, _ := plugin.updateData["profile"].(map[string]any)
	if notedColumn["name"] != "ada" || notedColumn["note"] != nil {
		t.Fatalf("column %#v", notedColumn)
	}

	first := httptest.NewRecorder()
	firstReq := httptest.NewRequest(http.MethodPut, "/restapi/v1/users/5/profile/", strings.NewReader(`{"name":"ada","token":"s"}`))
	firstReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(first, firstReq)
	if first.Code != http.StatusOK {
		t.Fatalf("status %d body %q", first.Code, first.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(first.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %v body %q", err, first.Body.String())
	}
	if body["updated"] != float64(1) || plugin.updateTable != "user_profile" || plugin.updateData["profile"] == nil {
		t.Fatalf("body %#v table %q data %#v", body, plugin.updateTable, plugin.updateData)
	}

	second := httptest.NewRecorder()
	secondReq := httptest.NewRequest(http.MethodPut, "/restapi/v1/users/5/profile/", strings.NewReader(`{"name":"bea"}`))
	secondReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(second, secondReq)
	if second.Code != http.StatusOK {
		t.Fatalf("status %d body %q", second.Code, second.Body.String())
	}
	column, _ := plugin.updateData["profile"].(map[string]any)
	if column["name"] != "bea" || column["token"] != nil || column["note"] != nil || plugin.updateCalls != 3 {
		t.Fatalf("column %#v calls %d", column, plugin.updateCalls)
	}
}

func TestRestAPI_StateSwagger(t *testing.T) {
	plugin := &restRecPlugin{}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						StateActions: map[string]config.RestStateAction{
							"profile": {SourceField: "profile", Fields: restActionFields()},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/restapi/v1/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	var spec map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths, _ := spec["paths"].(map[string]any)
	item, _ := paths["/users/{id}/profile/"].(map[string]any)
	getOp, _ := item["get"].(map[string]any)
	responses, _ := getOp["responses"].(map[string]any)
	ok, _ := responses["200"].(map[string]any)
	schema, _ := ok["schema"].(map[string]any)
	props, _ := schema["properties"].(map[string]any)
	if props["reason"] == nil || props["done"] == nil || props["token"] != nil {
		t.Fatalf("get %#v", props)
	}
	putOp, _ := item["put"].(map[string]any)
	params, _ := putOp["parameters"].([]any)
	if len(params) == 0 {
		t.Fatalf("put %#v", putOp)
	}
	bodyParam, _ := params[0].(map[string]any)
	putSchema, _ := bodyParam["schema"].(map[string]any)
	putProps, _ := putSchema["properties"].(map[string]any)
	if putProps["reason"] == nil || putProps["token"] == nil || putProps["done"] != nil {
		t.Fatalf("put %#v", putProps)
	}
}

func TestRestAPI_StateFuncSwagger(t *testing.T) {
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						StateActions: map[string]config.RestStateAction{
							"settings": {Func: "load_settings", Fields: restActionFields()},
						},
					},
				},
			},
		},
	}
	spec := restSpec(t, serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}}), "/restapi/v1/")
	paths, _ := spec["paths"].(map[string]any)
	if _, ok := paths["/users/{id}/settings/"]; ok {
		t.Fatalf("detail path present %#v", paths["/users/{id}/settings/"])
	}
	item, _ := paths["/users/settings/"].(map[string]any)
	getOp, _ := item["get"].(map[string]any)
	responses, _ := getOp["responses"].(map[string]any)
	ok, _ := responses["200"].(map[string]any)
	schema, _ := ok["schema"].(map[string]any)
	props, _ := schema["properties"].(map[string]any)
	if props["reason"] == nil || props["done"] == nil || props["token"] != nil {
		t.Fatalf("get %#v", props)
	}
	putOp, _ := item["put"].(map[string]any)
	params, _ := putOp["parameters"].([]any)
	if len(params) == 0 {
		t.Fatalf("put %#v", putOp)
	}
	bodyParam, _ := params[0].(map[string]any)
	putSchema, _ := bodyParam["schema"].(map[string]any)
	putProps, _ := putSchema["properties"].(map[string]any)
	if putProps["reason"] == nil || putProps["token"] == nil || putProps["done"] != nil {
		t.Fatalf("put %#v", putProps)
	}
}

func TestRestAPI_ActionScope(t *testing.T) {
	cfg := func(scope string) config.Config {
		return config.Config{
			CheckScope: true,
			AnonClaims: map[string]any{"sub": "u", "scope": scope},
			RestAPI: map[string]config.RestAPIApp{
				"v1": {
					Source: "db",
					Endpoints: map[string]config.RestEndpoint{
						"users": {
							DetailActions: map[string]config.RestCallAction{
								"archive": {Func: "archive_user", Fields: map[string]any{"reason": map[string]any{"type": "string"}}},
							},
							ListActions: map[string]config.RestCallAction{
								"export": {Func: "export_users", Fields: map[string]any{"format": map[string]any{"type": "string"}}},
							},
							StateActions: map[string]config.RestStateAction{
								"profile": {SourceField: "profile", Fields: map[string]any{"name": map[string]any{"type": "string"}}},
							},
						},
					},
				},
			},
		}
	}
	readPlugin := &restRecPlugin{rows: []map[string]any{{"profile": map[string]any{"name": "ada"}}}, updated: 1}
	readRouter := serveRest(t, cfg("users-read"), map[string]easyrest.DBPlugin{"db": readPlugin})
	got := httptest.NewRecorder()
	readRouter.ServeHTTP(got, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/5/profile/", nil))
	if got.Code != http.StatusOK {
		t.Fatalf("get status %d body %q", got.Code, got.Body.String())
	}
	for _, call := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/restapi/v1/users/5/archive/", `{"reason":"x"}`},
		{http.MethodPost, "/restapi/v1/users/export/", `{"format":"csv"}`},
		{http.MethodPut, "/restapi/v1/users/5/profile/", `{"name":"ada"}`},
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(call.method, call.path, strings.NewReader(call.body))
		req.Header.Set("Content-Type", "application/json")
		readRouter.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s %s status %d body %q", call.method, call.path, w.Code, w.Body.String())
		}
	}

	writePlugin := &restRecPlugin{rows: []map[string]any{{"profile": map[string]any{"name": "ada"}}}, updated: 1}
	writeRouter := serveRest(t, cfg("users-write"), map[string]easyrest.DBPlugin{"db": writePlugin})
	denied := httptest.NewRecorder()
	writeRouter.ServeHTTP(denied, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/5/profile/", nil))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("get with write status %d", denied.Code)
	}
	archive := httptest.NewRecorder()
	archiveReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/5/archive/", strings.NewReader(`{"reason":"x"}`))
	archiveReq.Header.Set("Content-Type", "application/json")
	writeRouter.ServeHTTP(archive, archiveReq)
	if archive.Code != http.StatusOK || writePlugin.funcName != "archive_user" {
		t.Fatalf("archive status %d func %q body %q", archive.Code, writePlugin.funcName, archive.Body.String())
	}
	export := httptest.NewRecorder()
	exportReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/export/", strings.NewReader(`{"format":"csv"}`))
	exportReq.Header.Set("Content-Type", "application/json")
	writeRouter.ServeHTTP(export, exportReq)
	if export.Code != http.StatusOK || writePlugin.funcName != "export_users" {
		t.Fatalf("export status %d func %q body %q", export.Code, writePlugin.funcName, export.Body.String())
	}
	put := httptest.NewRecorder()
	putReq := httptest.NewRequest(http.MethodPut, "/restapi/v1/users/5/profile/", strings.NewReader(`{"name":"ada"}`))
	putReq.Header.Set("Content-Type", "application/json")
	writeRouter.ServeHTTP(put, putReq)
	if put.Code != http.StatusOK || writePlugin.updateCalls != 1 {
		t.Fatalf("put status %d calls %d body %q", put.Code, writePlugin.updateCalls, put.Body.String())
	}
}

func TestRestAPI_ScopeUsesEndpointName(t *testing.T) {
	cfg := func(scope string) config.Config {
		return config.Config{
			CheckScope: true,
			AnonClaims: map[string]any{"sub": "u", "scope": scope},
			RestAPI: map[string]config.RestAPIApp{
				"v1": {
					Source: "db",
					Endpoints: map[string]config.RestEndpoint{
						"users": {
							Actions: map[string]config.RestAction{
								"list":   {},
								"create": {Table: "user_inbox"},
							},
						},
					},
				},
			},
		}
	}
	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}

	readRouter := serveRest(t, cfg("users-read"), map[string]easyrest.DBPlugin{"db": plugin})
	listW := httptest.NewRecorder()
	readRouter.ServeHTTP(listW, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if listW.Code != http.StatusOK {
		t.Fatalf("list status %d body %q", listW.Code, listW.Body.String())
	}
	createW := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"name":"a"}`))
	createReq.Header.Set("Content-Type", "application/json")
	readRouter.ServeHTTP(createW, createReq)
	if createW.Code != http.StatusForbidden {
		t.Fatalf("create with read status %d", createW.Code)
	}

	writePlugin := &restRecPlugin{}
	writeRouter := serveRest(t, cfg("users-write"), map[string]easyrest.DBPlugin{"db": writePlugin})
	writeList := httptest.NewRecorder()
	writeRouter.ServeHTTP(writeList, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if writeList.Code != http.StatusForbidden {
		t.Fatalf("list with write status %d", writeList.Code)
	}
	writeCreate := httptest.NewRecorder()
	writeReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"name":"a"}`))
	writeReq.Header.Set("Content-Type", "application/json")
	writeRouter.ServeHTTP(writeCreate, writeReq)
	if writeCreate.Code != http.StatusCreated {
		t.Fatalf("create with write status %d body %q", writeCreate.Code, writeCreate.Body.String())
	}
	if writePlugin.createTable != "user_inbox" {
		t.Fatalf("table %q", writePlugin.createTable)
	}

	other := serveRest(t, cfg("orders-read"), map[string]easyrest.DBPlugin{"db": plugin})
	otherW := httptest.NewRecorder()
	other.ServeHTTP(otherW, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if otherW.Code != http.StatusForbidden {
		t.Fatalf("orders-read status %d", otherW.Code)
	}
}

func TestRestAPI_GlobalScope(t *testing.T) {
	cfg := func(scope string) config.Config {
		return config.Config{
			CheckScope: true,
			AnonClaims: map[string]any{"sub": "u", "scope": scope},
			RestAPI: map[string]config.RestAPIApp{
				"v1": {Source: "db", Endpoints: map[string]config.RestEndpoint{"users": {}}},
			},
		}
	}
	readRouter := serveRest(t, cfg("read"), map[string]easyrest.DBPlugin{"db": &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}})
	listW := httptest.NewRecorder()
	readRouter.ServeHTTP(listW, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if listW.Code != http.StatusOK {
		t.Fatalf("read list %d body %q", listW.Code, listW.Body.String())
	}
	createW := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"name":"a"}`))
	createReq.Header.Set("Content-Type", "application/json")
	readRouter.ServeHTTP(createW, createReq)
	if createW.Code != http.StatusForbidden {
		t.Fatalf("read create %d", createW.Code)
	}

	writeRouter := serveRest(t, cfg("write"), map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	writeList := httptest.NewRecorder()
	writeRouter.ServeHTTP(writeList, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if writeList.Code != http.StatusForbidden {
		t.Fatalf("write list %d", writeList.Code)
	}
	writeCreate := httptest.NewRecorder()
	writeReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"name":"a"}`))
	writeReq.Header.Set("Content-Type", "application/json")
	writeRouter.ServeHTTP(writeCreate, writeReq)
	if writeCreate.Code != http.StatusCreated {
		t.Fatalf("write create %d body %q", writeCreate.Code, writeCreate.Body.String())
	}

	exact := serveRest(t, cfg("users-read"), map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	exactW := httptest.NewRecorder()
	exactReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"name":"a"}`))
	exactReq.Header.Set("Content-Type", "application/json")
	exact.ServeHTTP(exactW, exactReq)
	if exactW.Code != http.StatusForbidden {
		t.Fatalf("users-read create %d", exactW.Code)
	}
}

func TestRestAPI_PublicSkipsScope(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}
	endpointPublic := config.Config{
		CheckScope: true,
		AnonClaims: map[string]any{"sub": "u", "scope": "other"},
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {Public: true},
				},
			},
		},
	}
	router := serveRest(t, endpointPublic, map[string]easyrest.DBPlugin{"db": plugin})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("endpoint public %d body %q", w.Code, w.Body.String())
	}

	apiPublic := endpointPublic
	apiPublic.RestAPI = map[string]config.RestAPIApp{
		"v1": {
			Source: "db",
			Public: true,
			Endpoints: map[string]config.RestEndpoint{
				"users": {Public: false},
			},
		},
	}
	apiRouter := serveRest(t, apiPublic, map[string]easyrest.DBPlugin{"db": plugin})
	apiW := httptest.NewRecorder()
	apiRouter.ServeHTTP(apiW, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if apiW.Code != http.StatusOK {
		t.Fatalf("api public %d body %q", apiW.Code, apiW.Body.String())
	}

	unauth := apiPublic
	unauth.AnonClaims = map[string]any{}
	unauthRouter := serveRest(t, unauth, map[string]easyrest.DBPlugin{"db": plugin})
	unauthW := httptest.NewRecorder()
	unauthRouter.ServeHTTP(unauthW, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if unauthW.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth %d body %q", unauthW.Code, unauthW.Body.String())
	}
}

func TestRestAPI_ListCache(t *testing.T) {
	cachePlug := cachemw.New(lrustore.NewSimpleCachePlugin())
	if _, err := cachePlug.Init(map[string]any{"ttl": "24h"}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	origMW := MiddlewarePlugins.Load()
	t.Cleanup(func() { MiddlewarePlugins.Store(origMW) })
	MiddlewarePlugins.Store(&map[string]easyrest.MiddlewarePlugin{"cache-lru": cachePlug})

	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}
	cfg := config.Config{
		CheckScope: false,
		AnonClaims: map[string]any{"sub": "u"},
		MiddlewarePlugins: map[string]config.MiddlewareConfig{
			"cache-lru": {},
		},
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source:      "db",
				Middlewares: []string{"cache-lru"},
				Endpoints: map[string]config.RestEndpoint{
					"users": {Source: "db", Table: "people"},
					"notes": {Source: "db"},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	first := httptest.NewRecorder()
	router.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	etag := first.Header().Get("ETag")
	if first.Code != http.StatusOK || etag == "" {
		t.Fatalf("status %d etag %q body %q", first.Code, etag, first.Body.String())
	}
	calls := plugin.getCalls

	second := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	req.Header.Set("If-None-Match", etag)
	router.ServeHTTP(second, req)
	if second.Code != http.StatusNotModified || second.Header().Get("ETag") != etag {
		t.Fatalf("status %d etag %q body %q", second.Code, second.Header().Get("ETag"), second.Body.String())
	}
	if plugin.getCalls != calls {
		t.Fatalf("calls %d want %d", plugin.getCalls, calls)
	}

	plain := httptest.NewRecorder()
	router.ServeHTTP(plain, httptest.NewRequest(http.MethodGet, "/restapi/v1/notes/", nil))
	if plain.Code != http.StatusOK || plain.Header().Get("ETag") != "" {
		t.Fatalf("status %d etag %q body %q", plain.Code, plain.Header().Get("ETag"), plain.Body.String())
	}
	if plugin.getTable != "notes" {
		t.Fatalf("table %q", plugin.getTable)
	}
}

func TestRestAPI_RetrieveCache(t *testing.T) {
	cachePlug := cachemw.New(lrustore.NewSimpleCachePlugin())
	if _, err := cachePlug.Init(map[string]any{"ttl": "24h"}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	origMW := MiddlewarePlugins.Load()
	t.Cleanup(func() { MiddlewarePlugins.Store(origMW) })
	MiddlewarePlugins.Store(&map[string]easyrest.MiddlewarePlugin{"cache-lru": cachePlug})

	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(5), "name": "ada"}}}
	cfg := config.Config{
		CheckScope: false,
		AnonClaims: map[string]any{"sub": "u"},
		MiddlewarePlugins: map[string]config.MiddlewareConfig{
			"cache-lru": {},
		},
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source:      "db",
				Middlewares: []string{"cache-lru"},
				Endpoints: map[string]config.RestEndpoint{
					"users": {Source: "db", Table: "people"},
					"notes": {Source: "db"},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	first := httptest.NewRecorder()
	router.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/5/", nil))
	etag := first.Header().Get("ETag")
	if first.Code != http.StatusOK || etag == "" {
		t.Fatalf("status %d etag %q body %q", first.Code, etag, first.Body.String())
	}
	var row map[string]any
	if err := json.Unmarshal(first.Body.Bytes(), &row); err != nil {
		t.Fatalf("decode %v body %q", err, first.Body.String())
	}
	if row["name"] != "ada" || row["results"] != nil {
		t.Fatalf("row %#v", row)
	}
	calls := plugin.getCalls

	second := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/5/", nil)
	req.Header.Set("If-None-Match", etag)
	router.ServeHTTP(second, req)
	if second.Code != http.StatusNotModified || second.Header().Get("ETag") != etag {
		t.Fatalf("status %d etag %q body %q", second.Code, second.Header().Get("ETag"), second.Body.String())
	}
	if plugin.getCalls != calls {
		t.Fatalf("calls %d want %d", plugin.getCalls, calls)
	}

	plain := httptest.NewRecorder()
	router.ServeHTTP(plain, httptest.NewRequest(http.MethodGet, "/restapi/v1/notes/5/", nil))
	if plain.Code != http.StatusOK || plain.Header().Get("ETag") != "" {
		t.Fatalf("status %d etag %q body %q", plain.Code, plain.Header().Get("ETag"), plain.Body.String())
	}
	var note map[string]any
	if err := json.Unmarshal(plain.Body.Bytes(), &note); err != nil {
		t.Fatalf("decode %v body %q", err, plain.Body.String())
	}
	if note["name"] != "ada" {
		t.Fatalf("note %#v", note)
	}
}

func TestRestAPI_MiddlewareOrder(t *testing.T) {
	var order []string
	globalPlug := &recordingMiddlewarePlugin{label: "global", order: &order}
	apiPlug := &recordingMiddlewarePlugin{label: "api", order: &order}
	dbPlug := &recordingMiddlewarePlugin{label: "db", order: &order}
	origMW := MiddlewarePlugins.Load()
	t.Cleanup(func() { MiddlewarePlugins.Store(origMW) })
	loaded := map[string]easyrest.MiddlewarePlugin{
		"global":      globalPlug,
		"cache-redis": apiPlug,
		"dbmw":        dbPlug,
	}
	MiddlewarePlugins.Store(&loaded)

	cfg := config.Config{
		CheckScope:               false,
		AnonClaims:               map[string]any{"sub": "u"},
		GlobalRequestMiddlewares: []string{"global", "missing"},
		MiddlewarePlugins: map[string]config.MiddlewareConfig{
			"global":      {},
			"cache-redis": {},
			"missing":     {},
			"dbmw":        {},
		},
		PluginMap: map[string]config.PluginConfig{
			"db": {RequestMiddlewares: []string{"dbmw"}},
		},
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source:      "db",
				Middlewares: []string{"cache-redis", "missing"},
				Endpoints:   map[string]config.RestEndpoint{"users": {}},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if len(order) != 2 || order[0] != "global" || order[1] != "api" {
		t.Fatalf("order %#v", order)
	}
}

func TestRestAPI_SourceDefault(t *testing.T) {
	primary := &restRecPlugin{rows: []map[string]any{{"id": float64(1)}}}
	other := &restRecPlugin{rows: []map[string]any{{"id": float64(2)}}}
	cfg := config.Config{
		AnonClaims: map[string]any{"sub": "u", "scope": "read"},
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "primary",
				Endpoints: map[string]config.RestEndpoint{
					"users":  {},
					"orders": {Source: "other"},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"primary": primary, "other": other})
	usersW := httptest.NewRecorder()
	router.ServeHTTP(usersW, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if usersW.Code != http.StatusOK || primary.getTable != "users" || other.getTable != "" {
		t.Fatalf("users status %d primary %q other %q", usersW.Code, primary.getTable, other.getTable)
	}
	ordersW := httptest.NewRecorder()
	router.ServeHTTP(ordersW, httptest.NewRequest(http.MethodGet, "/restapi/v1/orders/", nil))
	if ordersW.Code != http.StatusOK || other.getTable != "orders" {
		t.Fatalf("orders status %d table %q", ordersW.Code, other.getTable)
	}
}

func TestRestAPI_ReloadSwap(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"name": "ada"}}}
	parent := chi.NewRouter()
	parent.Get("/api/kept/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mountRestAPI(parent)

	users := config.Config{
		AnonClaims: map[string]any{"sub": "u"},
		RestAPI: map[string]config.RestAPIApp{
			"v1": {Source: "db", Endpoints: map[string]config.RestEndpoint{"users": {}}},
		},
	}
	origCfg := GetConfig()
	origDB := DbPlugins.Load()
	t.Cleanup(func() {
		SetConfig(origCfg)
		DbPlugins.Store(origDB)
		publishRestAPI()
	})
	SetConfig(users)
	DbPlugins.Store(&map[string]easyrest.DBPlugin{"db": plugin})
	publishRestAPI()

	first := httptest.NewRecorder()
	parent.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("users before swap %d", first.Code)
	}

	SetConfig(config.Config{
		AnonClaims: map[string]any{"sub": "u"},
		RestAPI: map[string]config.RestAPIApp{
			"v1": {Source: "db", Endpoints: map[string]config.RestEndpoint{"orders": {Description: "Orders"}}},
		},
	})
	publishRestAPI()

	old := httptest.NewRecorder()
	parent.ServeHTTP(old, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if old.Code != http.StatusNotFound {
		t.Fatalf("old users %d", old.Code)
	}
	next := httptest.NewRecorder()
	parent.ServeHTTP(next, httptest.NewRequest(http.MethodGet, "/restapi/v1/orders/", nil))
	if next.Code != http.StatusOK {
		t.Fatalf("orders %d body %q", next.Code, next.Body.String())
	}
	specW := httptest.NewRecorder()
	parent.ServeHTTP(specW, httptest.NewRequest(http.MethodGet, "/restapi/v1/", nil))
	var spec map[string]any
	if err := json.Unmarshal(specW.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths, _ := spec["paths"].(map[string]any)
	if _, ok := paths["/users/"]; ok {
		t.Fatalf("old path still in spec %#v", paths)
	}
	if _, ok := paths["/orders/"]; !ok {
		t.Fatalf("orders missing %#v", paths)
	}
	kept := httptest.NewRecorder()
	parent.ServeHTTP(kept, httptest.NewRequest(http.MethodGet, "/api/kept/", nil))
	if kept.Code != http.StatusNoContent {
		t.Fatalf("parent route %d", kept.Code)
	}
}

func TestRestAPI_ContentPair(t *testing.T) {
	csvNames := []string{"csv"}
	plugin := &restRecPlugin{rows: []map[string]any{{"name": "ada"}}}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source:  "db",
				Parsers: &csvNames,
				Endpoints: map[string]config.RestEndpoint{
					"users": {},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})
	get := httptest.NewRecorder()
	router.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if get.Code != http.StatusOK || !strings.Contains(get.Header().Get("Content-Type"), "text/csv") || !strings.Contains(get.Body.String(), "ada") {
		t.Fatalf("csv get status %d type %q body %q", get.Code, get.Header().Get("Content-Type"), get.Body.String())
	}
	jsonPost := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"name":"ada"}`))
	jsonPost.Header.Set("Content-Type", "application/json")
	jsonW := httptest.NewRecorder()
	router.ServeHTTP(jsonW, jsonPost)
	if jsonW.Code == http.StatusCreated || plugin.creates != 0 {
		t.Fatalf("json post status %d creates %d", jsonW.Code, plugin.creates)
	}
	csvPost := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader("name\nada\n"))
	csvPost.Header.Set("Content-Type", "text/csv")
	csvW := httptest.NewRecorder()
	router.ServeHTTP(csvW, csvPost)
	if csvW.Code != http.StatusCreated || plugin.creates != 1 || !strings.Contains(csvW.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("csv post status %d type %q creates %d body %q", csvW.Code, csvW.Header().Get("Content-Type"), plugin.creates, csvW.Body.String())
	}

	htmlNames := []string{"html"}
	htmlRouter := serveRest(t, config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {Source: "db", Parsers: &htmlNames, Endpoints: map[string]config.RestEndpoint{"users": {}}},
		},
	}, map[string]easyrest.DBPlugin{"db": &restRecPlugin{rows: []map[string]any{{"name": "ada"}}}})
	htmlGet := httptest.NewRecorder()
	htmlRouter.ServeHTTP(htmlGet, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?format=html", nil))
	if htmlGet.Code != http.StatusInternalServerError || !strings.Contains(htmlGet.Body.String(), "html content is only for swagger pages") {
		t.Fatalf("html render status %d body %q", htmlGet.Code, htmlGet.Body.String())
	}
	htmlPost := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader("<p>ada</p>"))
	htmlPost.Header.Set("Content-Type", "text/html")
	htmlPostW := httptest.NewRecorder()
	htmlRouter.ServeHTTP(htmlPostW, htmlPost)
	if htmlPostW.Code == http.StatusCreated || !strings.Contains(htmlPostW.Body.String(), "unsupported Content-Type") {
		t.Fatalf("html parse status %d body %q", htmlPostW.Code, htmlPostW.Body.String())
	}

	jsonNames := []string{"json"}
	override := serveRest(t, config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Parsers: &csvNames,
						Actions: map[string]config.RestAction{
							"list": {Renderers: &jsonNames},
						},
						DetailActions: map[string]config.RestCallAction{
							"publish": {Func: "publish_user", Fields: map[string]any{"name": map[string]any{"type": "string"}}, Renderers: &jsonNames},
						},
						StateActions: map[string]config.RestStateAction{
							"flag": {Func: "flag_user", Fields: map[string]any{"name": map[string]any{"type": "string"}}, Renderers: &csvNames},
						},
					},
				},
			},
		},
	}, map[string]easyrest.DBPlugin{"db": &restRecPlugin{
		rows:       []map[string]any{{"name": "ada"}},
		funcResult: map[string]any{"name": "ada"},
	}})
	list := httptest.NewRecorder()
	override.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if list.Code != http.StatusOK || !strings.Contains(list.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("list override status %d type %q body %q", list.Code, list.Header().Get("Content-Type"), list.Body.String())
	}
	publish := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/1/publish/", strings.NewReader(`{"name":"ada"}`))
	publish.Header.Set("Content-Type", "application/json")
	publishW := httptest.NewRecorder()
	override.ServeHTTP(publishW, publish)
	if publishW.Code != http.StatusOK || !strings.Contains(publishW.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("detail override status %d type %q body %q", publishW.Code, publishW.Header().Get("Content-Type"), publishW.Body.String())
	}
	flag := httptest.NewRecorder()
	override.ServeHTTP(flag, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/flag/", nil))
	if flag.Code != http.StatusOK || !strings.Contains(flag.Header().Get("Content-Type"), "text/csv") || !strings.Contains(flag.Body.String(), "ada") {
		t.Fatalf("state override status %d type %q body %q", flag.Code, flag.Header().Get("Content-Type"), flag.Body.String())
	}

	handlers := serveRest(t, config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {ContentHandlers: []string{"xml"}},
				},
			},
		},
	}, map[string]easyrest.DBPlugin{"db": &restRecPlugin{rows: []map[string]any{{"name": "ada"}}}})
	xml := httptest.NewRecorder()
	handlers.ServeHTTP(xml, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?format=xml", nil))
	if xml.Code != http.StatusOK || !strings.Contains(xml.Body.String(), "<name>ada</name>") {
		t.Fatalf("handlers status %d body %q", xml.Code, xml.Body.String())
	}
}

func TestRestAPI_Format(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"name": "ada"}}}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})

	xmlReq := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?format=xml", nil)
	xmlW := httptest.NewRecorder()
	router.ServeHTTP(xmlW, xmlReq)
	if xmlW.Code != http.StatusOK || !strings.Contains(xmlW.Body.String(), "<name>ada</name>") {
		t.Fatalf("xml status %d body %q", xmlW.Code, xmlW.Body.String())
	}

	jsonReq := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	jsonReq.Header.Set("Accept", "application/json")
	jsonW := httptest.NewRecorder()
	router.ServeHTTP(jsonW, jsonReq)
	if jsonW.Code != http.StatusOK || !strings.Contains(jsonW.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("json status %d type %q", jsonW.Code, jsonW.Header().Get("Content-Type"))
	}
	var body map[string]any
	if err := json.Unmarshal(jsonW.Body.Bytes(), &body); err != nil {
		t.Fatalf("json %v body %q", err, jsonW.Body.String())
	}
	rows, _ := body["results"].([]any)
	row, _ := rows[0].(map[string]any)
	if row["name"] != "ada" {
		t.Fatalf("json body %q", jsonW.Body.String())
	}
}

func TestRestAPI_BadNeighbor(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"name": "ada"}}}
	cfg := config.Config{
		AnonClaims: map[string]any{"sub": "u"},
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"Users": {},
					"users": {},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})
	bad := httptest.NewRecorder()
	router.ServeHTTP(bad, httptest.NewRequest(http.MethodGet, "/restapi/v1/Users/", nil))
	if bad.Code != http.StatusNotFound {
		t.Fatalf("invalid name %d", bad.Code)
	}
	okW := httptest.NewRecorder()
	router.ServeHTTP(okW, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if okW.Code != http.StatusOK {
		t.Fatalf("sibling %d body %q", okW.Code, okW.Body.String())
	}
}

func TestRestAPI_PluginError(t *testing.T) {
	var order []string
	plug := &recordingMiddlewarePlugin{label: "global", order: &order}
	origMW := MiddlewarePlugins.Load()
	origChain := globalMiddlewareChain.Load()
	emptyChain := []easyrest.MiddlewarePlugin{}
	globalMiddlewareChain.Store(&emptyChain)
	t.Cleanup(func() {
		MiddlewarePlugins.Store(origMW)
		if origChain != nil {
			globalMiddlewareChain.Store(origChain)
		}
	})
	loaded := map[string]easyrest.MiddlewarePlugin{"global": plug}
	MiddlewarePlugins.Store(&loaded)
	cfg := config.Config{
		AnonClaims:               map[string]any{"sub": "u"},
		GlobalRequestMiddlewares: []string{"global"},
		MiddlewarePlugins:        map[string]config.MiddlewareConfig{"global": {}},
		RestAPI: map[string]config.RestAPIApp{
			"v1": {Source: "db", Endpoints: map[string]config.RestEndpoint{"users": {}}},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{getErr: errors.New("db down")}})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if len(order) != 2 || order[1] != "global-post" {
		t.Fatalf("order %#v", order)
	}
}

func TestRestAPI_QueryFilter(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{}}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Filters: map[string]config.RestFilter{
							"city":    {Field: "city", Op: "eq"},
							"min_age": {Field: "age", Op: "gt"},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	filtered := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?city=Berlin&min_age=40&status=open", nil)
	filteredW := httptest.NewRecorder()
	router.ServeHTTP(filteredW, filtered)
	if filteredW.Code != http.StatusOK {
		t.Fatalf("status %d", filteredW.Code)
	}
	assertEqWhere(t, plugin.getWhere, "city", "Berlin")
	got, _ := plugin.getWhere["age"].(map[string]any)
	if got[">"] != "40" {
		t.Fatalf("age where %#v", plugin.getWhere)
	}
	if _, ok := plugin.getWhere["status"]; ok {
		t.Fatalf("unknown query key applied %#v", plugin.getWhere)
	}

	plain := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	plainW := httptest.NewRecorder()
	router.ServeHTTP(plainW, plain)
	if _, ok := plugin.getWhere["city"]; ok {
		t.Fatalf("city applied without query %#v", plugin.getWhere)
	}
	if _, ok := plugin.getWhere["age"]; ok {
		t.Fatalf("age applied without query %#v", plugin.getWhere)
	}
}

type sliceRestPlugin struct {
	fakeDBPlugin
	rows   []map[string]any
	total  int64
	calls  int
	limits []int
}

func (p *sliceRestPlugin) TableGet(_ string, _ string, _ []string, _ map[string]any, _ []string, _ []string, limit, offset int, ctx map[string]any) ([]map[string]any, map[string]any, error) {
	p.calls++
	p.limits = append(p.limits, limit)
	out := map[string]any{}
	if prefer, ok := ctx["prefer"].(map[string]any); ok {
		if _, has := prefer["count"]; has {
			out["total"] = p.total
		}
	}
	if limit <= 0 || offset >= len(p.rows) {
		return []map[string]any{}, out, nil
	}
	end := min(offset+limit, len(p.rows))
	return append([]map[string]any{}, p.rows[offset:end]...), out, nil
}

func TestRestAPI_NDJSONAndCSVPagination(t *testing.T) {
	plug := &sliceRestPlugin{
		total: 9,
		rows: []map[string]any{
			{"name": "a"}, {"name": "b"}, {"name": "c"}, {"name": "d"},
		},
	}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plug})

	ndjsonReq := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?limit=4", nil)
	ndjsonReq.Header.Set("Accept", "application/x-ndjson")
	ndjsonReq.Header.Set("Prefer", "count=exact page_size=2")
	ndjsonReq.Header.Set("X-Forwarded-Proto", "https")
	ndjsonReq.Header.Set("X-Forwarded-Host", "example.com")
	ndjsonW := httptest.NewRecorder()
	router.ServeHTTP(ndjsonW, ndjsonReq)
	if ndjsonW.Code != http.StatusOK {
		t.Fatalf("ndjson status %d body %q", ndjsonW.Code, ndjsonW.Body.String())
	}
	if plug.calls != 2 || plug.limits[0] != 2 || plug.limits[1] != 2 {
		t.Fatalf("pages calls=%d limits=%v", plug.calls, plug.limits)
	}
	lines := strings.Split(strings.TrimSpace(ndjsonW.Body.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("lines %d body %q", len(lines), ndjsonW.Body.String())
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &meta); err != nil {
		t.Fatalf("meta %v line %q", err, lines[0])
	}
	if meta["count"] != float64(9) || meta["previous"] != nil {
		t.Fatalf("meta %#v", meta)
	}
	if _, ok := meta["results"]; ok {
		t.Fatalf("meta includes results %#v", meta)
	}
	next, _ := meta["next"].(string)
	if !strings.Contains(next, "offset=4") {
		t.Fatalf("next %#v", meta["next"])
	}
	countLines := 0
	for _, line := range lines[1:] {
		if strings.Contains(line, `"count"`) {
			countLines++
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("row %v %q", err, line)
		}
		if _, ok := row["name"]; !ok {
			t.Fatalf("row %#v", row)
		}
	}
	if countLines != 0 {
		t.Fatalf("later pages repeated count")
	}

	csvPlug := &sliceRestPlugin{rows: plug.rows, total: plug.total}
	csvRouter := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": csvPlug})
	csvReq := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?limit=2&offset=2", nil)
	csvReq.Header.Set("Accept", "text/csv")
	csvReq.Header.Set("Prefer", "count=exact")
	csvReq.Header.Set("X-Forwarded-Proto", "https")
	csvReq.Header.Set("X-Forwarded-Host", "example.com")
	csvW := httptest.NewRecorder()
	csvRouter.ServeHTTP(csvW, csvReq)
	if csvW.Code != http.StatusOK {
		t.Fatalf("csv status %d body %q", csvW.Code, csvW.Body.String())
	}
	link := csvW.Header().Get("Link")
	if !strings.Contains(link, `rel="prev"`) || !strings.Contains(link, `rel="next"`) || !strings.Contains(link, `rel="count"; total="9"`) {
		t.Fatalf("link %q body %q", link, csvW.Body.String())
	}
	if csvPlug.calls != 1 {
		t.Fatalf("csv fetches %d", csvPlug.calls)
	}
}

func assertEqWhere(t *testing.T, where map[string]any, field, value string) {
	t.Helper()
	got, _ := where[field].(map[string]any)
	if got["="] != value {
		t.Fatalf("%s where %#v", field, where)
	}
}

func TestRestAPI_SwaggerHTML(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{}}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})
	req := httptest.NewRequest(http.MethodGet, "/restapi/v1/", nil)
	req.Host = "example.com"
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("status %d type %q body %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "/restapi/v1/") || !strings.Contains(w.Body.String(), "format=json") {
		t.Fatalf("spec url missing: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"swagger"`) {
		t.Fatalf("spec leaked: %s", w.Body.String())
	}
}

func TestRestAPI_ResourceAcceptHTMLStaysJSON(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"id": float64(1), "name": "ada"}}}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})
	req := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Header().Get("Content-Type"), "text/html") || strings.Contains(w.Body.String(), "swagger-ui") {
		t.Fatalf("resource became html: type %q body %s", w.Header().Get("Content-Type"), w.Body.String())
	}
}

func TestRestAPI_CatalogHTML(t *testing.T) {
	plugin := &restRecPlugin{}
	cfg := config.Config{RestAPI: map[string]config.RestAPIApp{
		"v1": {Source: "db"},
		"v2": {Source: "db"},
	}}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})
	req := httptest.NewRequest(http.MethodGet, "/restapi/", nil)
	req.Host = "example.com"
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "/restapi/v1/") || !strings.Contains(body, "/restapi/v2/") {
		t.Fatalf("status %d body %s", w.Code, body)
	}
	if !strings.Contains(body, `"urls.primaryName":"v1"`) {
		t.Fatalf("primary name missing: %s", body)
	}
}

func TestRestAPI_CatalogPrefix(t *testing.T) {
	plugin := &restRecPlugin{}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})
	req := httptest.NewRequest(http.MethodGet, "/restapi/?format=json", nil)
	req.Host = "example.com"
	req.Header.Set("X-Forwarded-Prefix", "/someapp")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "http://example.com/someapp/restapi/v1/?format=json") {
		t.Fatalf("prefix missing: %s", w.Body.String())
	}
}

func TestRestAPI_HTMLUsesHTTPSWhenTLSEnabled(t *testing.T) {
	// A browser loads this page on the TLS listener. Swagger UI fetches the absolute spec URL embedded here.
	cfg := restUsersConfig()
	cfg.TLSEnabled = true
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	req := httptest.NewRequest(http.MethodGet, "/restapi/v1/?format=html", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "https://example.com/restapi/v1/?format=json") {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}

func TestRestAPI_HTMLKeepsHTTPSWhenForwardedProtoIsHTTP(t *testing.T) {
	// tls_enabled is the public scheme. A proxy header must not publish http for this listener.
	cfg := restUsersConfig()
	cfg.TLSEnabled = true
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	req := httptest.NewRequest(http.MethodGet, "/restapi/v1/?format=html", nil)
	req.Host = "example.com"
	req.Header.Set("X-Forwarded-Proto", "http")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "https://example.com/restapi/v1/?format=json") {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}

func TestRestAPI_CatalogJSON(t *testing.T) {
	plugin := &restRecPlugin{}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})
	req := httptest.NewRequest(http.MethodGet, "/restapi/?format=json", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	var model map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &model); err != nil {
		t.Fatalf("decode %v body %s", err, w.Body.String())
	}
	apis, _ := model["apis"].([]any)
	if len(apis) != 1 {
		t.Fatalf("model %#v", model)
	}
}

func TestRestAPI_CatalogEmpty(t *testing.T) {
	router := serveRest(t, config.Config{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/restapi/?format=json", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	var model map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &model); err != nil {
		t.Fatalf("decode %v body %s", err, w.Body.String())
	}
	apis, _ := model["apis"].([]any)
	if len(apis) != 0 {
		t.Fatalf("model %#v", model)
	}
}

func TestRestAPI_CatalogReload(t *testing.T) {
	plugin := &restRecPlugin{}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})
	cfg := restUsersConfig()
	cfg.RestAPI["v2"] = config.RestAPIApp{Source: "db"}
	SetConfig(cfg)
	publishRestAPI()
	req := httptest.NewRequest(http.MethodGet, "/restapi/?format=json", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	body := w.Body.String()
	if !strings.Contains(body, "/restapi/v2/") {
		t.Fatalf("reload missing v2: %s", body)
	}
}

func TestRestWriteKeysOmittedFieldsStayOpen(t *testing.T) {
	ep := config.RestEndpoint{Actions: map[string]config.RestAction{
		"create": {ExtraFields: map[string]any{"avatar": map[string]any{"type": "string"}}},
	}}
	if restWriteKeys(ep, "create") != nil {
		t.Fatal("extra_fields without fields must not become the only allowed keys")
	}
	listed := config.RestEndpoint{Actions: map[string]config.RestAction{
		"create": {
			Fields:      []string{"name"},
			ExtraFields: map[string]any{"avatar": map[string]any{"type": "string"}},
		},
	}}
	keys := restWriteKeys(listed, "create")
	if _, ok := keys["name"]; !ok {
		t.Fatal("listed field missing")
	}
	if _, ok := keys["avatar"]; !ok {
		t.Fatal("extra field missing")
	}
}
