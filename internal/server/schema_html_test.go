package server

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestSchemaHTMLPage(t *testing.T) {
	router, _ := setupTableRouter(t, &fakeAuthPlugin{}, "", nil)
	req := httptest.NewRequest(http.MethodGet, "/api/test/", nil)
	req.Host = "example.com"
	req.Header.Set("Accept", easyrest.MediaTypeHTML)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("content-type %q", w.Header().Get("Content-Type"))
	}
	body := w.Body.String()
	if !strings.Contains(body, "swagger-ui") || !strings.Contains(body, "format=json") {
		t.Fatalf("page %s", body)
	}
	if strings.Contains(body, `"swagger"`) {
		t.Fatalf("spec leaked: %s", body)
	}
}

func TestSchemaHTMLDoesNotReplaceJSON(t *testing.T) {
	router, _ := setupTableRouter(t, &fakeAuthPlugin{}, "", nil)
	req := httptest.NewRequest(http.MethodGet, "/api/test/", nil)
	req.Header.Set("Accept", easyrest.MediaTypeJSON)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var spec map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	if spec["openapi"] != "3.0.3" {
		t.Fatalf("spec %#v", spec["openapi"])
	}
}

func TestSchemaFormatHTMLBeatsAcceptJSON(t *testing.T) {
	router, _ := setupTableRouter(t, &fakeAuthPlugin{}, "", nil)
	req := httptest.NewRequest(http.MethodGet, "/api/test/?format=html", nil)
	req.Header.Set("Accept", easyrest.MediaTypeJSON)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("content-type %q body %s", w.Header().Get("Content-Type"), w.Body.String())
	}
}

func TestAPISchemaUsesHTTPSWhenTLSEnabled(t *testing.T) {
	router, _ := setupTableRouter(t, &fakeAuthPlugin{}, "", nil)
	cfg := GetConfig()
	cfg.TLSEnabled = true
	SetConfig(cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/test/", nil)
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-Host", "edge.example")
	req.Header.Set("X-Forwarded-Prefix", "/gateway")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var spec map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	if serverURL(t, spec) != "https://edge.example/gateway/api/test" {
		t.Fatalf("servers %#v", spec["servers"])
	}
}

func TestAPISchemaUsesHTTPWhenTLSDisabled(t *testing.T) {
	router, _ := setupTableRouter(t, &fakeAuthPlugin{}, "", nil)
	req := httptest.NewRequest(http.MethodGet, "/api/test/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var spec map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	if serverURL(t, spec) != "http://example.com/api/test" {
		t.Fatalf("servers %#v", spec["servers"])
	}
}

func serverURL(t *testing.T, spec map[string]any) string {
	t.Helper()
	servers, _ := spec["servers"].([]any)
	if len(servers) != 1 {
		t.Fatalf("servers %#v", spec["servers"])
	}
	first, _ := servers[0].(map[string]any)
	url, _ := first["url"].(string)
	return url
}

func TestRootCatalogSkipsInternal(t *testing.T) {
	router := setupCatalogRouter(t, config.Config{
		PluginMap: map[string]config.PluginConfig{
			"public": {Uri: "sqlite://memory"},
			"hidden": {Uri: "sqlite://memory", Internal: true},
			"query":  {Uri: "sqlite://memory", UseQuery: true},
		},
	})
	body := catalogBody(t, router, "/?format=json", "")
	if strings.Contains(body, "hidden") || strings.Contains(body, "query") {
		t.Fatalf("internal or query api listed: %s", body)
	}
	if !strings.Contains(body, "/api/public/") {
		t.Fatalf("public api missing: %s", body)
	}
}

func TestRootCatalogIncludesRestAPI(t *testing.T) {
	router := setupCatalogRouter(t, config.Config{
		PluginMap: map[string]config.PluginConfig{
			"hidden": {Uri: "sqlite://memory", Internal: true},
		},
		RestAPI: map[string]config.RestAPIApp{
			"v1": {Source: "hidden"},
		},
	})
	body := catalogBody(t, router, "/?format=json", "")
	if strings.Contains(body, "/api/hidden/") {
		t.Fatalf("internal db listed: %s", body)
	}
	if !strings.Contains(body, "/restapi/v1/") {
		t.Fatalf("restapi missing: %s", body)
	}
}

func TestRootCatalogAbsolutePrefix(t *testing.T) {
	router := setupCatalogRouter(t, config.Config{
		PluginMap: map[string]config.PluginConfig{
			"public": {Uri: "sqlite://memory"},
		},
	})
	body := catalogBody(t, router, "/", "/someapp")
	if !strings.Contains(body, "http://example.com/someapp/api/public/?format=json") &&
		!strings.Contains(body, `http://example.com/someapp/api/public/?format=json`) &&
		!strings.Contains(body, `http://example.com/someapp/api/public/?format\u003djson`) &&
		!strings.Contains(body, "http://example.com/someapp/api/public/?format=json") {
		t.Fatalf("prefix missing: %s", body)
	}
	if !strings.Contains(body, "/someapp/api/public/") {
		t.Fatalf("prefix missing: %s", body)
	}
}

func TestRootCatalogJSON(t *testing.T) {
	router := setupCatalogRouter(t, config.Config{
		PluginMap: map[string]config.PluginConfig{
			"public": {Uri: "sqlite://memory"},
		},
	})
	body := catalogBody(t, router, "/?format=json", "")
	var model map[string]any
	if err := json.Unmarshal([]byte(body), &model); err != nil {
		t.Fatalf("decode %v body %s", err, body)
	}
	apis, _ := model["apis"].([]any)
	if len(apis) != 1 {
		t.Fatalf("apis %#v", model)
	}
}

func setupCatalogRouter(t *testing.T, cfg config.Config) http.Handler {
	t.Helper()
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
	db := &countingDBPlugin{}
	PreservedDbPlugins = map[string]PreservedPluginFactory[easyrest.DBPlugin]{
		"sqlite": func() easyrest.DBPlugin { return db },
	}
	PreservedQueryPlugins = map[string]PreservedPluginFactory[easyrest.DBQueryPlugin]{}
	PreservedAuthPlugins = map[string]PreservedPluginFactory[easyrest.AuthPlugin]{}
	PreservedMiddlewarePlugins = map[string]PreservedPluginFactory[easyrest.MiddlewarePlugin]{}
	SetConfig(cfg)
	return SetupRouter()
}

func catalogBody(t *testing.T, router http.Handler, target, prefix string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Host = "example.com"
	if prefix != "" {
		req.Header.Set("X-Forwarded-Prefix", prefix)
		req.Header.Set("Accept", easyrest.MediaTypeHTML)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s status %d body %s", target, w.Code, w.Body.String())
	}
	return w.Body.String()
}

type schemaAuthPlugin struct {
	kind string
}

func (p schemaAuthPlugin) Init(map[string]any, easyrest.HostRPC) (easyrest.AuthInfo, error) {
	return easyrest.NewAuthInfo(map[string]any{"type": p.kind}), nil
}

func (schemaAuthPlugin) Authenticate(map[string]string, string, string, string) (map[string]any, error) {
	return map[string]any{"sub": "tester", "scope": "read write"}, nil
}

func setupVersionRouter(t *testing.T, cfg config.Config) http.Handler {
	t.Helper()
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
	db := &countingDBPlugin{}
	PreservedDbPlugins = map[string]PreservedPluginFactory[easyrest.DBPlugin]{
		"sqlite": func() easyrest.DBPlugin { return db },
	}
	PreservedQueryPlugins = map[string]PreservedPluginFactory[easyrest.DBQueryPlugin]{}
	PreservedAuthPlugins = map[string]PreservedPluginFactory[easyrest.AuthPlugin]{
		"jwt":   func() easyrest.AuthPlugin { return schemaAuthPlugin{kind: "apiKey"} },
		"basic": func() easyrest.AuthPlugin { return schemaAuthPlugin{kind: "basic"} },
	}
	PreservedMiddlewarePlugins = map[string]PreservedPluginFactory[easyrest.MiddlewarePlugin]{}
	SetConfig(cfg)
	return SetupRouter()
}

func TestRootVersionUsesRestAPISchema(t *testing.T) {
	router := setupVersionRouter(t, config.Config{
		PluginMap: map[string]config.PluginConfig{
			"shop": {Uri: "sqlite://memory", Internal: true},
		},
		RestAPI: map[string]config.RestAPIApp{
			"shop": {
				Source: "shop",
				Endpoints: map[string]config.RestEndpoint{
					"users": {},
				},
			},
		},
		AuthPlugins: map[string]config.AuthConfig{
			"jwt":   {},
			"basic": {},
		},
		Application: config.ApplicationConfig{Version: "shop", Auth: "jwt"},
	})
	root := decodeSpec(t, catalogBody(t, router, "/?format=json", ""))
	if serverURL(t, root) != "/restapi/shop" {
		t.Fatalf("root spec %#v", root["servers"])
	}
	if !onlySecurity(root, "jwt", "basic") {
		t.Fatalf("root security %#v", root["components"])
	}
	full := decodeSpec(t, catalogBody(t, router, "/restapi/shop/?format=json", ""))
	if !onlySecurity(full, "jwt", "basic") {
		t.Fatalf("restapi security %#v", full["components"])
	}
}

func TestRootVersionRejectsPluginName(t *testing.T) {
	_, err := config.Load(nil, `
plugins:
  public:
    uri: sqlite://memory
application:
  version: public
  auth: jwt
`)
	if err == nil || !strings.Contains(err.Error(), "application.version") {
		t.Fatalf("plugin version err = %v", err)
	}

	router := setupVersionRouter(t, config.Config{
		PluginMap: map[string]config.PluginConfig{
			"public": {Uri: "sqlite://memory", Title: "Public API"},
		},
		AuthPlugins: map[string]config.AuthConfig{
			"jwt":   {},
			"basic": {},
		},
		Application: config.ApplicationConfig{Version: "public", Auth: "jwt"},
	})
	root := decodeSpec(t, catalogBody(t, router, "/?format=json", ""))
	if _, ok := root["openapi"]; ok {
		t.Fatalf("plugin version embedded a spec %#v", root["openapi"])
	}
	apis, _ := root["apis"].([]any)
	if len(apis) != 1 {
		t.Fatalf("catalog %#v", root)
	}
}

func TestRootCustomTemplate(t *testing.T) {
	page, err := template.New("page").Parse("custom-root {{.Auth}}")
	if err != nil {
		t.Fatal(err)
	}
	router := setupVersionRouter(t, config.Config{
		PluginMap: map[string]config.PluginConfig{
			"public": {Uri: "sqlite://memory"},
		},
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "public",
				Endpoints: map[string]config.RestEndpoint{
					"users": {},
				},
			},
		},
		AuthPlugins: map[string]config.AuthConfig{
			"jwt":   {},
			"basic": {},
		},
		Application: config.ApplicationConfig{
			Version: "v1",
			Auth:    "jwt",
			Page:    page,
		},
	})
	root := htmlBody(t, router, "/")
	if !strings.Contains(root, "custom-root jwt") {
		t.Fatalf("custom template missing: %s", root)
	}
	api := htmlBody(t, router, "/api/public/")
	if strings.Contains(api, "custom-root") || !strings.Contains(api, "swagger-ui") {
		t.Fatalf("api page used the root template: %s", api)
	}
}

func htmlBody(t *testing.T, router http.Handler, target string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Host = "example.com"
	req.Header.Set("Accept", easyrest.MediaTypeHTML)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s status %d body %s", target, w.Code, w.Body.String())
	}
	return w.Body.String()
}

func decodeSpec(t *testing.T, body string) map[string]any {
	t.Helper()
	var spec map[string]any
	if err := json.Unmarshal([]byte(body), &spec); err != nil {
		t.Fatalf("decode %v body %s", err, body)
	}
	return spec
}

func onlySecurity(spec map[string]any, keys ...string) bool {
	components, _ := spec["components"].(map[string]any)
	defs, _ := components["securitySchemes"].(map[string]any)
	if len(defs) != len(keys) {
		return false
	}
	for _, key := range keys {
		if defs[key] == nil {
			return false
		}
	}
	return true
}
