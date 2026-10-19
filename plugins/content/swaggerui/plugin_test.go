package swaggerui

import (
	"errors"
	"strings"
	"testing"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestPlugin_Init(t *testing.T) {
	info, err := New().Init(nil)
	if err != nil || info.RenderMedia != easyrest.MediaTypeHTML || info.ParserMedia != "" || info.Format != "html" {
		t.Fatalf("Init() = %+v %v", info, err)
	}
}

func TestPlugin_Parse_Unsupported(t *testing.T) {
	_, _, err := New().Parse([]byte("a=b"), nil)
	if !errors.Is(err, easyrest.ErrContentUnsupported) {
		t.Fatalf("Parse err = %v", err)
	}
}

func TestPlugin_Render_NoContext(t *testing.T) {
	_, _, err := New().Render(map[string]any{"swagger": "2.0"}, nil)
	if err == nil {
		t.Fatal("expected error without swagger context")
	}
}

func TestPlugin_Render_UnknownMode(t *testing.T) {
	_, _, err := New().Render(nil, map[string]any{easyrest.CtxSwagger: "table"})
	if err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestPlugin_Render_DocumentURL(t *testing.T) {
	body := renderDocument(t, map[string]any{"swagger": "2.0"}, map[string]any{
		easyrest.CtxSwagger:    easyrest.SwaggerDocument,
		easyrest.CtxSwaggerURL: "http://example.com/someapp/api/test/?select=id&format=json",
	})
	if !strings.Contains(body, `http://example.com/someapp/api/test/?select=id\u0026format=json`) {
		t.Fatalf("spec url missing: %s", body)
	}
	if !strings.Contains(body, `"validatorUrl":null`) || !strings.Contains(body, `id="swagger-ui"`) {
		t.Fatalf("page config missing: %s", body)
	}
	if !strings.Contains(body, "swagger-ui-standalone-preset.js") || !strings.Contains(body, "SwaggerUIStandalonePreset") {
		t.Fatal("document page omitted the standalone preset")
	}
	if strings.Contains(body, `"urls"`) {
		t.Fatalf("document page must not use urls: %s", body)
	}
}

func TestPlugin_Render_OmitsSpecBody(t *testing.T) {
	body := renderDocument(t, map[string]any{
		"swagger":     "2.0",
		"paths":       map[string]any{"/secret-table/": map[string]any{}},
		"definitions": map[string]any{"SecretModel": map[string]any{"type": "object"}},
	}, map[string]any{
		easyrest.CtxSwagger:    easyrest.SwaggerDocument,
		easyrest.CtxSwaggerURL: "http://example.com/api/test/?format=json",
	})
	if strings.Contains(body, "/secret-table/") || strings.Contains(body, "SecretModel") {
		t.Fatalf("spec leaked into the page: %s", body)
	}
}

func TestPlugin_Render_FormatYAML(t *testing.T) {
	body := renderDocument(t, map[string]any{}, map[string]any{
		easyrest.CtxSwagger:    easyrest.SwaggerDocument,
		easyrest.CtxSwaggerURL: "http://example.com/api/test/?format=yaml",
	})
	if !strings.Contains(body, "format=yaml") {
		t.Fatalf("yaml url missing: %s", body)
	}
}

func TestPlugin_Render_NoCustomAuth(t *testing.T) {
	body := renderDocument(t, map[string]any{
		"securityDefinitions": map[string]any{
			"basic": map[string]any{"type": "basic"},
			"jwt":   map[string]any{"type": "apiKey", "in": "header", "name": "Authorization"},
			"oauth": map[string]any{"type": "oauth2", "flow": "password"},
		},
	}, documentCtx("http://example.com/api/test/?format=json"))
	if strings.Contains(body, "data-auth") || strings.Contains(body, "preauthorizeBasic") || strings.Contains(body, "localStorage") {
		t.Fatalf("custom auth leaked: %s", body)
	}
}

func TestPlugin_Render_BearerPrefix(t *testing.T) {
	body := renderDocument(t, map[string]any{"swagger": "2.0"}, documentCtx("http://example.com/api/test/?format=json"))
	if !strings.Contains(body, "requestInterceptor") || !strings.Contains(body, `"Bearer " + value`) {
		t.Fatalf("bearer prefix missing: %s", body)
	}
	if !strings.Contains(body, `value.indexOf(" ") < 0`) {
		t.Fatalf("bare-token check missing: %s", body)
	}
}

func TestPlugin_Render_CatalogURLs(t *testing.T) {
	body := renderCatalog(t, map[string]any{
		"apis": []any{
			map[string]any{"name": "shop", "url": "http://example.com/api/shop/?format=json"},
			map[string]any{"name": "v1", "url": "http://example.com/restapi/v1/?format=json"},
		},
	})
	if !strings.Contains(body, "http://example.com/api/shop/?format=json") || !strings.Contains(body, "http://example.com/restapi/v1/?format=json") {
		t.Fatalf("urls missing: %s", body)
	}
	if !strings.Contains(body, `"urls.primaryName":"shop"`) {
		t.Fatalf("primary name missing: %s", body)
	}
	if !strings.Contains(body, "swagger-ui-standalone-preset.js") {
		t.Fatal("catalog page omitted the standalone preset")
	}
}

func TestPlugin_Render_CatalogEmpty(t *testing.T) {
	body := renderCatalog(t, map[string]any{"apis": []any{}})
	if !strings.Contains(body, `"urls":[]`) {
		t.Fatalf("empty urls missing: %s", body)
	}
}

func TestPlugin_Render_CatalogIgnoresSecurityOnPayload(t *testing.T) {
	body := renderCatalog(t, map[string]any{
		"securityDefinitions": map[string]any{"basic": map[string]any{"type": "basic"}},
		"apis":                []any{map[string]any{"name": "v1", "url": "http://example.com/restapi/v1/?format=json"}},
	})
	if strings.Contains(body, `data-auth="basic"`) {
		t.Fatalf("catalog rendered auth from the payload: %s", body)
	}
}

func TestPlugin_Render_TopbarMatchesPage(t *testing.T) {
	body := renderCatalog(t, map[string]any{"apis": []any{}})
	if !strings.Contains(body, ".swagger-ui .topbar") || !strings.Contains(body, "background-color: #fafafa") {
		t.Fatalf("topbar override missing: %s", body)
	}
}

func TestPlugin_Render_PageChrome(t *testing.T) {
	body := renderDocument(t, map[string]any{"swagger": "2.0"}, documentCtx("http://example.com/api/test/?format=json"))
	if !strings.Contains(body, "background: #fafafa") || !strings.Contains(body, "margin: 0") {
		t.Fatalf("page chrome missing: %s", body)
	}
}

func TestPlugin_Render_TitleFromSpec(t *testing.T) {
	body := renderDocument(t, map[string]any{
		"info": map[string]any{"title": "SQLite API", "version": "v0.20.0"},
	}, documentCtx("http://example.com/api/test/?format=json"))
	if !strings.Contains(body, "<title>SQLite API</title>") {
		t.Fatalf("title missing: %s", body)
	}
	plain := renderDocument(t, map[string]any{"swagger": "2.0"}, documentCtx("http://example.com/api/test/?format=json"))
	if !strings.Contains(plain, "<title>API</title>") {
		t.Fatalf("default title missing: %s", plain)
	}
	spec := struct {
		Info struct{ Title string }
	}{}
	spec.Info.Title = "Struct API"
	fromStruct := renderDocument(t, spec, documentCtx("http://example.com/api/test/?format=json"))
	if !strings.Contains(fromStruct, "<title>Struct API</title>") {
		t.Fatalf("struct title missing: %s", fromStruct)
	}
}

func TestPlugin_Render_EmbedsSchemaAndAuth(t *testing.T) {
	body := renderDocument(t, map[string]any{
		"swagger": "2.0",
		"paths":   map[string]any{"/users/": map[string]any{}},
	}, map[string]any{
		easyrest.CtxSwagger:      easyrest.SwaggerDocument,
		easyrest.CtxSwaggerEmbed: true,
		easyrest.CtxSwaggerAuth:  "jwt",
		easyrest.CtxSwaggerURL:   "http://example.com/api/test/?format=json",
	})
	if !strings.Contains(body, "config.spec") || !strings.Contains(body, `"/users/"`) {
		t.Fatalf("schema was not embedded: %s", body)
	}
	if !strings.Contains(body, `var easyrestAuth = "jwt"`) {
		t.Fatalf("auth name missing: %s", body)
	}
	if strings.Contains(body, "example.com/api/test") {
		t.Fatalf("embedded page still points at a spec url: %s", body)
	}

	catalog := renderDocument(t, map[string]any{
		"apis": []any{map[string]any{"name": "shop", "url": "http://example.com/api/shop/?format=json"}},
		"paths": map[string]any{"/secret/": map[string]any{}},
	}, map[string]any{
		easyrest.CtxSwagger:     easyrest.SwaggerCatalog,
		easyrest.CtxSwaggerAuth: "basic",
	})
	if strings.Contains(catalog, "/secret/") {
		t.Fatalf("catalog embedded a schema: %s", catalog)
	}
	if !strings.Contains(catalog, `var easyrestAuth = "basic"`) {
		t.Fatalf("catalog auth missing: %s", catalog)
	}
}

func TestPlugin_EmbedHasTemplate(t *testing.T) {
	f, err := content.Open("page.html.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func documentCtx(url string) map[string]any {
	return map[string]any{
		easyrest.CtxSwagger:    easyrest.SwaggerDocument,
		easyrest.CtxSwaggerURL: url,
	}
}

func renderDocument(t *testing.T, data any, ctx map[string]any) string {
	t.Helper()
	raw, _, err := New().Render(data, ctx)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := raw.(string)
	return body
}

func renderCatalog(t *testing.T, data any) string {
	t.Helper()
	return renderDocument(t, data, map[string]any{
		easyrest.CtxSwagger:       easyrest.SwaggerCatalog,
		easyrest.CtxSwaggerAssets: "/media/static/",
	})
}
