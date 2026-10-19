package server

import (
	"net/http"
	"net/url"
	"slices"

	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func withHTMLContent(names []string) []string {
	out := slices.Clone(names)
	if slices.Contains(out, "html") {
		return out
	}
	return append(out, "html")
}

func defaultDocumentNames() []string {
	names := easyrest.StandardContentNames()
	if cfg := currentConfig(); len(cfg.DefaultContentHandlers) > 0 {
		names = cfg.DefaultContentHandlers
	}
	return withHTMLContent(names)
}

func swaggerPageCtx(r *http.Request, mode, specURL string) map[string]any {
	ctx := map[string]any{
		easyrest.CtxSwagger:       mode,
		easyrest.CtxSwaggerAssets: "/media/static/",
	}
	if specURL != "" {
		ctx[easyrest.CtxSwaggerURL] = specURL
	}
	return ctx
}

func absoluteFormatURL(r *http.Request, format string) string {
	q := r.URL.Query()
	q.Set("format", format)
	return easyrest.BuildAbsoluteUri(BuildPluginContext(r), r.URL.Path+"?"+q.Encode())
}

func absoluteSpecURL(r *http.Request, path, format string) string {
	return easyrest.BuildAbsoluteUri(BuildPluginContext(r), path+"?format="+url.QueryEscape(format))
}

func writeSwagger(w http.ResponseWriter, r *http.Request, dbKey string, pluginCtx map[string]any, names []string, runPost bool, data any, renderCtx map[string]any) {
	names = withHTMLContent(names)
	choice := negotiateContent(r, r.URL.Query(), contentRefsNamed(names))
	cw := newContentWriter(w, r, dbKey, pluginCtx, r.URL.Query(), choice.Renderer, runPost)
	cw.setRenderCtx(renderCtx)
	_ = cw.Write(http.StatusOK, data, nil)
}

func restCatalogModel(r *http.Request) map[string]any {
	apis := []map[string]any{}
	snap := restSpecs.Load()
	if snap != nil {
		for _, api := range snap.APIs {
			apis = append(apis, map[string]any{
				"name": api.Name,
				"url":  absoluteSpecURL(r, "/restapi/"+api.Name+"/", api.Format),
			})
		}
	}
	return map[string]any{"apis": apis}
}

func rootCatalogModel(r *http.Request) map[string]any {
	cfg := currentConfig()
	keys := make([]string, 0, len(cfg.PluginMap))
	for name, plug := range cfg.PluginMap {
		if plug.Internal || plug.UseQuery {
			continue
		}
		keys = append(keys, name)
	}
	slices.Sort(keys)
	apis := make([]map[string]any, 0, len(keys))
	for _, name := range keys {
		format := firstDocumentFormat(pluginDocumentNames(cfg, cfg.PluginMap[name]))
		apis = append(apis, map[string]any{
			"name": name,
			"url":  absoluteSpecURL(r, "/api/"+name+"/", format),
		})
	}
	rest := restCatalogModel(r)
	listed, _ := rest["apis"].([]map[string]any)
	apis = append(apis, listed...)
	return map[string]any{"apis": apis}
}

func pluginDocumentNames(cfg *config.Config, plug config.PluginConfig) []string {
	var defaults []string
	if cfg != nil {
		defaults = cfg.DefaultContentHandlers
	}
	return contentHandlerNames(nil, nil, plug.ContentHandlers, defaults)
}

func rootCatalogHandler(w http.ResponseWriter, r *http.Request) {
	cfg := currentConfig()
	names := defaultDocumentNames()
	if version := cfg.Application.Version; version != "" {
		if _, ok := cfg.RestAPI[version]; ok {
			writeSwagger(w, r, "", nil, names, false, restVersionDocument(version), rootPageCtx(r, cfg, true))
			return
		}
	}
	writeSwagger(w, r, "", nil, names, false, rootCatalogModel(r), rootPageCtx(r, cfg, false))
}

func restVersionDocument(name string) any {
	snap := restSpecs.Load()
	if snap == nil {
		return map[string]any{}
	}
	doc, ok := snap.Docs[name]
	if !ok || doc == nil {
		return map[string]any{}
	}
	return doc
}

func rootPageCtx(r *http.Request, cfg *config.Config, embed bool) map[string]any {
	mode := easyrest.SwaggerCatalog
	if embed {
		mode = easyrest.SwaggerDocument
	}
	ctx := swaggerPageCtx(r, mode, "")
	if cfg != nil && cfg.Application.Auth != "" {
		ctx[easyrest.CtxSwaggerAuth] = cfg.Application.Auth
	}
	if cfg != nil && cfg.Application.Page != nil {
		ctx[easyrest.CtxSwaggerTemplate] = cfg.Application.Page
	}
	if embed {
		ctx[easyrest.CtxSwaggerEmbed] = true
	}
	return ctx
}
