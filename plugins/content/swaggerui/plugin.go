// Package swaggerui renders a Swagger UI page for schema responses.
package swaggerui

import (
	"fmt"
	"html/template"
	"reflect"
	"strings"
	"sync"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// Plugin renders text/html only when the host marks the response as a swagger page.
type Plugin struct {
	easyrest.ContentBase
	once sync.Once
	tpl  *template.Template
	err  error
}

var _ easyrest.ContentPlugin = (*Plugin)(nil)

// New returns an HTML swagger content plugin.
func New() *Plugin { return &Plugin{} }

// Init reports HTML for the response only.
func (*Plugin) Init(map[string]any) (easyrest.ContentInfo, error) {
	return easyrest.NewContentInfo(easyrest.MediaTypeHTML, "", "html"), nil
}

// Parse refuses request bodies. This plugin only renders swagger pages.
func (*Plugin) Parse(body []byte, ctx map[string]any) (any, map[string]any, error) {
	return nil, ctx, easyrest.ErrContentUnsupported
}

// Render writes the swagger page. It refuses a call that is not a document or catalog.
func (p *Plugin) Render(data any, ctx map[string]any) (any, map[string]any, error) {
	mode, _ := ctxString(ctx, easyrest.CtxSwagger)
	var view pageView
	switch mode {
	case easyrest.SwaggerDocument:
		view = documentView(data, ctx)
	case easyrest.SwaggerCatalog:
		view = catalogView(data, ctx)
	default:
		return nil, ctx, fmt.Errorf("html content is only for swagger pages")
	}
	if embed, _ := ctx[easyrest.CtxSwaggerEmbed].(bool); embed {
		view.Schema = data
		view.Config.URL = ""
		view.Config.URLs = nil
		view.Config.PrimaryName = ""
	}
	view.Auth, _ = ctxString(ctx, easyrest.CtxSwaggerAuth)
	return p.render(ctx, view)
}

func (p *Plugin) render(ctx map[string]any, view pageView) (any, map[string]any, error) {
	tpl, err := p.templateFor(ctx)
	if err != nil {
		return nil, nil, err
	}
	var buf strings.Builder
	if err := tpl.Execute(&buf, view); err != nil {
		return nil, nil, fmt.Errorf("swagger page: %w", err)
	}
	return buf.String(), nil, nil
}

func (p *Plugin) templateFor(ctx map[string]any) (*template.Template, error) {
	if ctx != nil {
		if tpl, ok := ctx[easyrest.CtxSwaggerTemplate].(*template.Template); ok && tpl != nil {
			return tpl, nil
		}
	}
	return p.template()
}

func (p *Plugin) template() (*template.Template, error) {
	p.once.Do(func() {
		p.tpl, p.err = template.ParseFS(content, "page.html.tmpl")
	})
	return p.tpl, p.err
}

type specURL struct {
	URL  string `json:"url"`
	Name string `json:"name"`
}

type swaggerConfig struct {
	URL                    string     `json:"url,omitempty"`
	URLs                   *[]specURL `json:"urls,omitempty"`
	PrimaryName            string     `json:"urls.primaryName,omitempty"`
	DomID                  string     `json:"dom_id"`
	DeepLinking            bool       `json:"deepLinking"`
	DocExpansion           string     `json:"docExpansion"`
	Filter                 bool       `json:"filter"`
	DisplayRequestDuration bool       `json:"displayRequestDuration"`
	TryItOutEnabled        bool       `json:"tryItOutEnabled"`
	ValidatorURL           any        `json:"validatorUrl"`
	QueryConfigEnabled     bool       `json:"queryConfigEnabled"`
	PersistAuthorization   bool       `json:"persistAuthorization"`
	SupportedSubmitMethods []string   `json:"supportedSubmitMethods"`
	Layout                 string     `json:"layout"`
}

type pageView struct {
	Title      string
	Assets     string
	Config     swaggerConfig
	Standalone bool
	Schema     any
	Auth       string
}

func baseConfig(layout string) swaggerConfig {
	return swaggerConfig{
		DomID:                  "#swagger-ui",
		DeepLinking:            true,
		DocExpansion:           "list",
		Filter:                 true,
		DisplayRequestDuration: true,
		TryItOutEnabled:        false,
		QueryConfigEnabled:     false,
		PersistAuthorization:   false,
		SupportedSubmitMethods: []string{"get", "put", "post", "delete", "options", "head", "patch", "trace", "query"},
		Layout:                 layout,
	}
}

func documentView(data any, ctx map[string]any) pageView {
	cfg := baseConfig("StandaloneLayout")
	cfg.URL, _ = ctxString(ctx, easyrest.CtxSwaggerURL)
	return pageView{
		Title:      specTitle(data),
		Assets:     assetsPrefix(ctx),
		Config:     cfg,
		Standalone: true,
	}
}

func specTitle(data any) string {
	if obj, ok := data.(map[string]any); ok {
		info, _ := obj["info"].(map[string]any)
		title, _ := info["title"].(string)
		if title != "" {
			return title
		}
		return "API"
	}
	v := reflect.ValueOf(data)
	if !v.IsValid() {
		return "API"
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return "API"
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return "API"
	}
	info := v.FieldByName("Info")
	if !info.IsValid() {
		return "API"
	}
	if info.Kind() == reflect.Pointer {
		if info.IsNil() {
			return "API"
		}
		info = info.Elem()
	}
	if info.Kind() != reflect.Struct {
		return "API"
	}
	title := info.FieldByName("Title")
	if title.IsValid() && title.Kind() == reflect.String && title.String() != "" {
		return title.String()
	}
	return "API"
}

func catalogView(data any, ctx map[string]any) pageView {
	cfg := baseConfig("StandaloneLayout")
	urls := catalogURLs(data)
	cfg.URLs = &urls
	if len(urls) > 0 {
		cfg.PrimaryName = urls[0].Name
	}
	return pageView{
		Title:      "API",
		Assets:     assetsPrefix(ctx),
		Config:     cfg,
		Standalone: true,
	}
}

func assetsPrefix(ctx map[string]any) string {
	prefix, _ := ctxString(ctx, easyrest.CtxSwaggerAssets)
	if prefix == "" {
		return "/media/static/"
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return prefix
}

func catalogURLs(data any) []specURL {
	obj, ok := data.(map[string]any)
	if !ok || obj == nil {
		return []specURL{}
	}
	raw, ok := obj["apis"]
	if !ok || raw == nil {
		return []specURL{}
	}
	rows, ok := easyrest.MapRows(raw)
	if !ok {
		if one, ok := raw.([]map[string]any); ok {
			rows = one
		} else {
			return []specURL{}
		}
	}
	out := make([]specURL, 0, len(rows))
	for _, row := range rows {
		name, _ := row["name"].(string)
		url, _ := row["url"].(string)
		if name == "" || url == "" {
			continue
		}
		out = append(out, specURL{Name: name, URL: url})
	}
	return out
}

func ctxString(ctx map[string]any, key string) (string, bool) {
	if ctx == nil {
		return "", false
	}
	s, ok := ctx[key].(string)
	return s, ok && s != ""
}
