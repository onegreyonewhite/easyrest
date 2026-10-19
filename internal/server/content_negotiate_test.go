package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func testContentAllowed() []contentPluginRef {
	return []contentPluginRef{
		contentBoth("json", easyrest.MediaTypeJSON, "json"),
		contentBoth("ndjson", easyrest.MediaTypeNDJSON, "ndjson"),
		contentBoth("xml", easyrest.MediaTypeXML, "xml"),
		contentBoth("csv", easyrest.MediaTypeCSV, "csv"),
		contentBoth("form", easyrest.MediaTypeForm, "form"),
		contentParseOnly("parse-only", "application/parse-only", "parse-only"),
	}
}

func contentBoth(name, media, format string) contentPluginRef {
	return contentPluginRef{Name: name, ContentInfo: easyrest.NewContentInfo(media, media, format)}
}

func contentParseOnly(name, media, format string) contentPluginRef {
	return contentPluginRef{Name: name, ContentInfo: easyrest.ContentInfo{ParserMedia: media, Format: format}}
}

func contentRenderOnly(name, media, format string) contentPluginRef {
	return contentPluginRef{Name: name, ContentInfo: easyrest.NewContentInfo(media, "", format)}
}

func TestContentPairFill(t *testing.T) {
	parsers, renderers, ok := fillContentPair(nil, nil)
	if ok || parsers != nil || renderers != nil {
		t.Fatalf("unset parsers %#v renderers %#v ok %v", parsers, renderers, ok)
	}

	set := []string{"xml", "json"}
	parsers, renderers, ok = fillContentPair(&set, nil)
	if !ok || !slices.Equal(parsers, []string{"xml", "json"}) || !slices.Equal(renderers, []string{"xml", "json"}) {
		t.Fatalf("from parsers %#v %#v", parsers, renderers)
	}

	onlyRender := []string{"csv"}
	parsers, renderers, ok = fillContentPair(nil, &onlyRender)
	if !ok || !slices.Equal(parsers, []string{"csv"}) || !slices.Equal(renderers, []string{"csv"}) {
		t.Fatalf("from renderers %#v %#v", parsers, renderers)
	}

	empty := []string{}
	parsers, renderers, ok = fillContentPair(&empty, nil)
	if !ok || parsers == nil || len(parsers) != 0 || renderers == nil || len(renderers) != 0 {
		t.Fatalf("empty parsers %#v renderers %#v", parsers, renderers)
	}

	left := []string{"csv"}
	right := []string{"json", "xml"}
	parsers, renderers, ok = fillContentPair(&left, &right)
	if !ok || !slices.Equal(parsers, []string{"csv"}) || !slices.Equal(renderers, []string{"json", "xml"}) {
		t.Fatalf("both %#v %#v", parsers, renderers)
	}
}

func TestContentDirectionRefs(t *testing.T) {
	refs := []contentPluginRef{
		contentBoth("json", easyrest.MediaTypeJSON, "json"),
		contentParseOnly("parse-only", "application/parse-only", "parse-only"),
		contentRenderOnly("html", easyrest.MediaTypeHTML, "html"),
		contentBoth("csv", easyrest.MediaTypeCSV, "csv"),
	}
	parsers := contentDirectionRefs(refs, false)
	if names := contentRefNames(parsers); !slices.Equal(names, []string{"json", "parse-only", "csv"}) {
		t.Fatalf("parsers %#v", names)
	}
	renderers := contentDirectionRefs(refs, true)
	if names := contentRefNames(renderers); !slices.Equal(names, []string{"json", "html", "csv"}) {
		t.Fatalf("renderers %#v", names)
	}
}

func contentRefNames(refs []contentPluginRef) []string {
	names := make([]string, 0, len(refs))
	for _, ref := range refs {
		names = append(names, ref.Name)
	}
	return names
}

func TestContentLevels(t *testing.T) {
	actionParsers := []string{"csv"}
	endpointParsers := []string{"ndjson"}
	endpointHandlers := []string{"xml"}
	apiParsers := []string{"form"}
	appRenderers := []string{"json"}

	parsers, renderers := resolveContentNames([]contentLevel{
		{parsers: &actionParsers},
		{parsers: &endpointParsers, handlers: endpointHandlers},
		{parsers: &apiParsers},
		{renderers: &appRenderers},
	}, []string{"xml"}, []string{"json"})
	if !slices.Equal(parsers, []string{"csv"}) || !slices.Equal(renderers, []string{"csv"}) {
		t.Fatalf("action %#v %#v", parsers, renderers)
	}

	parsers, renderers = resolveContentNames([]contentLevel{
		{},
		{parsers: &endpointParsers, handlers: endpointHandlers},
	}, []string{"form"}, nil)
	if !slices.Equal(parsers, []string{"ndjson"}) || !slices.Equal(renderers, []string{"ndjson"}) {
		t.Fatalf("endpoint parsers beat handlers %#v %#v", parsers, renderers)
	}

	parsers, renderers = resolveContentNames([]contentLevel{
		{},
		{handlers: endpointHandlers},
		{parsers: &apiParsers},
	}, nil, nil)
	if !slices.Equal(parsers, []string{"xml"}) || !slices.Equal(renderers, []string{"xml"}) {
		t.Fatalf("endpoint handlers %#v %#v", parsers, renderers)
	}

	parsers, renderers = resolveContentNames([]contentLevel{
		{},
		{},
		{parsers: &apiParsers},
		{renderers: &appRenderers},
	}, []string{"csv"}, nil)
	if !slices.Equal(parsers, []string{"form"}) || !slices.Equal(renderers, []string{"form"}) {
		t.Fatalf("api %#v %#v", parsers, renderers)
	}

	parsers, renderers = resolveContentNames([]contentLevel{
		{},
		{},
		{},
		{renderers: &appRenderers},
	}, []string{"csv"}, []string{"xml"})
	if !slices.Equal(parsers, []string{"json"}) || !slices.Equal(renderers, []string{"json"}) {
		t.Fatalf("application %#v %#v", parsers, renderers)
	}

	parsers, renderers = resolveContentNames([]contentLevel{{}, {}, {}, {}}, []string{"csv"}, []string{"xml"})
	if !slices.Equal(parsers, []string{"csv"}) || !slices.Equal(renderers, []string{"csv"}) {
		t.Fatalf("plugin fallback %#v %#v", parsers, renderers)
	}

	parsers, renderers = resolveContentNames(nil, nil, []string{"xml", "json"})
	if !slices.Equal(parsers, []string{"xml", "json"}) || !slices.Equal(renderers, []string{"xml", "json"}) {
		t.Fatalf("default fallback %#v %#v", parsers, renderers)
	}
}

func TestNegotiateContentSameMedia(t *testing.T) {
	allowed := []contentPluginRef{
		contentBoth("first", easyrest.MediaTypeJSON, "first"),
		contentBoth("second", easyrest.MediaTypeJSON, "json"),
	}
	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	req.Header.Set("Accept", easyrest.MediaTypeJSON)
	choice := negotiateContent(req, nil, allowed)
	if choice.Renderer.Name != "first" || choice.Parser.Name != "first" {
		t.Fatalf("choice renderer %q parser %q", choice.Renderer.Name, choice.Parser.Name)
	}

	parsers := []contentPluginRef{contentBoth("csv", easyrest.MediaTypeCSV, "csv")}
	renderers := []contentPluginRef{contentBoth("json", easyrest.MediaTypeJSON, "json")}
	req = httptest.NewRequest(http.MethodPost, "/t", nil)
	req.Header.Set("Content-Type", easyrest.MediaTypeCSV)
	choice = negotiateContentLists(req, nil, parsers, renderers)
	if choice.ParseErr != nil || choice.Parser.Name != "csv" || choice.Renderer.Name != "json" {
		t.Fatalf("split parser %q renderer %q err %v", choice.Parser.Name, choice.Renderer.Name, choice.ParseErr)
	}
}

func TestContentHandlerNames(t *testing.T) {
	if got := contentHandlerNames([]string{"ndjson"}, []string{"xml"}, []string{"csv"}, []string{"json"}); len(got) != 1 || got[0] != "ndjson" {
		t.Fatalf("endpoint %#v", got)
	}
	if got := contentHandlerNames(nil, []string{"xml"}, []string{"csv"}, []string{"json"}); got[0] != "xml" {
		t.Fatalf("app %#v", got)
	}
	if got := contentHandlerNames(nil, nil, []string{"csv"}, []string{"json"}); got[0] != "csv" {
		t.Fatalf("plugin %#v", got)
	}
	if got := contentHandlerNames(nil, nil, nil, []string{"json", "csv"}); len(got) != 2 || got[1] != "csv" {
		t.Fatalf("default %#v", got)
	}
	got := contentHandlerNames(nil, nil, nil, nil)
	if len(got) != 5 || got[0] != "json" || got[4] != "form" {
		t.Fatalf("standards %#v", got)
	}
}

func TestNegotiateContent(t *testing.T) {
	allowed := testContentAllowed()
	cases := []struct {
		name     string
		method   string
		target   string
		accept   string
		ct       string
		query    url.Values
		renderer string
		parser   string
		parseErr bool
	}{
		{name: "format beats accept", target: "/t?format=csv", accept: easyrest.MediaTypeJSON, renderer: "csv", parser: "json"},
		{name: "format case", target: "/t", query: url.Values{"format": {"JSON"}}, renderer: "json", parser: "json"},
		{name: "unknown format falls through", target: "/t?format=bogus", accept: easyrest.MediaTypeCSV, renderer: "csv", parser: "json"},
		{name: "accept order", target: "/t", accept: "text/plain, text/csv;q=0.1, application/json", renderer: "json", parser: "json"},
		{name: "accept default q", target: "/t", accept: "text/csv;q=0.5, application/json", renderer: "json", parser: "json"},
		{name: "accept q zero skipped", target: "/t", accept: "application/json;q=0, text/csv", renderer: "csv", parser: "json"},
		{name: "accept equal q keeps order", target: "/t", accept: "application/xml, application/json", renderer: "xml", parser: "json"},
		{name: "star uses content type", target: "/t", accept: "*/*", ct: easyrest.MediaTypeCSV, renderer: "csv", parser: "csv"},
		{name: "empty accept uses content type", target: "/t", ct: easyrest.MediaTypeXML, renderer: "xml", parser: "xml"},
		{name: "empty selection is json", target: "/t", renderer: "json", parser: "json"},
		{name: "charset", target: "/t", accept: "application/json; charset=utf-8", renderer: "json", parser: "json"},
		{name: "unknown content type", target: "/t", ct: "application/octet-stream", renderer: "json", parseErr: true},
		{name: "parse only skipped for render", target: "/t?format=parse-only", accept: easyrest.MediaTypeXML, renderer: "xml", ct: "application/parse-only", parser: "parse-only"},
		{name: "accept skips parse only", target: "/t", accept: "application/parse-only, application/xml", renderer: "xml", parser: "json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptestNew(tc.method, tc.target)
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}
			if tc.ct != "" {
				req.Header.Set("Content-Type", tc.ct)
			}
			got := negotiateContent(req, tc.query, allowed)
			if got.Renderer.Name != tc.renderer {
				t.Fatalf("renderer %s, want %s", got.Renderer.Name, tc.renderer)
			}
			if tc.parseErr {
				if got.ParseErr == nil || !strings.Contains(got.ParseErr.Error(), "unsupported Content-Type") {
					t.Fatalf("parse err %v", got.ParseErr)
				}
				return
			}
			if got.ParseErr != nil || got.Parser.Name != tc.parser {
				t.Fatalf("parser %s err %v", got.Parser.Name, got.ParseErr)
			}
		})
	}

	req := httptestNew(http.MethodGet, "/t")
	got := negotiateContent(req, nil, []contentPluginRef{contentRenderOnly("csv", easyrest.MediaTypeCSV, "csv")})
	if got.Renderer.Name != "csv" || got.ParseErr == nil {
		t.Fatalf("render-only %+v", got)
	}
	if negotiateContent(req, nil, nil).Renderer.Name != "" {
		t.Fatal("expected no renderer")
	}
}

func TestNegotiateAcceptParams(t *testing.T) {
	allowed := testContentAllowed()
	req := httptestNew(http.MethodGet, "/t")
	req.Header.Set("Accept", "application/json; charset=utf-8; indent=2")
	got := negotiateContent(req, nil, allowed)
	if got.Renderer.Name != "json" {
		t.Fatalf("renderer %s", got.Renderer.Name)
	}
	if got.Renderer.Params["charset"] != "utf-8" || got.Renderer.Params["indent"] != "2" {
		t.Fatalf("params %#v", got.Renderer.Params)
	}
	if _, ok := got.Renderer.Params["q"]; ok {
		t.Fatal("q is not a content param")
	}
	if allowed[0].Params != nil {
		t.Fatal("allowed catalog was mutated")
	}
}

type paramSpy struct {
	easyrest.ContentBase
	ctx map[string]any
}

func (paramSpy) Init(map[string]any) (easyrest.ContentInfo, error) {
	return easyrest.NewContentInfo(easyrest.MediaTypeJSON, "", "json"), nil
}

func (p *paramSpy) Render(data any, ctx map[string]any) (any, map[string]any, error) {
	p.ctx = ctx
	return []byte("ok"), ctx, nil
}

func TestRenderCtxReceivesAcceptParams(t *testing.T) {
	spy := &paramSpy{}
	ref := contentPluginRef{
		Plugin:      spy,
		ContentInfo: easyrest.NewContentInfo(easyrest.MediaTypeJSON, "", "json"),
		Params:      map[string]string{"indent": "2", "charset": "utf-8"},
	}
	w := httptest.NewRecorder()
	cw := newContentWriter(w, httptestNew(http.MethodGet, "/t"), "", nil, nil, ref, false)
	if err := cw.Write(http.StatusOK, map[string]any{"a": 1}, nil); err != nil {
		t.Fatal(err)
	}
	params, _ := spy.ctx[easyrest.CtxContentParams].(map[string]string)
	if params["indent"] != "2" || params["charset"] != "utf-8" {
		t.Fatalf("ctx %#v", spy.ctx)
	}
}

func TestRenderCtxSwaggerFlag(t *testing.T) {
	spy := &paramSpy{}
	ref := contentPluginRef{Plugin: spy, ContentInfo: easyrest.NewContentInfo(easyrest.MediaTypeJSON, "", "json")}
	w := httptest.NewRecorder()
	cw := newContentWriter(w, httptestNew(http.MethodGet, "/t"), "", nil, nil, ref, false)
	if err := cw.Write(http.StatusOK, map[string]any{"a": 1}, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := spy.ctx[easyrest.CtxSwagger]; ok {
		t.Fatalf("unset render ctx leaked %#v", spy.ctx)
	}
	spy.ctx = nil
	cw = newContentWriter(w, httptestNew(http.MethodGet, "/t"), "", nil, nil, ref, false)
	cw.setRenderCtx(map[string]any{easyrest.CtxSwagger: easyrest.SwaggerDocument})
	if err := cw.Write(http.StatusOK, map[string]any{"a": 1}, nil); err != nil {
		t.Fatal(err)
	}
	if spy.ctx[easyrest.CtxSwagger] != easyrest.SwaggerDocument {
		t.Fatalf("ctx %#v", spy.ctx)
	}
}

func TestFirstDocumentFormat(t *testing.T) {
	prev := contentPlugins.Load()
	t.Cleanup(func() { contentPlugins.Store(prev) })
	loaded := map[string]contentPluginRef{
		"json": contentBoth("json", easyrest.MediaTypeJSON, "json"),
		"yaml": contentBoth("yaml", easyrest.MediaTypeYAML, "yaml"),
		"html": contentRenderOnly("html", easyrest.MediaTypeHTML, "html"),
	}
	contentPlugins.Store(&loaded)

	cases := []struct {
		name  string
		names []string
		want  string
	}{
		{name: "json is first", names: []string{"json", "yaml"}, want: "json"},
		{name: "html skipped", names: []string{"html", "json"}, want: "json"},
		{name: "yaml before json", names: []string{"missing", "yaml", "json"}, want: "yaml"},
		{name: "only html falls back to json", names: []string{"html"}, want: "json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstDocumentFormat(tc.names); got != tc.want {
				t.Fatalf("firstDocumentFormat(%v) = %q, want %q", tc.names, got, tc.want)
			}
		})
	}
}

func TestSelectParserEmptyContentType(t *testing.T) {
	yamlFirst := []contentPluginRef{
		contentBoth("yaml", easyrest.MediaTypeYAML, "yaml"),
		contentBoth("json", easyrest.MediaTypeJSON, "json"),
	}
	req := httptestNew(http.MethodPost, "/t")
	got := negotiateContent(req, nil, yamlFirst)
	if got.ParseErr != nil || got.Parser.Name != "yaml" {
		t.Fatalf("yaml first parser %s err %v", got.Parser.Name, got.ParseErr)
	}

	htmlThenYAML := []contentPluginRef{
		contentRenderOnly("html", easyrest.MediaTypeHTML, "html"),
		contentBoth("yaml", easyrest.MediaTypeYAML, "yaml"),
	}
	got = negotiateContent(req, nil, htmlThenYAML)
	if got.ParseErr != nil || got.Parser.Name != "yaml" {
		t.Fatalf("skip render-only parser %s err %v", got.Parser.Name, got.ParseErr)
	}

	got = negotiateContent(req, nil, []contentPluginRef{contentRenderOnly("html", easyrest.MediaTypeHTML, "html")})
	if got.ParseErr == nil || !strings.Contains(got.ParseErr.Error(), "unsupported Content-Type") {
		t.Fatalf("no parser err %v", got.ParseErr)
	}
}

func httptestNew(method, target string) *http.Request {
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		panic(err)
	}
	return req
}
