package server

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// contentPluginRef is one loaded content plugin plus the identity returned by Init.
type contentPluginRef struct {
	Name   string
	Plugin easyrest.ContentPlugin
	easyrest.ContentInfo
	// Params are media-type parameters from the matched Accept token.
	// The shared catalog leaves this nil.
	Params map[string]string
}

// contentChoice is the parser and renderer for one request.
// ParseErr is set when the request Content-Type has no parser in the allowed list.
// Callers that do not read a body ignore ParseErr.
type contentChoice struct {
	Parser   contentPluginRef
	Renderer contentPluginRef
	ParseErr error
}

// contentHandlerNames picks the first non-empty handler list.
// Order is endpoint, REST app, db plugin, then the process default.
// An empty selection uses the preserved standard plugins.
func contentHandlerNames(endpoint, app, pluginNames, defaults []string) []string {
	switch {
	case len(endpoint) > 0:
		return endpoint
	case len(app) > 0:
		return app
	case len(pluginNames) > 0:
		return pluginNames
	case len(defaults) > 0:
		return defaults
	default:
		return easyrest.StandardContentNames()
	}
}

// fillContentPair copies a set list onto a nil opposite list.
// Both nil means this level does not choose. Both set stay independent.
func fillContentPair(parsers, renderers *[]string) ([]string, []string, bool) {
	if parsers == nil && renderers == nil {
		return nil, nil, false
	}
	if parsers == nil {
		parsers = renderers
	}
	if renderers == nil {
		renderers = parsers
	}
	return *parsers, *renderers, true
}

// contentDirectionRefs keeps plugins that implement the requested direction.
// render false keeps parsers. render true keeps renderers. Order is unchanged.
func contentDirectionRefs(refs []contentPluginRef, render bool) []contentPluginRef {
	out := make([]contentPluginRef, 0, len(refs))
	for _, ref := range refs {
		if render && ref.RenderMedia == "" {
			continue
		}
		if !render && ref.ParserMedia == "" {
			continue
		}
		out = append(out, ref)
	}
	return out
}

// contentLevel is one config scope. Parsers and renderers win over handlers.
// handlers is the legacy content_handlers list and applies only when both pointers are nil.
type contentLevel struct {
	parsers   *[]string
	renderers *[]string
	handlers  []string
}

// resolveContentNames returns parser and renderer names from the first level that chooses.
// pluginNames and defaults are the existing fallback after every level is unset.
func resolveContentNames(levels []contentLevel, pluginNames, defaults []string) ([]string, []string) {
	for _, level := range levels {
		parsers, renderers, ok := fillContentPair(level.parsers, level.renderers)
		if ok {
			return parsers, renderers
		}
		if len(level.handlers) > 0 {
			return level.handlers, level.handlers
		}
	}
	fallback := contentHandlerNames(nil, nil, pluginNames, defaults)
	return fallback, fallback
}

// negotiateContent selects a parser from Content-Type and a renderer from
// format, Accept, Content-Type, then the first allowed renderer.
func negotiateContent(r *http.Request, query url.Values, allowed []contentPluginRef) contentChoice {
	return negotiateContentLists(r, query, allowed, allowed)
}

// negotiateContentLists matches the parser list and the renderer list separately.
func negotiateContentLists(r *http.Request, query url.Values, parsers, renderers []contentPluginRef) contentChoice {
	var choice contentChoice
	choice.Parser, choice.ParseErr = selectParser(r, parsers)
	choice.Renderer = selectRenderer(r, query, renderers)
	return choice
}

func selectParser(r *http.Request, allowed []contentPluginRef) (contentPluginRef, error) {
	ct := mediaType(r.Header.Get("Content-Type"))
	if ct == "" {
		if plug, ok := findParser(allowed, func(contentPluginRef) bool { return true }); ok {
			return plug, nil
		}
		return contentPluginRef{}, fmt.Errorf("unsupported Content-Type")
	}
	if plug, ok := findParser(allowed, func(p contentPluginRef) bool {
		return strings.EqualFold(p.ParserMedia, ct)
	}); ok {
		return plug, nil
	}
	return contentPluginRef{}, fmt.Errorf("unsupported Content-Type: %s", ct)
}

func selectRenderer(r *http.Request, query url.Values, allowed []contentPluginRef) contentPluginRef {
	if format := strings.TrimSpace(queryFormat(r, query)); format != "" {
		if plug, ok := findRenderer(allowed, func(p contentPluginRef) bool {
			return strings.EqualFold(p.Format, format) || strings.EqualFold(p.RenderMedia, format)
		}); ok {
			return plug
		}
	}
	accept := r.Header.Get("Accept")
	if accept != "" && strings.TrimSpace(accept) != "*/*" {
		if strings.IndexByte(accept, ',') < 0 {
			media, q, params := acceptMediaQ(accept)
			if plug, ok := matchAcceptOffer(allowed, media, q, params); ok {
				return plug
			}
		} else {
			for _, offer := range parseAccept(accept) {
				if plug, ok := matchAcceptOffer(allowed, offer.media, offer.q, offer.params); ok {
					return plug
				}
			}
		}
	}
	if ct := mediaType(r.Header.Get("Content-Type")); ct != "" {
		if plug, ok := findRenderer(allowed, func(p contentPluginRef) bool {
			return strings.EqualFold(p.RenderMedia, ct)
		}); ok {
			return plug
		}
	}
	if plug, ok := findRenderer(allowed, func(contentPluginRef) bool { return true }); ok {
		return plug
	}
	return contentPluginRef{}
}

// firstDocumentFormat is the first allowed renderer that is not HTML.
// A missing name is skipped. An empty or all-HTML list falls back to json.
func firstDocumentFormat(names []string) string {
	for _, ref := range contentRefsNamed(names) {
		if ref.RenderMedia == "" || strings.EqualFold(ref.RenderMedia, easyrest.MediaTypeHTML) {
			continue
		}
		if ref.Format != "" {
			return ref.Format
		}
	}
	return "json"
}

// acceptOffer is one Accept media range. q is 0..1000; 1000 is the default 1.0.
// q 0 is omitted: that range is not acceptable.
type acceptOffer struct {
	media  string
	q      uint16
	params map[string]string
}

func matchAcceptOffer(allowed []contentPluginRef, media string, q uint16, params map[string]string) (contentPluginRef, bool) {
	if media == "" || media == "*/*" || q == 0 {
		return contentPluginRef{}, false
	}
	plug, ok := findRenderer(allowed, func(p contentPluginRef) bool {
		return strings.EqualFold(p.RenderMedia, media)
	})
	if !ok {
		return contentPluginRef{}, false
	}
	plug.Params = params
	return plug, true
}

func parseAccept(header string) []acceptOffer {
	n := 1
	for i := 0; i < len(header); i++ {
		if header[i] == ',' {
			n++
		}
	}
	offers := make([]acceptOffer, 0, n)
	start := 0
	for i := 0; i <= len(header); i++ {
		if i < len(header) && header[i] != ',' {
			continue
		}
		media, q, params := acceptMediaQ(header[start:i])
		start = i + 1
		if media == "" || q == 0 {
			continue
		}
		offers = append(offers, acceptOffer{media: media, q: q, params: params})
	}
	if len(offers) > 1 {
		slices.SortStableFunc(offers, func(a, b acceptOffer) int {
			return int(b.q) - int(a.q)
		})
	}
	return offers
}

func acceptMediaQ(token string) (string, uint16, map[string]string) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", 0, nil
	}
	media := token
	rest := ""
	if before, after, ok := strings.Cut(token, ";"); ok {
		media = strings.TrimSpace(before)
		rest = after
	}
	q := uint16(1000)
	var params map[string]string
	for rest != "" {
		param := rest
		if i := strings.IndexByte(rest, ';'); i >= 0 {
			param = rest[:i]
			rest = rest[i+1:]
		} else {
			rest = ""
		}
		name, value, ok := splitAcceptParam(param)
		if !ok {
			continue
		}
		if name == "q" {
			q = parseQ(value)
			continue
		}
		if params == nil {
			params = make(map[string]string, 2)
		}
		params[name] = value
	}
	return media, q, params
}

func splitAcceptParam(param string) (string, string, bool) {
	param = strings.TrimSpace(param)
	eq := strings.IndexByte(param, '=')
	if eq <= 0 {
		return "", "", false
	}
	name := strings.ToLower(strings.TrimSpace(param[:eq]))
	value := strings.TrimSpace(param[eq+1:])
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	if name == "" {
		return "", "", false
	}
	return name, value, true
}

// parseQ reads an RFC 9110 qvalue into thousandths. A missing or invalid value is 0.
func parseQ(s string) uint16 {
	if s == "" || len(s) > 5 {
		return 0
	}
	if s[0] == '1' {
		if len(s) == 1 {
			return 1000
		}
		if s[1] != '.' {
			return 0
		}
		for i := 2; i < len(s); i++ {
			if s[i] != '0' {
				return 0
			}
		}
		return 1000
	}
	if s[0] != '0' {
		return 0
	}
	if len(s) == 1 {
		return 0
	}
	if s[1] != '.' {
		return 0
	}
	var v uint16
	scale := uint16(100)
	for i := 2; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0
		}
		v += uint16(c-'0') * scale
		scale /= 10
	}
	return v
}

func findParser(allowed []contentPluginRef, match func(contentPluginRef) bool) (contentPluginRef, bool) {
	for _, plug := range allowed {
		if plug.ParserMedia == "" || !match(plug) {
			continue
		}
		return plug, true
	}
	return contentPluginRef{}, false
}

func findRenderer(allowed []contentPluginRef, match func(contentPluginRef) bool) (contentPluginRef, bool) {
	for _, plug := range allowed {
		if plug.RenderMedia == "" || !match(plug) {
			continue
		}
		return plug, true
	}
	return contentPluginRef{}, false
}
