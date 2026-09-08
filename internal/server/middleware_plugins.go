package server

import (
	"fmt"
	stdlog "log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-json"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

const responseHeaderPrefix = "response.header."

func resolveMiddlewareNames(names []string, cfg config.Config, loaded map[string]easyrest.MiddlewarePlugin) []easyrest.MiddlewarePlugin {
	if len(names) == 0 {
		return nil
	}
	out := make([]easyrest.MiddlewarePlugin, 0, len(names))
	for _, name := range names {
		if _, ok := cfg.MiddlewarePlugins[name]; !ok {
			stdlog.Printf("Error: middleware plugin %q not found in middleware_plugins", name)
			continue
		}
		plug, ok := loaded[name]
		if !ok {
			stdlog.Printf("Error: middleware plugin %q not loaded", name)
			continue
		}
		out = append(out, plug)
	}
	return out
}

func buildMiddlewareChains(
	cfg config.Config,
	loaded map[string]easyrest.MiddlewarePlugin,
) ([]easyrest.MiddlewarePlugin, map[string][]easyrest.MiddlewarePlugin) {
	global := resolveMiddlewareNames(cfg.GlobalRequestMiddlewares, cfg, loaded)

	perDb := make(map[string][]easyrest.MiddlewarePlugin)
	for dbKey, plCfg := range cfg.PluginMap {
		local := resolveMiddlewareNames(plCfg.RequestMiddlewares, cfg, loaded)
		if len(global) == 0 && len(local) == 0 {
			continue
		}
		chain := make([]easyrest.MiddlewarePlugin, 0, len(global)+len(local))
		chain = append(chain, global...)
		chain = append(chain, local...)
		perDb[dbKey] = chain
	}
	return global, perDb
}

func middlewareChain(dbKey string) []easyrest.MiddlewarePlugin {
	var plugs []easyrest.MiddlewarePlugin
	if chains := dbMiddlewareOrder.Load(); chains != nil {
		plugs = (*chains)[dbKey]
	}
	if plugs == nil {
		if g := globalMiddlewareChain.Load(); g != nil {
			plugs = *g
		}
	}
	return plugs
}

func applyReturnedPluginContext(current, returned map[string]any) map[string]any {
	if returned != nil {
		return returned
	}
	return current
}

func runPreRequestMiddlewares(w http.ResponseWriter, dbKey string, pluginCtx map[string]any) (map[string]any, bool) {
	plugs := middlewareChain(dbKey)
	if len(plugs) == 0 {
		return pluginCtx, true
	}

	currentCtx := pluginCtx
	for _, plug := range plugs {
		updatedCtx, status, err := plug.PreRequest(dbKey, currentCtx)
		if updatedCtx != nil {
			currentCtx = updatedCtx
		}
		if status != nil {
			applyContextResponseHeaders(w, currentCtx)
			w.WriteHeader(*status)
			if err != nil {
				_, _ = w.Write([]byte(err.Error()))
			}
			return currentCtx, false
		}
		if err != nil {
			applyContextResponseHeaders(w, currentCtx)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(err.Error()))
			return currentCtx, false
		}
	}
	return currentCtx, true
}

func runPostRequestMiddlewares(w http.ResponseWriter, dbKey string, pluginCtx map[string]any) {
	plugs := middlewareChain(dbKey)
	if len(plugs) == 0 {
		return
	}
	for _, plug := range plugs {
		headers, err := plug.PostRequest(dbKey, pluginCtx)
		if err != nil {
			stdlog.Printf("Error: middleware plugin PostRequest for %q: %v", dbKey, err)
		}
		for k, v := range headers {
			if k == "" {
				continue
			}
			w.Header().Add(k, v)
		}
	}
}

func applyContextResponseHeaders(w http.ResponseWriter, pluginCtx map[string]any) {
	if pluginCtx == nil {
		return
	}

	prefixKeys := make([]string, 0)
	for k := range pluginCtx {
		if strings.HasPrefix(k, responseHeaderPrefix) {
			prefixKeys = append(prefixKeys, k)
		}
	}
	_, hasHeadersArray := pluginCtx["response.headers"]
	if len(prefixKeys) == 0 && !hasHeadersArray {
		return
	}

	type pair struct{ name, value string }
	pairs := make([]pair, 0, len(prefixKeys))
	sort.Strings(prefixKeys)
	for _, k := range prefixKeys {
		name := k[len(responseHeaderPrefix):]
		if name == "" {
			continue
		}
		pairs = append(pairs, pair{name, headerValueString(pluginCtx[k])})
	}

	if raw, ok := pluginCtx["response.headers"]; ok {
		objs, err := parseResponseHeadersArray(raw)
		if err != nil {
			stdlog.Printf("Error: parse response.headers: %v", err)
		} else {
			for _, obj := range objs {
				for name, v := range obj {
					if name == "" {
						continue
					}
					pairs = append(pairs, pair{name, headerValueString(v)})
				}
			}
		}
	}

	type group struct {
		name   string
		values []string
	}
	order := make([]string, 0)
	groups := make(map[string]*group)
	for _, p := range pairs {
		canon := http.CanonicalHeaderKey(p.name)
		if canon == "" {
			continue
		}
		g, ok := groups[canon]
		if !ok {
			g = &group{name: p.name}
			groups[canon] = g
			order = append(order, canon)
		}
		g.values = append(g.values, p.value)
	}
	for _, canon := range order {
		g := groups[canon]
		w.Header().Add(g.name, strings.Join(g.values, ", "))
	}
}

func headerValueString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

func parseResponseHeadersArray(v any) ([]map[string]any, error) {
	switch t := v.(type) {
	case []map[string]any:
		return t, nil
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, item := range t {
			m, ok := item.(map[string]any)
			if !ok {
				b, err := json.Marshal(item)
				if err != nil {
					return nil, err
				}
				var mm map[string]any
				if err := json.Unmarshal(b, &mm); err != nil {
					return nil, err
				}
				out = append(out, mm)
				continue
			}
			out = append(out, m)
		}
		return out, nil
	}

	var data []byte
	switch t := v.(type) {
	case string:
		data = []byte(t)
	case []byte:
		data = t
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		data = b
	}
	var out []map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func statusFromPluginContext(pluginCtx map[string]any, fallback int) int {
	if pluginCtx == nil {
		return fallback
	}
	raw, ok := pluginCtx["response.status"]
	if !ok {
		return fallback
	}
	code, ok := httpStatusCode(raw)
	if !ok {
		stdlog.Printf("Error: invalid response.status %#v", raw)
		return http.StatusInternalServerError
	}
	return code
}

func httpStatusCode(v any) (int, bool) {
	var n int
	switch t := v.(type) {
	case int:
		n = t
	case int64:
		n = int(t)
	case float64:
		if t != float64(int(t)) {
			return 0, false
		}
		n = int(t)
	case json.Number:
		i, err := t.Int64()
		if err != nil {
			return 0, false
		}
		n = int(i)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return 0, false
		}
		n = parsed
	default:
		return 0, false
	}
	if n < 100 || n > 599 {
		return 0, false
	}
	return n, true
}

func setHandlerStatus(pluginCtx map[string]any, code int) {
	if pluginCtx != nil {
		pluginCtx[easyrest.CtxHandlerStatus] = code
	}
}

func middlewareHTTPError(w http.ResponseWriter, dbKey string, pluginCtx map[string]any, msg string, code int) {
	setHandlerStatus(pluginCtx, code)
	runPostRequestMiddlewares(w, dbKey, pluginCtx)
	applyContextResponseHeaders(w, pluginCtx)
	http.Error(w, msg, code)
}

func middlewareWriteHeader(w http.ResponseWriter, dbKey string, pluginCtx map[string]any, code int) {
	setHandlerStatus(pluginCtx, code)
	runPostRequestMiddlewares(w, dbKey, pluginCtx)
	applyContextResponseHeaders(w, pluginCtx)
	w.WriteHeader(statusFromPluginContext(pluginCtx, code))
}

func middlewareMakeResponse(w http.ResponseWriter, r *http.Request, dbKey string, pluginCtx map[string]any, status int, v any, query url.Values) {
	setHandlerStatus(pluginCtx, status)
	runPostRequestMiddlewares(w, dbKey, pluginCtx)
	applyContextResponseHeaders(w, pluginCtx)
	status = statusFromPluginContext(pluginCtx, status)
	if query == nil {
		makeResponse(w, r, status, v)
		return
	}
	makeResponseWithQuery(w, r, status, v, query)
}

func middlewareRespondJSON(w http.ResponseWriter, dbKey string, pluginCtx map[string]any, status int, v any) {
	setHandlerStatus(pluginCtx, status)
	runPostRequestMiddlewares(w, dbKey, pluginCtx)
	applyContextResponseHeaders(w, pluginCtx)
	respondJSON(w, statusFromPluginContext(pluginCtx, status), v)
}
