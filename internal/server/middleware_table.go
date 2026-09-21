package server

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"slices"

	"github.com/go-chi/chi/v5"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// resourceSpec describes how to resolve a DB plugin for a named resource.
// Table handlers pass tableResource; RPC/QUERY can pass their own later.
type resourceSpec struct {
	exclude  func(config.PluginConfig) []string
	allow    func(config.PluginConfig) []string
	reserved []string
	public   func(config.PluginConfig, string) bool
}

var tableResource = resourceSpec{
	exclude:  func(c config.PluginConfig) []string { return c.Exclude.Table },
	allow:    func(c config.PluginConfig) []string { return c.AllowList.Table },
	reserved: []string{"easyrest_cache"},
	public: func(c config.PluginConfig, name string) bool {
		return slices.Contains(c.Public.Table, name)
	},
}

func sanitizeTableMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bag, r := newAPIRequest(r)
		defer releaseAPIRequest(bag)
		bag.dbKey = strings.ToLower(chi.URLParam(r, "db"))
		bag.resource = chi.URLParam(r, "table")
		bag.query = r.URL.Query()
		if err := sanitizeIdentifier(bag.resource); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requirePluginMiddleware(spec resourceSpec) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bag := apiRequestFrom(r)
			preCfg := currentConfig()
			prePluginCfg := preCfg.PluginMap[bag.dbKey]
			var exclude, allow []string
			if spec.exclude != nil {
				exclude = spec.exclude(prePluginCfg)
			}
			if spec.allow != nil {
				allow = spec.allow(prePluginCfg)
			}
			dbPlug, cfg, pluginCfg, ok := resolveDBPlugin(w, bag.dbKey, bag.resource, exclude, allow, spec.reserved)
			if !ok {
				return
			}
			bag.dbPlug = dbPlug
			bag.cfg = cfg
			bag.pluginCfg = pluginCfg
			if spec.public != nil {
				bag.isPublic = spec.public(pluginCfg, bag.resource)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func authenticateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bag := apiRequestFrom(r)
		userID, r, err := Authenticate(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		bag.userID = userID
		next.ServeHTTP(w, r)
	})
}

func tableScopeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bag := apiRequestFrom(r)
		var requiredScope string
		if r.Method == http.MethodGet {
			requiredScope = tableScope(bag.resource, "-read")
		} else {
			requiredScope = tableScope(bag.resource, "-write")
		}
		if !enforceScope(w, r, bag.cfg.CheckScope, bag.isPublic, requiredScope) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func tablePreRequestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bag := apiRequestFrom(r)
		pluginCtx := BuildPluginContext(r)
		typ, _ := negotiateResponseType(r, bag.query)
		bag.respType = typ
		if len(middlewareChain(bag.dbKey)) > 0 {
			pluginCtx[easyrest.CtxCacheETagVariant] = cacheVaryFingerprint(typ, r, pluginCtx)
		}
		if r.Method == http.MethodGet {
			addResponseFormatVary(w)
		}
		pluginCtx, ok := runPreRequestMiddlewares(w, bag.dbKey, pluginCtx)
		if !ok {
			return
		}
		setPreferenceApplied(w, pluginCtx)
		bag.pluginCtx = pluginCtx
		next.ServeHTTP(w, r)
	})
}

func cacheVaryFingerprint(accept string, r *http.Request, pluginCtx map[string]any) string {
	if accept == "" {
		accept = "application/json"
	}
	var b strings.Builder
	b.WriteString("Accept=")
	b.WriteString(accept)
	b.WriteByte('\n')
	b.WriteString("Content-Type=")
	b.WriteString(mediaType(r.Header.Get("Content-Type")))
	b.WriteByte('\n')
	b.WriteString("Prefer=")
	b.WriteString(preferFingerprint(pluginCtx))
	b.WriteByte('\n')
	b.WriteString("Range=")
	b.WriteString(r.Header.Get("Range"))
	b.WriteByte('\n')
	b.WriteString("Range-Unit=")
	b.WriteString(r.Header.Get("Range-Unit"))
	return b.String()
}

func preferFingerprint(pluginCtx map[string]any) string {
	prefer, _ := pluginCtx["prefer"].(map[string]any)
	n := 0
	if prefer != nil {
		n = len(prefer)
	}
	vals := make(map[string]string, n+1)
	for k, v := range prefer {
		switch t := v.(type) {
		case string:
			vals[k] = t
		case nil:
			vals[k] = ""
		default:
			vals[k] = fmt.Sprint(t)
		}
	}
	if _, ok := vals["timezone"]; !ok {
		if tz, _ := pluginCtx["timezone"].(string); tz != "" {
			vals["timezone"] = tz
		}
	}
	if len(vals) == 0 {
		return ""
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(vals[k])
	}
	return b.String()
}

func tableMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	bag := apiRequestFrom(r)
	middlewareHTTPError(w, bag.dbKey, bag.pluginCtx, "Method not allowed", http.StatusMethodNotAllowed)
}
