package responseheaders

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/goccy/go-json"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

const (
	responseHeaderPrefix = "response.header."
	ctxResponseHeaders   = "response.headers"
)

type conflictMode int

const (
	modeSkip      conflictMode = 0
	modeOverwrite conflictMode = 1
	modeAppend    conflictMode = 2
)

type headerPair struct {
	name  string
	value string
}

var _ easyrest.MiddlewarePlugin = (*Plugin)(nil)

// Plugin sets static response headers on the request context in PostRequest.
type Plugin struct {
	host    easyrest.HostRPC
	headers []headerPair
	mode    conflictMode
}

// New returns an uninitialized plugin. Call Init before PreRequest.
func New() *Plugin {
	return &Plugin{}
}

// Init validates settings and stores header names and values.
func (p *Plugin) Init(settings map[string]any, host easyrest.HostRPC) (easyrest.MiddlewareInfo, error) {
	p.host = host
	if err := p.initSettings(settings); err != nil {
		return easyrest.MiddlewareInfo{}, err
	}
	return easyrest.NewMiddlewareInfo(), nil
}

func (p *Plugin) initSettings(settings map[string]any) error {
	if settings == nil {
		settings = map[string]any{}
	}
	mode, err := parseConflictMode(settings["on_conflict"])
	if err != nil {
		return err
	}
	raw, ok := settings["headers"]
	if !ok {
		return errors.New("headers is required")
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return errors.New("headers must be a map")
	}
	if len(m) == 0 {
		return errors.New("headers must not be empty")
	}
	seen := make(map[string]string)
	pairs := make([]headerPair, 0, len(m))
	for name, val := range m {
		name = strings.TrimSpace(name)
		if name == "" {
			return errors.New("header name must not be empty")
		}
		s, ok := val.(string)
		if !ok {
			return fmt.Errorf("header %q value must be a string", name)
		}
		canon := http.CanonicalHeaderKey(name)
		if other, dup := seen[canon]; dup {
			return fmt.Errorf("duplicate header %q and %q", other, name)
		}
		seen[canon] = name
		pairs = append(pairs, headerPair{name: canon, value: s})
	}
	p.mode = mode
	p.headers = pairs
	return nil
}

func parseConflictMode(v any) (conflictMode, error) {
	if v == nil {
		return modeSkip, nil
	}
	s, ok := v.(string)
	if !ok {
		return 0, errors.New("on_conflict must be a string")
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "skip", "":
		return modeSkip, nil
	case "overwrite":
		return modeOverwrite, nil
	case "append":
		return modeAppend, nil
	default:
		return 0, errors.New("on_conflict must be skip, overwrite, or append")
	}
}

// PreRequest does not modify the context.
func (p *Plugin) PreRequest(_ string, ctx map[string]any) (map[string]any, *int, error) {
	return ctx, nil, nil
}

// PostRequest writes configured headers onto the context for the host to emit.
func (p *Plugin) PostRequest(_ string, ctx map[string]any) (map[string]string, error) {
	if ctx == nil {
		ctx = map[string]any{}
	}
	for _, h := range p.headers {
		applyHeader(ctx, h.name, h.value, p.mode)
	}
	return nil, nil
}

func applyHeader(ctx map[string]any, canonName, value string, mode conflictMode) {
	existing := collectHeaderValues(ctx, canonName)
	switch mode {
	case modeSkip:
		if len(existing) > 0 {
			return
		}
		ctx[responseHeaderPrefix+canonName] = value
	case modeOverwrite:
		removeHeaderValues(ctx, canonName)
		ctx[responseHeaderPrefix+canonName] = value
	case modeAppend:
		if len(existing) == 0 {
			ctx[responseHeaderPrefix+canonName] = value
			return
		}
		removeHeaderValues(ctx, canonName)
		ctx[responseHeaderPrefix+canonName] = strings.Join(existing, ", ") + ", " + value
	}
}

func collectHeaderValues(ctx map[string]any, canonName string) []string {
	var prefixKeys []string
	for k := range ctx {
		if !strings.HasPrefix(k, responseHeaderPrefix) {
			continue
		}
		name := k[len(responseHeaderPrefix):]
		if name == "" {
			continue
		}
		if http.CanonicalHeaderKey(name) == canonName {
			prefixKeys = append(prefixKeys, k)
		}
	}
	sort.Strings(prefixKeys)
	out := make([]string, 0, len(prefixKeys))
	for _, k := range prefixKeys {
		out = append(out, headerValueString(ctx[k]))
	}
	raw, ok := ctx[ctxResponseHeaders]
	if !ok {
		return out
	}
	objs, err := parseResponseHeadersArray(raw)
	if err != nil {
		return out
	}
	for _, obj := range objs {
		for name, v := range obj {
			if http.CanonicalHeaderKey(name) == canonName {
				out = append(out, headerValueString(v))
			}
		}
	}
	return out
}

func removeHeaderValues(ctx map[string]any, canonName string) {
	for k := range ctx {
		if !strings.HasPrefix(k, responseHeaderPrefix) {
			continue
		}
		name := k[len(responseHeaderPrefix):]
		if name != "" && http.CanonicalHeaderKey(name) == canonName {
			delete(ctx, k)
		}
	}
	raw, ok := ctx[ctxResponseHeaders]
	if !ok {
		return
	}
	objs, err := parseResponseHeadersArray(raw)
	if err != nil {
		return
	}
	filtered := make([]map[string]any, 0, len(objs))
	for _, obj := range objs {
		next := map[string]any{}
		for name, v := range obj {
			if http.CanonicalHeaderKey(name) == canonName {
				continue
			}
			next[name] = v
		}
		if len(next) > 0 {
			filtered = append(filtered, next)
		}
	}
	writeResponseHeaders(ctx, raw, filtered)
}

func writeResponseHeaders(ctx map[string]any, original any, objs []map[string]any) {
	switch original.(type) {
	case nil:
		if len(objs) == 0 {
			delete(ctx, ctxResponseHeaders)
			return
		}
		ctx[ctxResponseHeaders] = objs
	case string:
		if len(objs) == 0 {
			delete(ctx, ctxResponseHeaders)
			return
		}
		b, err := json.Marshal(objs)
		if err != nil {
			ctx[ctxResponseHeaders] = objs
			return
		}
		ctx[ctxResponseHeaders] = string(b)
	case []byte:
		if len(objs) == 0 {
			delete(ctx, ctxResponseHeaders)
			return
		}
		b, err := json.Marshal(objs)
		if err != nil {
			ctx[ctxResponseHeaders] = objs
			return
		}
		ctx[ctxResponseHeaders] = b
	default:
		if len(objs) == 0 {
			delete(ctx, ctxResponseHeaders)
			return
		}
		ctx[ctxResponseHeaders] = objs
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
