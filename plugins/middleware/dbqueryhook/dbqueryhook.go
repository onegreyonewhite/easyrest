package dbqueryhook

import (
	"fmt"
	"maps"
	"strings"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

var _ easyrest.MiddlewarePlugin = (*Plugin)(nil)

type hookField struct {
	set bool
	val string
}

type hookRules struct {
	pre, post hookField
}

// Plugin sets db.pre-request / db.post-request from Init-compiled YAML rules.
type Plugin struct {
	host   easyrest.HostRPC
	byType map[string]hookRules
	byKey  map[string]hookRules
}

// New returns an uninitialized hook plugin. Call Init before PreRequest.
func New() *Plugin {
	return &Plugin{}
}

// Init compiles by_type and by_key routine rules. Invalid non-empty names fail Init.
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
	byType, err := parseRuleGroup(settings["by_type"], true)
	if err != nil {
		return fmt.Errorf("by_type: %w", err)
	}
	byKey, err := parseRuleGroup(settings["by_key"], false)
	if err != nil {
		return fmt.Errorf("by_key: %w", err)
	}
	p.byType = byType
	p.byKey = byKey
	return nil
}

// PreRequest writes resolved hook names into ctx. dbKey rules override type per field.
func (p *Plugin) PreRequest(dbKey string, ctx map[string]any) (map[string]any, *int, error) {
	pre, post := p.resolve(dbKey, ctx)
	if !pre.set && !post.set {
		return ctx, nil, nil
	}
	var out map[string]any
	if ctx == nil {
		out = map[string]any{}
	} else {
		out = make(map[string]any, len(ctx)+2)
		maps.Copy(out, ctx)
	}
	if pre.set {
		if pre.val == "" {
			delete(out, easyrest.CtxDBPreRequest)
		} else {
			out[easyrest.CtxDBPreRequest] = pre.val
		}
	}
	if post.set {
		if post.val == "" {
			delete(out, easyrest.CtxDBPostRequest)
		} else {
			out[easyrest.CtxDBPostRequest] = post.val
		}
	}
	return out, nil, nil
}

// PostRequest does not add response headers.
func (p *Plugin) PostRequest(string, map[string]any) (map[string]string, error) {
	return nil, nil
}

func (p *Plugin) resolve(dbKey string, ctx map[string]any) (pre, post hookField) {
	if p.byType != nil {
		dbType := ""
		if ctx != nil {
			dbType, _ = ctx[easyrest.CtxDBType].(string)
		}
		if rules, ok := p.byType[easyrest.CanonicalDBType(dbType)]; ok {
			pre, post = rules.pre, rules.post
		}
	}
	if p.byKey != nil {
		if rules, ok := p.byKey[strings.ToLower(dbKey)]; ok {
			if rules.pre.set {
				pre = rules.pre
			}
			if rules.post.set {
				post = rules.post
			}
		}
	}
	return pre, post
}

func parseRuleGroup(raw any, asType bool) (map[string]hookRules, error) {
	if raw == nil {
		return map[string]hookRules{}, nil
	}
	group, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("must be a map")
	}
	out := make(map[string]hookRules, len(group))
	for name, v := range group {
		rules, err := parseHookRules(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		key := strings.ToLower(strings.TrimSpace(name))
		if asType {
			key = easyrest.CanonicalDBType(key)
		}
		if key == "" {
			continue
		}
		out[key] = rules
	}
	return out, nil
}

func parseHookRules(raw any) (hookRules, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return hookRules{}, fmt.Errorf("must be a map")
	}
	var rules hookRules
	pre, err := optionalRoutine(m, "pre_request")
	if err != nil {
		return hookRules{}, err
	}
	post, err := optionalRoutine(m, "post_request")
	if err != nil {
		return hookRules{}, err
	}
	rules.pre, rules.post = pre, post
	return rules, nil
}

func optionalRoutine(m map[string]any, key string) (hookField, error) {
	v, ok := m[key]
	if !ok {
		return hookField{}, nil
	}
	s, ok := v.(string)
	if !ok {
		return hookField{}, fmt.Errorf("%s must be a string", key)
	}
	s = strings.TrimSpace(s)
	if s != "" && easyrest.ContextRoutineName(map[string]any{easyrest.CtxDBPreRequest: s}, easyrest.CtxDBPreRequest) == "" {
		return hookField{}, fmt.Errorf("invalid %s %q", key, s)
	}
	return hookField{set: true, val: s}, nil
}
