package server

import (
	stdlog "log"
	"maps"
	"sync"
	"sync/atomic"

	hplugin "github.com/hashicorp/go-plugin"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

var (
	builtinContentOnce sync.Once
	builtinContentRefs atomic.Pointer[map[string]contentPluginRef]
)

func ensureBuiltinContentLoaded() {
	builtinContentOnce.Do(func() {
		refs := make(map[string]contentPluginRef, len(easyrest.StandardContentNames()))
		for _, name := range easyrest.StandardContentNames() {
			factory, ok := PreservedContentPlugins[name]
			if !ok {
				continue
			}
			ref, ok := initContentPlugin(name, factory(), nil)
			if ok {
				refs[name] = ref
			}
		}
		builtinContentRefs.Store(&refs)
	})
}

func ensureStandardContent(cfg *config.Config) {
	plugins := make(map[string]config.ExternalPlugin, len(cfg.ContentPlugins)+len(easyrest.StandardContentNames()))
	maps.Copy(plugins, cfg.ContentPlugins)
	for _, name := range easyrest.StandardContentNames() {
		if _, ok := plugins[name]; !ok {
			plugins[name] = config.ExternalPlugin{}
		}
	}
	cfg.ContentPlugins = plugins
}

func loadOneContentPlugin(name string, plugCfg config.ExternalPlugin, noPluginLog bool) (contentPluginRef, *hplugin.Client, bool) {
	if plugCfg.Path == "" {
		if factory, ok := PreservedContentPlugins[name]; ok {
			inst := factory()
			ref, ok := initContentPlugin(name, inst, plugCfg.Settings)
			if ok {
				stdlog.Printf("Content plugin '%s' (preserved) initialized.", name)
			}
			return ref, nil, ok
		}
	}

	absPluginPath, pathSearchOrigin, err := resolveNamedPluginPath(name, plugCfg.Path, "easyrest-content-"+name)
	if err != nil {
		stdlog.Printf("Content plugin '%s': Could not find/validate executable (searched as '%s'): %v. Skipping.", name, pathSearchOrigin, err)
		return contentPluginRef{}, nil, false
	}
	client, rpcClient, err := startPluginRPCClient(absPluginPath, map[string]hplugin.Plugin{
		"content": &easyrest.ContentPluginPlugin{},
	}, noPluginLog)
	if err != nil {
		stdlog.Printf("Error creating RPC client for content plugin %s (%s): %v", name, absPluginPath, err)
		return contentPluginRef{}, nil, false
	}
	raw, err := rpcClient.Dispense("content")
	if err != nil {
		stdlog.Printf("Error dispensing 'content' interface for plugin %s: %v", name, err)
		client.Kill()
		return contentPluginRef{}, nil, false
	}
	plug, ok := raw.(easyrest.ContentPlugin)
	if !ok {
		stdlog.Printf("Error: Content plugin %s dispensed 'content' but type assertion failed", name)
		client.Kill()
		return contentPluginRef{}, nil, false
	}
	ref, ok := initContentPlugin(name, plug, plugCfg.Settings)
	if !ok {
		client.Kill()
		return contentPluginRef{}, nil, false
	}
	stdlog.Printf("Content plugin '%s' (executable) initialized.", name)
	return ref, client, true
}

func initContentPlugin(name string, plug easyrest.ContentPlugin, settings map[string]any) (contentPluginRef, bool) {
	info, err := plug.Init(settings)
	if err != nil {
		stdlog.Printf("Error initializing content plugin '%s': %v", name, err)
		return contentPluginRef{}, false
	}
	if info.ParserMedia == "" && info.RenderMedia == "" {
		stdlog.Printf("Error initializing content plugin '%s': no parser or renderer media type", name)
		return contentPluginRef{}, false
	}
	return contentPluginRef{Name: name, Plugin: plug, ContentInfo: info}, true
}

func contentRefsNamed(names []string) []contentPluginRef {
	loaded := contentPlugins.Load()
	out := make([]contentPluginRef, 0, len(names))
	for _, name := range names {
		if loaded != nil {
			if ref, ok := (*loaded)[name]; ok {
				out = append(out, ref)
				continue
			}
		}
		if ref, ok := preservedContentRef(name); ok {
			out = append(out, ref)
			continue
		}
		stdlog.Printf("Error: content plugin %q not loaded", name)
	}
	return out
}

func preservedContentRef(name string) (contentPluginRef, bool) {
	ensureBuiltinContentLoaded()
	if loaded := builtinContentRefs.Load(); loaded != nil {
		if ref, ok := (*loaded)[name]; ok {
			return ref, true
		}
	}
	factory, ok := PreservedContentPlugins[name]
	if !ok {
		return contentPluginRef{}, false
	}
	return initContentPlugin(name, factory(), nil)
}
