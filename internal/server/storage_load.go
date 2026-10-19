package server

import (
	"fmt"
	stdlog "log"
	"maps"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/go-chi/chi/v5"
	hplugin "github.com/hashicorp/go-plugin"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

type storagePluginRef struct {
	Name   string
	Plugin easyrest.StoragePlugin
	Root   string
	Inline bool
}

var storageSwap atomic.Pointer[http.Handler]

type storageSwapHandler struct{}

func (storageSwapHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := storageSwap.Load()
	if h == nil || *h == nil {
		http.NotFound(w, r)
		return
	}
	(*h).ServeHTTP(w, r)
}

func mountStorage(r chi.Router) {
	r.Mount("/media", storageSwapHandler{})
}

func publishStorage() {
	sub := chi.NewRouter()
	if loaded := storagePlugins.Load(); loaded != nil {
		for name, ref := range *loaded {
			if ref.Inline || ref.Root == "" || ref.Plugin == nil || !storageNameOK(name) {
				continue
			}
			plug := ref.Plugin
			sub.Get("/"+name+"/*", func(w http.ResponseWriter, r *http.Request) {
				serveStorageFile(w, r, plug)
			})
		}
	}
	handler := http.Handler(sub)
	storageSwap.Store(&handler)
}

func storageNameOK(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

func loadStoragePlugins(cfg *config.Config, noPluginLog bool) (map[string]storagePluginRef, map[string]*hplugin.Client) {
	plugins := maps.Clone(cfg.StoragePlugins)
	if plugins == nil {
		plugins = map[string]config.StoragePluginConfig{}
	}
	if _, ok := plugins["static"]; !ok {
		plugins["static"] = config.StoragePluginConfig{Plugin: "static"}
	}
	refs := make(map[string]storagePluginRef)
	clients := make(map[string]*hplugin.Client)
	for name, plugCfg := range plugins {
		ref, client, ok := loadOneStoragePlugin(name, plugCfg, noPluginLog)
		if !ok {
			continue
		}
		refs[name] = ref
		if client != nil {
			clients[name] = client
		}
	}
	return refs, clients
}

func storageDriver(name string, plugCfg config.StoragePluginConfig) string {
	if plugCfg.Plugin != "" {
		return plugCfg.Plugin
	}
	return name
}

func loadOneStoragePlugin(name string, plugCfg config.StoragePluginConfig, noPluginLog bool) (storagePluginRef, *hplugin.Client, bool) {
	driver := storageDriver(name, plugCfg)
	if plugCfg.Path == "" {
		factory, ok := PreservedStoragePlugins[driver]
		if !ok {
			stdlog.Printf("Storage plugin '%s': no preserved plugin %q and no path. Skipping.", name, driver)
			return storagePluginRef{}, nil, false
		}
		ref, ok := initStoragePlugin(name, factory(), plugCfg.Settings)
		if ok {
			stdlog.Printf("Storage plugin '%s' (preserved) initialized.", name)
		}
		return ref, nil, ok
	}

	absPluginPath, pathSearchOrigin, err := resolveNamedPluginPath(name, plugCfg.Path, "easyrest-storage-"+driver)
	if err != nil {
		stdlog.Printf("Storage plugin '%s': Could not find/validate executable (searched as '%s'): %v. Skipping.", name, pathSearchOrigin, err)
		return storagePluginRef{}, nil, false
	}
	client, rpcClient, err := startPluginRPCClient(absPluginPath, map[string]hplugin.Plugin{
		"storage": &easyrest.StoragePluginPlugin{},
	}, noPluginLog)
	if err != nil {
		stdlog.Printf("Error creating RPC client for storage plugin %s (%s): %v", name, absPluginPath, err)
		return storagePluginRef{}, nil, false
	}
	raw, err := rpcClient.Dispense("storage")
	if err != nil {
		stdlog.Printf("Error dispensing 'storage' interface for plugin %s: %v", name, err)
		client.Kill()
		return storagePluginRef{}, nil, false
	}
	plug, ok := raw.(easyrest.StoragePlugin)
	if !ok {
		stdlog.Printf("Error: Storage plugin %s dispensed 'storage' but type assertion failed", name)
		client.Kill()
		return storagePluginRef{}, nil, false
	}
	ref, ok := initStoragePlugin(name, plug, plugCfg.Settings)
	if !ok {
		client.Kill()
		return storagePluginRef{}, nil, false
	}
	stdlog.Printf("Storage plugin '%s' (executable) initialized.", name)
	return ref, client, true
}

func initStoragePlugin(name string, plug easyrest.StoragePlugin, settings map[string]any) (storagePluginRef, bool) {
	info, err := plug.Init(withPluginName(name, settings), currentHostRPC())
	if err != nil {
		stdlog.Printf("Error initializing storage plugin '%s': %v", name, err)
		return storagePluginRef{}, false
	}
	return storagePluginRef{Name: name, Plugin: plug, Root: info.Root, Inline: info.Inline}, true
}

func withPluginName(name string, settings map[string]any) map[string]any {
	out := maps.Clone(settings)
	if out == nil {
		out = map[string]any{}
	}
	out["name"] = name
	return out
}

func serveStorageFile(w http.ResponseWriter, r *http.Request, plug easyrest.StoragePlugin) {
	if err := r.Context().Err(); err != nil {
		return
	}
	rel, err := easyrest.CleanStorageRel(strings.TrimPrefix(chi.URLParam(r, "*"), "/"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ctx := map[string]any{"request": requestPublic(r)}
	meta, err := plug.GetMetadata(rel, ctx)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if meta.Mime != "" {
		w.Header().Set("Content-Type", meta.Mime)
	}
	w.Header().Set("ETag", storageETag(meta))
	http.ServeContent(w, r, rel, meta.ModTime, &lazyStorageBody{
		plug: plug,
		rel:  rel,
		ctx:  ctx,
		size: meta.Size,
		req:  r,
	})
}

func storageETag(meta easyrest.StorageMeta) string {
	return fmt.Sprintf("\"%x-%x\"", meta.Size, meta.ModTime.UnixNano())
}
