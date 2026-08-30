package server

import (
	stdlog "log"
	"path/filepath"
	"strings"
	"sync/atomic"

	hplugin "github.com/hashicorp/go-plugin"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

type PreservedPluginFactory[T any] func() T

// Global configuration and dbPlugins loaded only once.
var (
	DbPlugins                  atomic.Pointer[map[string]easyrest.DBPlugin]
	QueryPlugins               atomic.Pointer[map[string]easyrest.DBQueryPlugin]
	AuthPlugins                atomic.Pointer[map[string]easyrest.AuthPlugin]
	AuthSecurityDefinitions    atomic.Pointer[map[string]map[string]any]
	MiddlewarePlugins          atomic.Pointer[map[string]easyrest.MiddlewarePlugin]
	pluginClients              atomic.Pointer[map[string]*hplugin.Client]
	middlewarePluginClients    atomic.Pointer[map[string]*hplugin.Client]
	globalMiddlewareChain      atomic.Pointer[[]easyrest.MiddlewarePlugin]
	dbMiddlewareOrder          atomic.Pointer[map[string][]easyrest.MiddlewarePlugin]
	PreservedDbPlugins         map[string]PreservedPluginFactory[easyrest.DBPlugin]
	PreservedQueryPlugins      map[string]PreservedPluginFactory[easyrest.DBQueryPlugin]
	PreservedAuthPlugins       map[string]PreservedPluginFactory[easyrest.AuthPlugin]
	PreservedMiddlewarePlugins map[string]PreservedPluginFactory[easyrest.MiddlewarePlugin]
)

func init() {
	emptyDbPlugins := make(map[string]easyrest.DBPlugin)
	DbPlugins.Store(&emptyDbPlugins)
	emptyQueryPlugins := make(map[string]easyrest.DBQueryPlugin)
	QueryPlugins.Store(&emptyQueryPlugins)
	emptyPluginClients := make(map[string]*hplugin.Client)
	pluginClients.Store(&emptyPluginClients)

	emptyAuthPlugins := make(map[string]easyrest.AuthPlugin)
	AuthPlugins.Store(&emptyAuthPlugins)
	emptyAuthSecDefs := make(map[string]map[string]any)
	AuthSecurityDefinitions.Store(&emptyAuthSecDefs)
	emptyMiddlewarePlugins := make(map[string]easyrest.MiddlewarePlugin)
	MiddlewarePlugins.Store(&emptyMiddlewarePlugins)
	emptyMiddlewarePluginClients := make(map[string]*hplugin.Client)
	middlewarePluginClients.Store(&emptyMiddlewarePluginClients)
	emptyGlobalMiddlewareChain := []easyrest.MiddlewarePlugin{}
	globalMiddlewareChain.Store(&emptyGlobalMiddlewareChain)
	emptyDbMiddlewareOrder := make(map[string][]easyrest.MiddlewarePlugin)
	dbMiddlewareOrder.Store(&emptyDbMiddlewareOrder)

	PreservedDbPlugins = make(map[string]PreservedPluginFactory[easyrest.DBPlugin])
	PreservedQueryPlugins = make(map[string]PreservedPluginFactory[easyrest.DBQueryPlugin])
	PreservedAuthPlugins = make(map[string]PreservedPluginFactory[easyrest.AuthPlugin])
	PreservedMiddlewarePlugins = make(map[string]PreservedPluginFactory[easyrest.MiddlewarePlugin])
}

type pluginCloser interface {
	Close()
}

func closePluginMap[T any](kind string, plugins map[string]T) {
	for pluginName, plugin := range plugins {
		if closer, ok := any(plugin).(pluginCloser); ok {
			closer.Close()
			stdlog.Printf("Closed %s plugin: %s", kind, pluginName)
		}
	}
}

func closeLoadedPlugins() {
	if ptr := DbPlugins.Load(); ptr != nil {
		closePluginMap("DB", *ptr)
	}
	if ptr := QueryPlugins.Load(); ptr != nil {
		closePluginMap("query", *ptr)
	}
}

func StopPlugins() {
	// Get the current clients map pointer
	oldClientsPtr := pluginClients.Load()

	closeLoadedPlugins()

	// Atomically set empty maps
	emptyDbPlugins := make(map[string]easyrest.DBPlugin)
	DbPlugins.Store(&emptyDbPlugins)
	emptyQueryPlugins := make(map[string]easyrest.DBQueryPlugin)
	QueryPlugins.Store(&emptyQueryPlugins)
	emptyPluginClients := make(map[string]*hplugin.Client)
	pluginClients.Store(&emptyPluginClients)

	// New for AuthPlugins
	emptyAuthPlugins := make(map[string]easyrest.AuthPlugin)
	AuthPlugins.Store(&emptyAuthPlugins)
	emptyAuthSecDefs := make(map[string]map[string]any)
	AuthSecurityDefinitions.Store(&emptyAuthSecDefs)

	emptyOrder := []string{}
	authPluginOrder.Store(&emptyOrder)

	emptyMiddlewarePlugins := make(map[string]easyrest.MiddlewarePlugin)
	MiddlewarePlugins.Store(&emptyMiddlewarePlugins)
	emptyMiddlewarePluginClients := make(map[string]*hplugin.Client)
	middlewarePluginClients.Store(&emptyMiddlewarePluginClients)
	emptyGlobalMiddlewareChain := []easyrest.MiddlewarePlugin{}
	globalMiddlewareChain.Store(&emptyGlobalMiddlewareChain)
	emptyDbMiddlewareOrder := make(map[string][]easyrest.MiddlewarePlugin)
	dbMiddlewareOrder.Store(&emptyDbMiddlewareOrder)

	clearSchemaCache()

	// Kill clients from the old map
	if oldClientsPtr != nil {
		oldClients := *oldClientsPtr
		for connName, client := range oldClients {
			stdlog.Printf("Stopping plugin client for connection: %s", connName)
			client.Kill()
		}
	}
	oldMiddlewareClientsPtr := middlewarePluginClients.Load()
	if oldMiddlewareClientsPtr != nil {
		oldMiddlewareClients := *oldMiddlewareClientsPtr
		for name, client := range oldMiddlewareClients {
			stdlog.Printf("Stopping middleware plugin client for: %s", name)
			client.Kill()
		}
	}
}

type connectionPlugin interface {
	InitConnection(uri string) error
}

func initPreservedConnection[T connectionPlugin](
	factories map[string]PreservedPluginFactory[T],
	hint, uri, connName, kind string,
) (T, bool) {
	var zero T
	factory, ok := factories[hint]
	if !ok {
		return zero, false
	}
	inst := factory()
	if err := inst.InitConnection(uri); err != nil {
		stdlog.Printf("Error initializing %s connection for plugin %s: %v", kind, connName, err)
		return zero, false
	}
	return inst, true
}

func dispenseConnection[T connectionPlugin](
	rpcClient hplugin.ClientProtocol,
	iface, uri, connName, pluginPath, kind string,
) (T, bool) {
	var zero T
	raw, err := rpcClient.Dispense(iface)
	if err != nil {
		if !strings.Contains(err.Error(), "unknown service") {
			stdlog.Printf("Error dispensing '%s' interface for plugin %s: %v", iface, connName, err)
		}
		return zero, false
	}
	plug, ok := raw.(T)
	if !ok {
		stdlog.Printf("Error: Plugin %s (%s) dispensed '%s' but type assertion to %s failed", connName, pluginPath, iface, kind)
		return zero, false
	}
	if err := plug.InitConnection(uri); err != nil {
		stdlog.Printf("Error initializing %s connection for plugin %s: %v", kind, connName, err)
		return zero, false
	}
	return plug, true
}

// LoadPlugins loads all configured database plugins.
func LoadPlugins() {
	cfg := currentConfig()
	newDbPlugins := make(map[string]easyrest.DBPlugin)
	newQueryPlugins := make(map[string]easyrest.DBQueryPlugin)
	newPluginClients := make(map[string]*hplugin.Client)
	newAuthPlugins := make(map[string]easyrest.AuthPlugin)
	newAuthSecurityDefinitions := make(map[string]map[string]any)

	for connName, pluginCfg := range cfg.PluginMap {
		splitURI := strings.SplitN(pluginCfg.Uri, "://", 2)
		if len(splitURI) != 2 {
			stdlog.Printf("Invalid URI for %s: %s", connName, pluginCfg.Uri)
			continue
		}
		pluginTypeHint := splitURI[0]
		pluginExec := "easyrest-plugin-" + pluginTypeHint
		kind := "DB"
		if pluginCfg.UseQuery {
			kind = "Query"
		}

		var pluginPath string
		if pluginCfg.Path != "" {
			var err error
			pluginPath, err = expandHomePath(pluginCfg.Path)
			if err != nil {
				stdlog.Printf("Error getting home directory for plugin %s: %v", connName, err)
				continue
			}
		} else {
			if pluginCfg.UseQuery {
				if plug, ok := initPreservedConnection(PreservedQueryPlugins, pluginTypeHint, pluginCfg.Uri, connName, kind); ok {
					newQueryPlugins[connName] = plug
					stdlog.Printf("Connection %s (%s as preserved) initialized with interfaces: [%s]", connName, pluginExec, kind)
					continue
				}
			} else if plug, ok := initPreservedConnection(PreservedDbPlugins, pluginTypeHint, pluginCfg.Uri, connName, kind); ok {
				newDbPlugins[connName] = plug
				stdlog.Printf("Connection %s (%s as preserved) initialized with interfaces: [%s]", connName, pluginExec, kind)
				continue
			}
			var err error
			pluginPath, err = findPluginPath(pluginExec)
			if err != nil {
				stdlog.Printf("Plugin executable for %s (%s or %s-os-arch) not found: %v", connName, pluginExec, pluginExec, err)
				continue
			}
		}

		absPluginPath, err := filepath.Abs(pluginPath)
		if err != nil {
			stdlog.Printf("Error getting absolute path for plugin %s (%s): %v", connName, pluginPath, err)
			continue
		}

		client, rpcClient, err := startPluginRPCClient(absPluginPath, map[string]hplugin.Plugin{
			"db":    &easyrest.DBPluginPlugin{},
			"query": &easyrest.DBQueryPluginPlugin{},
		}, cfg.NoPluginLog)
		if err != nil {
			stdlog.Printf("Error creating RPC client process for plugin %s (%s): %v", connName, pluginPath, err)
			continue
		}

		loaded := false
		if pluginCfg.UseQuery {
			if plug, ok := dispenseConnection[easyrest.DBQueryPlugin](rpcClient, "query", pluginCfg.Uri, connName, pluginPath, kind); ok {
				newQueryPlugins[connName] = plug
				loaded = true
			}
		} else if plug, ok := dispenseConnection[easyrest.DBPlugin](rpcClient, "db", pluginCfg.Uri, connName, pluginPath, kind); ok {
			newDbPlugins[connName] = plug
			loaded = true
		}

		if loaded {
			newPluginClients[connName] = client
			stdlog.Printf("Connection %s (%s) initialized with interfaces: [%s]", connName, pluginExec, kind)
		} else {
			stdlog.Printf("Connection %s (%s) failed to initialize any supported interfaces. Stopping client.", connName, pluginExec)
			client.Kill()
		}
	}

	// --- Load Auth Plugins ---
	for authPluginName, authPluginCfg := range cfg.AuthPlugins {
		pluginInitialized := false // Tracks if *any* form (preserved or RPC) of this auth plugin was inited

		// Attempt 1: Preserved Auth Plugin
		// Considered if Path is empty and authPluginName matches a key in PreservedAuthPlugins.
		if authPluginCfg.Path == "" {
			if factory, ok := PreservedAuthPlugins[authPluginName]; ok {
				authPluginInstance := factory()
				schema, errInitPreserved := authPluginInstance.Init(authPluginCfg.Settings)
				if errInitPreserved != nil {
					stdlog.Printf("Error initializing preserved Auth plugin '%s': %v", authPluginName, errInitPreserved)
				} else {
					newAuthPlugins[authPluginName] = authPluginInstance
					if schema != nil {
						newAuthSecurityDefinitions[authPluginName] = schema
					}
					pluginInitialized = true
					stdlog.Printf("Auth plugin '%s' (preserved) initialized.", authPluginName)
				}
				continue // Move to the next auth plugin in config
			}
		}

		// Attempt 2: External (RPC) Auth Plugin
		// Reaches here if:
		// 1. authPluginCfg.Path is specified (explicit external plugin).
		// 2. authPluginCfg.Path is empty, AND it was not found/handled as a preserved plugin.
		absPluginPath, pathSearchOrigin, errResolvingPath := resolveNamedPluginPath(authPluginName, authPluginCfg.Path, "easyrest-auth-"+authPluginName)
		if errResolvingPath != nil {
			stdlog.Printf("Auth plugin '%s': Could not find/validate executable (searched as '%s'): %v. Skipping.", authPluginName, pathSearchOrigin, errResolvingPath)
			continue
		}

		client, rpcClient, err := startPluginRPCClient(absPluginPath, map[string]hplugin.Plugin{
			"auth": &easyrest.AuthPluginPlugin{},
		}, cfg.NoPluginLog)
		if err != nil {
			stdlog.Printf("Error creating RPC client for auth plugin %s (%s): %v", authPluginName, absPluginPath, err)
			continue
		}

		rawAuth, errDispense := rpcClient.Dispense("auth")
		if errDispense == nil {
			authPlug, ok := rawAuth.(easyrest.AuthPlugin)
			if ok {
				schema, errInit := authPlug.Init(authPluginCfg.Settings)
				if errInit == nil {
					newAuthPlugins[authPluginName] = authPlug
					if schema != nil {
						newAuthSecurityDefinitions[authPluginName] = schema
					}
					pluginInitialized = true
				} else {
					stdlog.Printf("Error initializing Auth interface for plugin %s (RPC): %v", authPluginName, errInit)
				}
			} else {
				stdlog.Printf("Error: Auth plugin %s (%s) dispensed 'auth' but type assertion to AuthPlugin failed", authPluginName, absPluginPath)
			}
		} else {
			if !strings.Contains(errDispense.Error(), "unknown service") {
				stdlog.Printf("Error dispensing 'auth' interface for plugin %s: %v", authPluginName, errDispense)
			}
		}

		if pluginInitialized {
			newPluginClients[authPluginName] = client // Store the client process for this auth plugin
			stdlog.Printf("Auth plugin '%s' (executable: %s) initialized.", authPluginName, filepath.Base(absPluginPath))
		} else {
			// If not preserved and RPC init failed for any reason
			stdlog.Printf("Auth plugin '%s' (executable: %s) failed to initialize. Stopping client.", authPluginName, filepath.Base(absPluginPath))
			client.Kill() // Kill the client if no interfaces were loaded or init failed
		}
	} // End loop over cfg.AuthPlugins

	// --- Load Middleware Plugins ---
	newMiddlewarePlugins := make(map[string]easyrest.MiddlewarePlugin)
	newMiddlewarePluginClients := make(map[string]*hplugin.Client)

	for mwPluginName, mwPluginCfg := range cfg.MiddlewarePlugins {
		pluginInitialized := false

		if mwPluginCfg.Path == "" {
			if factory, ok := PreservedMiddlewarePlugins[mwPluginName]; ok {
				mwInstance := factory()
				if errInit := mwInstance.Init(mwPluginCfg.Settings); errInit != nil {
					stdlog.Printf("Error initializing preserved middleware plugin '%s': %v", mwPluginName, errInit)
				} else {
					newMiddlewarePlugins[mwPluginName] = mwInstance
					pluginInitialized = true
					stdlog.Printf("Middleware plugin '%s' (preserved) initialized.", mwPluginName)
				}
				continue
			}
		}

		absPluginPath, pathSearchOrigin, errResolvingPath := resolveNamedPluginPath(mwPluginName, mwPluginCfg.Path, "easyrest-middleware-"+mwPluginName)
		if errResolvingPath != nil {
			stdlog.Printf("Middleware plugin '%s': Could not find/validate executable (searched as '%s'): %v. Skipping.", mwPluginName, pathSearchOrigin, errResolvingPath)
			continue
		}

		client, rpcClient, err := startPluginRPCClient(absPluginPath, map[string]hplugin.Plugin{
			"middleware": &easyrest.MiddlewarePluginPlugin{},
		}, cfg.NoPluginLog)
		if err != nil {
			stdlog.Printf("Error creating RPC client for middleware plugin %s (%s): %v", mwPluginName, absPluginPath, err)
			continue
		}

		rawMw, errDispense := rpcClient.Dispense("middleware")
		if errDispense == nil {
			mwPlug, ok := rawMw.(easyrest.MiddlewarePlugin)
			if ok {
				if errInit := mwPlug.Init(mwPluginCfg.Settings); errInit != nil {
					stdlog.Printf("Error initializing Middleware interface for plugin %s (RPC): %v", mwPluginName, errInit)
				} else {
					newMiddlewarePlugins[mwPluginName] = mwPlug
					newMiddlewarePluginClients[mwPluginName] = client
					pluginInitialized = true
				}
			} else {
				stdlog.Printf("Error: Middleware plugin %s (%s) dispensed 'middleware' but type assertion to MiddlewarePlugin failed", mwPluginName, absPluginPath)
			}
		} else {
			if !strings.Contains(errDispense.Error(), "unknown service") {
				stdlog.Printf("Error dispensing 'middleware' interface for plugin %s: %v", mwPluginName, errDispense)
			}
		}

		if pluginInitialized {
			stdlog.Printf("Middleware plugin '%s' (executable: %s) initialized.", mwPluginName, filepath.Base(absPluginPath))
		} else {
			stdlog.Printf("Middleware plugin '%s' (executable: %s) failed to initialize. Stopping client.", mwPluginName, filepath.Base(absPluginPath))
			client.Kill()
		}
	} // End loop over cfg.MiddlewarePlugins

	globalChain, dbChains := buildMiddlewareChains(*cfg, newMiddlewarePlugins)
	globalMiddlewareChain.Store(&globalChain)
	dbMiddlewareOrder.Store(&dbChains)

	// Get the pointer to the old clients map *before* swapping
	oldClientsPtr := pluginClients.Load()
	oldMiddlewareClientsPtr := middlewarePluginClients.Load()

	closeLoadedPlugins()

	// Atomically swap to the new maps for DB/Query
	DbPlugins.Store(&newDbPlugins)
	QueryPlugins.Store(&newQueryPlugins)

	// Atomically swap for Auth
	AuthPlugins.Store(&newAuthPlugins)
	AuthSecurityDefinitions.Store(&newAuthSecurityDefinitions)
	setAuthPluginOrder(newAuthPlugins)

	MiddlewarePlugins.Store(&newMiddlewarePlugins)
	middlewarePluginClients.Store(&newMiddlewarePluginClients)

	// Swap the plugin clients
	pluginClients.Store(&newPluginClients)

	// Kill the old clients *after* the swap for DB/Query
	if oldClientsPtr != nil {
		oldClients := *oldClientsPtr
		if len(oldClients) > 0 {
			stdlog.Printf("Stopping %d old plugin client(s)...", len(oldClients))
			for _, client := range oldClients {
				client.Kill()
			}
			stdlog.Printf("Finished stopping old plugin clients.")
		}
	}
	if oldMiddlewareClientsPtr != nil {
		oldMiddlewareClients := *oldMiddlewareClientsPtr
		if len(oldMiddlewareClients) > 0 {
			stdlog.Printf("Stopping %d old middleware plugin client(s)...", len(oldMiddlewareClients))
			for name, client := range oldMiddlewareClients {
				stdlog.Printf("Stopping middleware plugin client for: %s", name)
				client.Kill()
			}
			stdlog.Printf("Finished stopping old middleware plugin clients.")
		}
	}
}
