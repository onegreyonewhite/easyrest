package server

import (
	stdlog "log"
	"sync"
	"sync/atomic"

	"github.com/onegreyonewhite/easyrest/internal/config"
)

var (
	cfgPtr  atomic.Pointer[config.Config]
	cfgOnce sync.Once

	appMu       sync.Mutex
	appOverride string
	appFiles    []string
)

// schemaCache caches GetSchema results per dbKey.
var (
	schemaCache      = make(map[string]any)
	schemaCacheMutex sync.RWMutex
)

func ensureConfig() *config.Config {
	if ptr := cfgPtr.Load(); ptr != nil {
		return ptr
	}
	cfgOnce.Do(func() {
		if cfgPtr.Load() == nil {
			loaded, err := config.Load(nil, "")
			if err != nil {
				stdlog.Printf("load default config: %v", err)
				loaded = config.Config{}
			}
			cfgPtr.Store(&loaded)
		}
	})
	return cfgPtr.Load()
}

// currentConfig returns the active configuration without copying it.
func currentConfig() *config.Config {
	return ensureConfig()
}

// GetConfig returns a copy of the active configuration.
func GetConfig() config.Config {
	return *ensureConfig()
}

// SetConfig sets a new configuration.
func SetConfig(newConfig config.Config) {
	stored := newConfig
	cfgPtr.Store(&stored)
}

func clearSchemaCache() {
	schemaCacheMutex.Lock()
	schemaCache = make(map[string]any)
	schemaCacheMutex.Unlock()
}

// SetupApplication loads config files, overlays overrideYAML, swaps the global
// config, and reloads plugins. It does not rebuild the HTTP router.
func SetupApplication(overrideYAML string, configFiles []string) error {
	loaded, err := config.Load(configFiles, overrideYAML)
	if err != nil {
		return err
	}
	if err := validateRestHandlers(&loaded); err != nil {
		return err
	}
	files := append([]string(nil), configFiles...)
	appMu.Lock()
	appOverride = overrideYAML
	appFiles = files
	appMu.Unlock()

	SetConfig(loaded)
	clearSchemaCache()
	ResetClaimsCache()
	LoadPlugins()
	return nil
}

func reloadApplication() error {
	appMu.Lock()
	override := appOverride
	files := append([]string(nil), appFiles...)
	appMu.Unlock()
	return SetupApplication(override, files)
}

// ReloadConfig reloads the last SetupApplication inputs.
func ReloadConfig() {
	if err := reloadApplication(); err != nil {
		stdlog.Printf("reload config: %v", err)
	}
}
