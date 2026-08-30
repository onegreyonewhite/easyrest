package server

import (
	"sync"
	"sync/atomic"

	"github.com/onegreyonewhite/easyrest/internal/config"
)

var (
	cfgPtr  atomic.Pointer[config.Config]
	cfgOnce sync.Once
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
			loaded := config.Load()
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

func ReloadConfig() {
	loaded := config.Load()
	cfgPtr.Store(&loaded)
	clearSchemaCache()
	ResetClaimsCache()
}
