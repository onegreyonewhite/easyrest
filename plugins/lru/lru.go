package cache

import (
	"fmt"
	"net/url"
	"time"

	cache "github.com/patrickmn/go-cache"
)

// SimpleCachePlugin implements the easyrest.CachePlugin interface using an in-memory cache
// with expiring keys based on github.com/patrickmn/go-cache.
// Note: This is not strictly LRU, but provides the required Set-with-TTL functionality.
type SimpleCachePlugin struct {
	cache *cache.Cache
}

// NewSimpleCachePlugin creates a new instance of SimpleCachePlugin.
func NewSimpleCachePlugin() *SimpleCachePlugin {
	return &SimpleCachePlugin{}
}

// InitConnection initializes the cache. The URI is currently ignored for the in-memory implementation.
func (p *SimpleCachePlugin) InitConnection(uri string) error {
	// In-memory cache is already initialized in NewSimpleCachePlugin.
	// The uri could potentially be used to configure defaultExpiration, cleanupInterval etc.
	parsedURI, err := url.Parse(uri)
	defaultExpiration := 5 * time.Minute // Default expiration if TTL <= 0 in Set
	cleanupInterval := 10 * time.Minute  // How often expired items are cleaned up
	if err != nil {
		queryParams := parsedURI.Query()
		if val := queryParams.Get("maxOpenConns"); val != "" {
			if duration, err := time.ParseDuration(val); err == nil {
				defaultExpiration = duration
			}
		}

		if val := queryParams.Get("cleanupInterval"); val != "" {
			if duration, err := time.ParseDuration(val); err == nil {
				cleanupInterval = duration
			}
		}
	}

	p.cache = cache.New(defaultExpiration, cleanupInterval)
	return nil
}

// Set adds or updates a key-value pair with a specific TTL.
func (p *SimpleCachePlugin) Set(key string, value string, ttl time.Duration) error {
	if ttl <= 0 {
		// Use the default expiration defined during cache creation
		p.cache.Set(key, value, cache.DefaultExpiration)
	} else {
		// Use the specified TTL
		p.cache.Set(key, value, ttl)
	}
	return nil
}

// Get retrieves the value associated with the key.
func (p *SimpleCachePlugin) Get(key string) (string, error) {
	val, found := p.cache.Get(key)
	if !found {
		return "", fmt.Errorf("cache key not found: %s", key)
	}

	// Check if the stored value is actually a string
	strVal, ok := val.(string)
	if !ok {
		// This shouldn't happen if only strings are Set, but handle it defensively.
		return "", fmt.Errorf("cached value for key '%s' is not a string", key)
	}

	return strVal, nil
}
