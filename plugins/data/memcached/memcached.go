package memcached

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
)

// Version can be set during build time
var Version = "v0.1.0" // Initial version

// memcacheClientInterface defines the subset of memcache.Client methods used by the plugin.
// This allows for mocking in tests.
type memcacheClientInterface interface {
	Get(key string) (*memcache.Item, error)
	Set(item *memcache.Item) error
	Delete(key string) error // Added Delete in case it's needed in future, though not used now
}

// memcachedCachePlugin implements the CachePlugin interface using Memcached.
type memcachedCachePlugin struct {
	client memcacheClientInterface // Changed to interface
}

// InitConnection establishes a connection to the Memcached server(s) based on the URI.
// URI format: "memcached://host1:port1,host2:port2"
func (p *memcachedCachePlugin) InitConnection(uri string) error {
	if !strings.HasPrefix(uri, "memcached://") {
		return errors.New("invalid Memcached URI: must start with memcached://")
	}

	serverList := strings.TrimPrefix(uri, "memcached://")
	if serverList == "" {
		return errors.New("invalid Memcached URI: no servers specified")
	}

	servers := strings.Split(serverList, ",")
	actualServers := []string{}
	for _, s := range servers {
		if strings.TrimSpace(s) != "" {
			actualServers = append(actualServers, strings.TrimSpace(s))
		}
	}

	if len(actualServers) == 0 {
		return errors.New("invalid Memcached URI: no valid servers specified after prefix")
	}

	// Create the real client
	realClient := memcache.New(actualServers...)
	if realClient == nil {
		// This case should ideally not happen with memcache.New unless actualServers is empty (which we check above),
		// but good to have a safeguard if memcache.New could return nil for other reasons.
		return errors.New("failed to create Memcached client instance from memcache.New")
	}
	p.client = realClient // Assign real client to the interface field

	// "Ping" the server by attempting to Get a non-existent key.
	// This helps confirm basic connectivity and that the client is operational.
	pingKey := "__easyrest_memcached_ping__"
	_, err := p.client.Get(pingKey) // Uses the interface, which points to realClient here

	if err != nil && !errors.Is(err, memcache.ErrCacheMiss) {
		// If the error is something other than a cache miss (which is expected for a non-existent key),
		// it might indicate a connection problem or other server issue.
		// We don't nil out p.client here, as the client might still be partially functional
		// or the issue might be transient. Returning an error is sufficient.
		return fmt.Errorf("post-initialization check (test Get on key '%s') failed for Memcached: %w", pingKey, err)
	}

	return nil
}

// Set stores a key-value pair with a TTL in the Memcached cache.
func (p *memcachedCachePlugin) Set(key string, value string, ttl time.Duration) error {
	if p.client == nil {
		return errors.New("memcached client not initialized")
	}

	ttlSeconds := int32(ttl.Seconds())
	if ttlSeconds < 0 {
		ttlSeconds = 0
	}

	err := p.client.Set(&memcache.Item{
		Key:        key,
		Value:      []byte(value),
		Expiration: ttlSeconds,
	})

	if err != nil {
		return fmt.Errorf("failed to set cache entry in Memcached for key '%s': %w", key, err)
	}
	return nil
}

// Get retrieves a value from the Memcached cache.
// It returns memcache.ErrCacheMiss if the key is not found.
func (p *memcachedCachePlugin) Get(key string) (string, error) {
	if p.client == nil {
		return "", errors.New("memcached client not initialized")
	}

	item, err := p.client.Get(key)
	if err != nil {
		if errors.Is(err, memcache.ErrCacheMiss) {
			return "", memcache.ErrCacheMiss
		}
		return "", fmt.Errorf("failed to get cache entry from Memcached for key '%s': %w", key, err)
	}
	return string(item.Value), nil
}

// Close cleans up the Memcached client connection.
func (p *memcachedCachePlugin) Close() error {
	if p.client != nil {
		// If p.client is a real *memcache.Client, it doesn't have a Close() method.
		// If it were a closable interface, we'd call it.
		// For now, setting to nil is the main cleanup for the plugin's reference.
		p.client = nil
	}
	return nil
}

// NewMemcachedCachePlugin creates a new instance of the Memcached cache plugin.
func NewMemcachedCachePlugin() *memcachedCachePlugin {
	return &memcachedCachePlugin{}
}
