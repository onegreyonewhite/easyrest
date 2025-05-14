package redis

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisCachePlugin implements the CachePlugin interface using Redis.
type redisCachePlugin struct {
	client *redis.Client
}

// InitConnection establishes a connection to the Redis server based on the URI.
func (p *redisCachePlugin) InitConnection(uri string) error {
	if !strings.HasPrefix(uri, "redis://") && !strings.HasPrefix(uri, "rediss://") {
		return errors.New("invalid Redis URI: must start with redis:// or rediss://")
	}

	// Use redis.ParseURL which handles standard Redis URIs correctly.
	opts, err := redis.ParseURL(uri)
	if err != nil {
		return fmt.Errorf("failed to parse Redis URI: %w", err)
	}

	p.client = redis.NewClient(opts)

	// Ping the server to ensure connection is working.
	ctx, cancel := context.WithTimeout(context.Background(), opts.DialTimeout+opts.ReadTimeout+1*time.Second) // Use a reasonable combined timeout
	defer cancel()

	status := p.client.Ping(ctx)
	if err := status.Err(); err != nil {
		p.client.Close() // Close the client if ping fails
		p.client = nil
		return fmt.Errorf("failed to ping Redis server: %w", err)
	}

	return nil
}

// Set stores a key-value pair with a TTL in the Redis cache.
func (p *redisCachePlugin) Set(key string, value string, ttl time.Duration) error {
	if p.client == nil {
		return errors.New("redis client not initialized")
	}
	ctx := context.Background() // Use background context for cache operations
	err := p.client.Set(ctx, key, value, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to set cache entry in Redis for key '%s': %w", key, err)
	}
	return nil
}

// Get retrieves a value from the Redis cache.
// It returns redis.Nil if the key is not found.
func (p *redisCachePlugin) Get(key string) (string, error) {
	if p.client == nil {
		return "", errors.New("redis client not initialized")
	}
	ctx := context.Background()
	val, err := p.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Return redis.Nil directly as go-redis v9 recommends.
			// EasyREST core or the caller can handle this specific error.
			return "", redis.Nil // Changed from errors.New("cache miss")
		}
		return "", fmt.Errorf("failed to get cache entry from Redis for key '%s': %w", key, err)
	}
	return val, nil
}

// Close cleans up the Redis client connection.
func (p *redisCachePlugin) Close() error {
	if p.client != nil {
		err := p.client.Close()
		p.client = nil // Ensure client is marked as nil after closing
		if err != nil {
			return fmt.Errorf("error closing Redis client: %w", err)
		}
	}
	return nil
}

func NewRedisCachePlugin() *redisCachePlugin {
	return &redisCachePlugin{}
}
