package main

import (
	"flag"
	"fmt"

	hplugin "github.com/hashicorp/go-plugin"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	memcachedPlugin "github.com/onegreyonewhite/easyrest/plugins/data/memcached"
)

func main() {
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()
	if *showVersion {
		// Assuming memcachedPlugin.Version exists, similar to redisPlugin.Version
		// If not, use a generic version or easyrest.Version if more appropriate.
		// For now, let's use memcachedPlugin.Version for consistency with the pattern.
		fmt.Println(memcachedPlugin.Version) // Display memcached plugin's own version
		return
	}

	cacheImpl := memcachedPlugin.NewMemcachedCachePlugin()

	hplugin.Serve(&hplugin.ServeConfig{
		HandshakeConfig: easyrest.Handshake,
		Plugins: map[string]hplugin.Plugin{
			// Only register the cache plugin
			"cache": &easyrest.CachePluginPlugin{Impl: cacheImpl},
		},
	})
	// defer cacheImpl.Close() // gomemcache client doesn't have a Close method that needs deferring here.
	// The Close method in our plugin is for interface compliance and resource cleanup if any (sets client to nil).
}
