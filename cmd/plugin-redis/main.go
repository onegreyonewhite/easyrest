package main

import (
	"flag"
	"fmt"

	hplugin "github.com/hashicorp/go-plugin"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	redisPlugin "github.com/onegreyonewhite/easyrest/plugins/redis"
	_ "go.uber.org/automaxprocs"
)

func main() {
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(easyrest.Version)
		return
	}

	cacheImpl := redisPlugin.NewRedisCachePlugin()

	hplugin.Serve(&hplugin.ServeConfig{
		HandshakeConfig: easyrest.Handshake,
		Plugins: map[string]hplugin.Plugin{
			// Only register the cache plugin
			"cache": &easyrest.CachePluginPlugin{Impl: cacheImpl},
		},
	})
	defer cacheImpl.Close()
}
