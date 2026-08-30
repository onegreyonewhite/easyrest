package main

import (
	hplugin "github.com/hashicorp/go-plugin"
	easyrestPlugin "github.com/onegreyonewhite/easyrest/plugin"
	lruPlugin "github.com/onegreyonewhite/easyrest/plugins/data/lru"
	cachemw "github.com/onegreyonewhite/easyrest/plugins/middleware/cache"
)

func main() {
	hplugin.Serve(&hplugin.ServeConfig{
		HandshakeConfig: easyrestPlugin.Handshake,
		Plugins: map[string]hplugin.Plugin{
			"middleware": &easyrestPlugin.MiddlewarePluginPlugin{Impl: cachemw.New(lruPlugin.NewSimpleCachePlugin())},
		},
	})
}
