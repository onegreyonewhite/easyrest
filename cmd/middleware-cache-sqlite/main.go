package main

import (
	hplugin "github.com/hashicorp/go-plugin"
	easyrestPlugin "github.com/onegreyonewhite/easyrest/plugin"
	sqlitePlugin "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
	cachemw "github.com/onegreyonewhite/easyrest/plugins/middleware/cache"
)

func main() {
	hplugin.Serve(&hplugin.ServeConfig{
		HandshakeConfig: easyrestPlugin.Handshake,
		Plugins: map[string]hplugin.Plugin{
			"middleware": &easyrestPlugin.MiddlewarePluginPlugin{Impl: cachemw.New(sqlitePlugin.NewSqliteCachePlugin())},
		},
	})
}
