package main

import (
	hplugin "github.com/hashicorp/go-plugin"
	easyrestPlugin "github.com/onegreyonewhite/easyrest/plugin"
	dbqueryhook "github.com/onegreyonewhite/easyrest/plugins/middleware/dbqueryhook"
)

func main() {
	hplugin.Serve(&hplugin.ServeConfig{
		HandshakeConfig: easyrestPlugin.Handshake,
		Plugins: map[string]hplugin.Plugin{
			"middleware": &easyrestPlugin.MiddlewarePluginPlugin{Impl: dbqueryhook.New()},
		},
	})
}
