package main

import (
	hcplugin "github.com/hashicorp/go-plugin"
	easyrestPlugin "github.com/onegreyonewhite/easyrest/plugin"
	awssigv4 "github.com/onegreyonewhite/easyrest/plugins/auth/awssigv4"
)

func main() {
	hcplugin.Serve(&hcplugin.ServeConfig{
		HandshakeConfig: easyrestPlugin.Handshake,
		Plugins: map[string]hcplugin.Plugin{
			"auth": &easyrestPlugin.AuthPluginPlugin{Impl: &awssigv4.AWSSigV4AuthPlugin{}},
		},
	})
}
