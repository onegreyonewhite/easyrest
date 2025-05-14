package main

import (
	hcplugin "github.com/hashicorp/go-plugin"
	easyrestPlugin "github.com/onegreyonewhite/easyrest/plugin"
	jwtAuth "github.com/onegreyonewhite/easyrest/plugins/auth/jwt"
)

func main() {
	hcplugin.Serve(&hcplugin.ServeConfig{
		HandshakeConfig: easyrestPlugin.Handshake,
		Plugins: map[string]hcplugin.Plugin{
			"auth": &easyrestPlugin.AuthPluginPlugin{Impl: &jwtAuth.JWTAuthPlugin{}},
		},
	})
}
