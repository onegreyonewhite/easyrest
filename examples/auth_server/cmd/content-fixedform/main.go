package main

import (
	"flag"
	"fmt"

	hplugin "github.com/hashicorp/go-plugin"
	"github.com/onegreyonewhite/easyrest/examples/auth_server/fixedform"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func main() {
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(easyrest.Version)
		return
	}

	hplugin.Serve(&hplugin.ServeConfig{
		HandshakeConfig: easyrest.Handshake,
		Plugins: map[string]hplugin.Plugin{
			"content": &easyrest.ContentPluginPlugin{Impl: fixedform.New()},
		},
		Test: nil,
	})
}
