package main

import (
	"flag"
	"fmt"

	hplugin "github.com/hashicorp/go-plugin"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	sqlite "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
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
			"db":    &easyrest.DBPluginPlugin{Impl: sqlite.NewSqlitePlugin()},
			"cache": &easyrest.CachePluginPlugin{Impl: sqlite.NewSqliteCachePlugin()},
		},
		Test: nil,
	})
}
