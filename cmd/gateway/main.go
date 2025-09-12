package main

import (
	"github.com/onegreyonewhite/easyrest/internal/cli"
	"github.com/onegreyonewhite/easyrest/internal/server"
)

func main() {
	cfg, err := cli.ParseFlags()
	if err == nil {
		server.Run(cfg)
	}
}
