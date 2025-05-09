package main

import (
	"github.com/onegreyonewhite/easyrest/internal/cli"
	"github.com/onegreyonewhite/easyrest/internal/server"

	_ "go.uber.org/automaxprocs"
)

func main() {
	cfg, err := cli.ParseFlags()
	if err == nil {
		server.Run(cfg)
	}
}
