package main

import (
	"flag"
	"fmt"

	"github.com/onegreyonewhite/easyrest/internal/server"
	"github.com/onegreyonewhite/easyrest/plugin"
)

func main() {
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(plugin.Version)
		return
	}

	// Start the server using code from internal/server.
	server.Run()
}
