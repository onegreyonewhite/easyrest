package main

import (
	"log"

	"github.com/onegreyonewhite/easyrest/embed"
	"github.com/onegreyonewhite/easyrest/internal/cli"
)

func main() {
	files, overlay, err := cli.ParseFlags()
	if err != nil {
		log.Fatal(err)
	}
	if err := embed.Run(overlay, files); err != nil {
		log.Fatal(err)
	}
}
