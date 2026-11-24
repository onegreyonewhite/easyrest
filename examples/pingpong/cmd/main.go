package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/onegreyonewhite/easyrest/embed"
	"github.com/onegreyonewhite/easyrest/examples/pingpong"
)

func main() {
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	// config.yaml lives next to this cmd directory.
	configPath := filepath.Join(dir, "..", "config.yaml")
	pingURL := "http://127.0.0.1:8091" + pingpong.PongPath
	opts := pingpong.EmbedOptions(pingURL, log.Printf)
	if err := embed.Run("", []string{configPath}, opts...); err != nil {
		log.Fatal(err)
	}
}