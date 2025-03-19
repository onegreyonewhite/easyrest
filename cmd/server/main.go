package main

import (
	"flag"
	"fmt"

	"github.com/onegreyonewhite/easyrest/internal/config"
	"github.com/onegreyonewhite/easyrest/internal/server"
	"github.com/onegreyonewhite/easyrest/plugin"
)

func main() {
	// Load base configuration from environment variables
	cfg := config.Load()

	// Define command line flags
	showVersion := flag.Bool("version", false, "Show version and exit")
	port := flag.String("port", "", "Server port")
	checkScope := flag.Bool("check-scope", true, "Enable scope checking")
	tokenSecret := flag.String("token-secret", "", "JWT token secret")
	tokenUserSearch := flag.String("token-user-search", "", "JWT claim key for user ID")
	noPluginLog := flag.Bool("no-plugin-log", true, "Disable plugin logging")
	accessLogOn := flag.Bool("access-log", false, "Enable access logging")
	defaultTimezone := flag.String("timezone", "", "Default timezone")
	tokenURL := flag.String("token-url", "", "Token validation URL")
	authFlow := flag.String("auth-flow", "", "Authentication flow type")

	// Parse flags
	flag.Parse()

	// If version flag is set, show version and exit
	if *showVersion {
		fmt.Println(plugin.Version)
		return
	}

	// Update configuration with values from flags if they are set
	if *port != "" {
		cfg.Port = *port
	}
	if flag.Lookup("check-scope").Value.String() != "" {
		cfg.CheckScope = *checkScope
	}
	if *tokenSecret != "" {
		cfg.TokenSecret = *tokenSecret
	}
	if *tokenUserSearch != "" {
		cfg.TokenUserSearch = *tokenUserSearch
	}
	if flag.Lookup("no-plugin-log").Value.String() != "" {
		cfg.NoPluginLog = *noPluginLog
	}
	if flag.Lookup("access-log").Value.String() != "" {
		cfg.AccessLogOn = *accessLogOn
	}
	if *defaultTimezone != "" {
		cfg.DefaultTimezone = *defaultTimezone
	}
	if *tokenURL != "" {
		cfg.TokenURL = *tokenURL
	}
	if *authFlow != "" {
		cfg.AuthFlow = *authFlow
	}

	// Run server
	server.Run(cfg)
}
