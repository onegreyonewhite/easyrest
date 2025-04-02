package main

import (
	"flag"
	"fmt"
	"strings"

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
	enablePluginLog := flag.Bool("enable-plugin-log", false, "Enable plugin logging")
	accessLogOn := flag.Bool("access-log", false, "Enable access logging")
	defaultTimezone := flag.String("timezone", "", "Default timezone")
	tokenURL := flag.String("token-url", "", "Token validation URL")
	authFlow := flag.String("auth-flow", "", "Authentication flow type")

	// CORS flags
	corsEnabled := flag.Bool("cors-enabled", false, "Enable CORS support")

	// CORS configuration flags (only used when cors-enabled is true)
	var corsOrigins, corsMethods, corsHeaders string
	var corsMaxAge int

	// Define CORS flags with custom usage messages
	flag.StringVar(&corsOrigins, "cors-origins", "", "Comma-separated list of allowed CORS origins (requires --cors-enabled)")
	flag.StringVar(&corsMethods, "cors-methods", "", "Comma-separated list of allowed CORS methods (requires --cors-enabled)")
	flag.StringVar(&corsHeaders, "cors-headers", "", "Comma-separated list of allowed CORS headers (requires --cors-enabled)")
	flag.IntVar(&corsMaxAge, "cors-max-age", 86400, "Maximum age for CORS preflight requests in seconds (requires --cors-enabled)")

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
	if flag.Lookup("enable-plugin-log").Value.String() != "" {
		cfg.NoPluginLog = !*enablePluginLog
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

	// Update CORS configuration from flags
	if flag.Lookup("cors-enabled").Value.String() != "" {
		cfg.CORSEnabled = *corsEnabled
	}

	// Only process other CORS flags if CORS is enabled
	if cfg.CORSEnabled {
		if corsOrigins != "" {
			cfg.CORSOrigins = strings.Split(corsOrigins, ",")
		}
		if corsMethods != "" {
			cfg.CORSMethods = strings.Split(corsMethods, ",")
		}
		if corsHeaders != "" {
			cfg.CORSHeaders = strings.Split(corsHeaders, ",")
		}
		if flag.Lookup("cors-max-age").Value.String() != "" {
			cfg.CORSMaxAge = corsMaxAge
		}
	} else {
		// If CORS is disabled, show warning if other CORS flags were used
		if corsOrigins != "" || corsMethods != "" || corsHeaders != "" {
			fmt.Println("Warning: CORS-related flags were ignored because --cors-enabled is not set")
		}
	}

	// Run server
	server.Run(cfg)
}
