package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/onegreyonewhite/easyrest/internal/server"
	"github.com/onegreyonewhite/easyrest/plugin"
)

type pluginsFlag []string

func (p *pluginsFlag) String() string {
	return strings.Join(*p, ",")
}
func (p *pluginsFlag) Set(value string) error {
	*p = append(*p, value)
	return nil
}

func main() {
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

	// Define configuration flags
	configFile := flag.String("config", "", "Path to configuration file")

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

	// TLS flags
	var tlsCertFile, tlsKeyFile string
	flag.StringVar(&tlsCertFile, "tls-cert-file", "", "Path to TLS certificate file")
	flag.StringVar(&tlsKeyFile, "tls-key-file", "", "Path to TLS key file")

	// Plugin configuration flags
	var plugins pluginsFlag
	flag.Var(&plugins, "plugin", "Config for plugins to load (can be specified multiple times)")

	// Parse flags
	flag.Parse()

	// If version flag is set, show version and exit
	if *showVersion {
		fmt.Println(plugin.Version)
		return
	}

	// Load plugins
	if len(plugins) > 0 {
		os.Setenv("ER_PLUGINS", strings.Join(plugins, ","))
	}

	if *configFile != "" {
		fstat, err := os.Stat(*configFile)
		if err != nil && errors.Is(err, os.ErrNotExist) {
			fmt.Println("Config file does not exist:", *configFile)
		}
		if !fstat.IsDir() {
			os.Setenv("ER_CONFIG_FILE", *configFile)
		}
	}

	// Load base configuration from environment variables
	cfg := server.GetConfig()

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
		cfg.CORS.Enabled = *corsEnabled
	}

	// Only process other CORS flags if CORS is enabled
	if cfg.CORS.Enabled {
		if corsOrigins != "" {
			cfg.CORS.Origins = strings.Split(corsOrigins, ",")
		}
		if corsMethods != "" {
			cfg.CORS.Methods = strings.Split(corsMethods, ",")
		}
		if corsHeaders != "" {
			cfg.CORS.Headers = strings.Split(corsHeaders, ",")
		}
		if flag.Lookup("cors-max-age").Value.String() != "" {
			cfg.CORS.MaxAge = corsMaxAge
		}
	} else {
		// If CORS is disabled, show warning if other CORS flags were used
		if corsOrigins != "" || corsMethods != "" || corsHeaders != "" {
			fmt.Println("Warning: CORS-related flags were ignored because --cors-enabled is not set")
		}
	}

	// Update TLS configuration from flags
	if tlsCertFile != "" {
		cfg.TLSCertFile = tlsCertFile
	}
	if tlsKeyFile != "" {
		cfg.TLSKeyFile = tlsKeyFile
	}

	// Automatically enable TLS if both certificate and key are provided
	if tlsCertFile != "" && tlsKeyFile != "" {
		cfg.TLSEnabled = true
	}

	// Run server
	server.Run(cfg)
}
