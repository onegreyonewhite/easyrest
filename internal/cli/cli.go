package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/onegreyonewhite/easyrest/internal/config"
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

func ParseFlags() (config.Config, error) {
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
		return config.Config{}, errors.New("version flag set")
	}

	// Load plugins
	if len(plugins) > 0 {
		os.Setenv("ER_PLUGINS", strings.Join(plugins, ","))
	}

	if *configFile != "" {
		fstat, err := os.Stat(*configFile)
		if err != nil && errors.Is(err, os.ErrNotExist) {
			fmt.Println("Config file does not exist:", *configFile)
		} else if err == nil && !fstat.IsDir() {
			os.Setenv("ER_CONFIG_FILE", *configFile)
		}
	}

	if *port != "" {
		os.Setenv("ER_PORT", *port)
	}
	if flag.Lookup("check-scope").Value.String() != "" {
		os.Setenv("ER_CHECK_SCOPE", flag.Lookup("check-scope").Value.String())
	}
	if *tokenSecret != "" {
		os.Setenv("ER_TOKEN_SECRET", *tokenSecret)
	}
	if *tokenUserSearch != "" {
		os.Setenv("ER_TOKEN_USER_SEARCH", *tokenUserSearch)
	}
	if flag.Lookup("enable-plugin-log").Value.String() != "" {
		if *enablePluginLog {
			os.Setenv("ER_NO_PLUGIN_LOG", "true")
		}
	}
	if flag.Lookup("access-log").Value.String() != "" && *accessLogOn {
		os.Setenv("ER_ACCESS_LOG", "true")
	}
	if *defaultTimezone != "" {
		os.Setenv("ER_DEFAULT_TIMEZONE", *defaultTimezone)
	}
	if *tokenURL != "" {
		os.Setenv("ER_TOKEN_URL", *tokenURL)
	}
	if *authFlow != "" {
		os.Setenv("ER_AUTH_FLOW", *authFlow)
	}
	if *corsEnabled {
		os.Setenv("ER_CORS_ENABLED", "1")
	}
	if corsOrigins != "" {
		os.Setenv("ER_CORS_ORIGINS", corsOrigins)
	}
	if corsMethods != "" {
		os.Setenv("ER_CORS_METHODS", corsMethods)
	}
	if corsHeaders != "" {
		os.Setenv("ER_CORS_HEADERS", corsHeaders)
	}
	if corsMaxAge != 0 {
		os.Setenv("ER_CORS_MAX_AGE", strconv.Itoa(corsMaxAge))
	}
	if tlsCertFile != "" {
		os.Setenv("ER_TLS_CERT_FILE", tlsCertFile)
	}
	if tlsKeyFile != "" {
		os.Setenv("ER_TLS_KEY_FILE", tlsKeyFile)
	}
	if *checkScope {
		os.Setenv("ER_CHECK_SCOPE", "true")
	}

	// Load base configuration from environment variables
	return server.GetConfig(), nil
}
