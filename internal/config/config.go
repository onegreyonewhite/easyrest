package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port            string
	CheckScope      bool
	TokenSecret     string
	TokenUserSearch string
	NoPluginLog     bool
	AccessLogOn     bool
	DefaultTimezone string
	TokenURL        string
	AuthFlow        string
	// CORS settings
	CORSEnabled bool
	CORSOrigins []string
	CORSMethods []string
	CORSHeaders []string
	CORSMaxAge  int
}

func Load() Config {
	// Port: default "8080"
	port := os.Getenv("ER_PORT")
	if port == "" {
		port = "8080"
	}

	// CheckScope: default true, unless set to other value than "1"
	checkScopeStr := os.Getenv("ER_CHECK_SCOPE")
	checkScope := true
	if checkScopeStr != "" {
		if checkScopeStr == "1" {
			checkScope = true
		} else {
			checkScope = false
		}
	}

	// TokenSecret and TokenUserSearch with default for TokenUserSearch.
	tokenSecret := os.Getenv("ER_TOKEN_SECRET")
	tokenUserSearch := os.Getenv("ER_TOKEN_USER_SEARCH")
	if tokenUserSearch == "" {
		tokenUserSearch = "sub"
	}

	// NoPluginLog: default true, unless set to other value than "1"
	noPluginLogStr := os.Getenv("ER_NO_PLUGIN_LOG")
	noPluginLog := true
	if noPluginLogStr != "" {
		if noPluginLogStr == "1" {
			noPluginLog = true
		} else {
			noPluginLog = false
		}
	}

	// AccessLogOn: if set to "1" then true, else false (default false).
	accessLogOnStr := os.Getenv("ER_ACCESSLOG")
	accessLogOn := false
	if accessLogOnStr == "1" {
		accessLogOn = true
	}

	// DefaultTimezone: try environment variable, then system /etc/localtime
	defaultTimezone := os.Getenv("ER_DEFAULT_TIMEZONE")
	if defaultTimezone == "" {
		link, err := os.Readlink("/etc/localtime")
		if err != nil {
			defaultTimezone = "GMT"
		} else {
			parts := strings.Split(link, "/")
			if len(parts) > 2 {
				defaultTimezone = strings.Join(parts[len(parts)-2:], "/")
			} else {
				defaultTimezone = link
			}
		}
	}

	// TokenURL: HTTP path for authorization from ER_TOKEN_AUTHURL
	tokenURL := os.Getenv("ER_TOKEN_AUTHURL")

	authFlow := os.Getenv("ER_TOKEN_AUTHFLOW")

	if authFlow == "" {
		authFlow = "password"
	}

	// CORS configuration
	corsEnabled := os.Getenv("ER_CORS_ENABLED") == "1"

	corsOrigins := strings.Split(os.Getenv("ER_CORS_ORIGINS"), ",")
	if len(corsOrigins) == 1 && corsOrigins[0] == "" {
		corsOrigins = []string{"*"}
	}

	corsMethods := strings.Split(os.Getenv("ER_CORS_METHODS"), ",")
	if len(corsMethods) == 1 && corsMethods[0] == "" {
		corsMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	}

	corsHeaders := strings.Split(os.Getenv("ER_CORS_HEADERS"), ",")
	if len(corsHeaders) == 1 && corsHeaders[0] == "" {
		corsHeaders = []string{"Content-Type", "Authorization", "X-Requested-With"}
	}

	corsMaxAge := 86400 // 24 hours default
	if maxAge := os.Getenv("ER_CORS_MAX_AGE"); maxAge != "" {
		if age, err := strconv.Atoi(maxAge); err == nil {
			corsMaxAge = age
		}
	}

	return Config{
		Port:            port,
		CheckScope:      checkScope,
		TokenSecret:     tokenSecret,
		TokenUserSearch: tokenUserSearch,
		NoPluginLog:     noPluginLog,
		AccessLogOn:     accessLogOn,
		DefaultTimezone: defaultTimezone,
		TokenURL:        tokenURL,
		AuthFlow:        authFlow,
		// CORS settings
		CORSEnabled: corsEnabled,
		CORSOrigins: corsOrigins,
		CORSMethods: corsMethods,
		CORSHeaders: corsHeaders,
		CORSMaxAge:  corsMaxAge,
	}
}
