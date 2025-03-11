package config

import (
	"os"
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
	}
}
