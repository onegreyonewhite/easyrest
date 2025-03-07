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
}

func Load() Config {
	// Port: default "8080"
	port := os.Getenv("ER_PORT")
	if port == "" {
		port = "8080"
	}

	// CheckScope: if not set default to true; if set, only "1" yields true.
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

	// NoPluginLog: if not set, default to true; otherwise only "1" yields true.
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

	return Config{
		Port:            port,
		CheckScope:      checkScope,
		TokenSecret:     tokenSecret,
		TokenUserSearch: tokenUserSearch,
		NoPluginLog:     noPluginLog,
		AccessLogOn:     accessLogOn,
		DefaultTimezone: defaultTimezone,
	}
}
