package config

import (
	"bytes" // Required for yaml.Decoder
	"io"    // Required for yaml.Decoder EOF check
	"log"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type PluginConfig struct {
	Name string `yaml:"name"`
	Uri  string `yaml:"uri"`
	Path string `yaml:"path"`
}

type CORSConfig struct {
	Enabled bool     `yaml:"enabled"`
	Origins []string `yaml:"origins"`
	Methods []string `yaml:"methods"`
	Headers []string `yaml:"headers"`
	MaxAge  int      `yaml:"max_age"`
}

type Config struct {
	Port            string `yaml:"port"`
	CheckScope      bool   `yaml:"check_scope"`
	TokenSecret     string `yaml:"token_secret"`
	TokenUserSearch string `yaml:"token_user_search"`
	NoPluginLog     bool   `yaml:"plugin_log"`
	AccessLogOn     bool   `yaml:"access_log"`
	DefaultTimezone string `yaml:"default_timezone"`
	TokenURL        string `yaml:"token_url"`
	AuthFlow        string `yaml:"auth_flow"`
	// CORS settings
	CORS CORSConfig `yaml:"cors"`

	// TLS settings
	TLSEnabled  bool   `yaml:"tls_enabled"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	// Plugin settings
	Plugins   []string                `yaml:"plugin_configs"`
	PluginMap map[string]PluginConfig `yaml:"plugins"`
}

func LoadPluginConfigs(configs []string) map[string]PluginConfig {
	plugins := make(map[string]PluginConfig)
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "ER_DB_") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) != 2 {
				continue
			}
			envName := parts[0]
			connName := strings.ToLower(strings.TrimPrefix(envName, "ER_DB_"))
			plugins[connName] = PluginConfig{
				Name: connName,
				Uri:  parts[1],
			}
		}
	}
	for _, path := range configs {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("ERROR: can't read file %s: %v", path, err)
			continue // Skip to the next file on read error
		}

		decoder := yaml.NewDecoder(bytes.NewReader(data))
		for {
			var cfg PluginConfig
			// Decode one YAML document.
			if err := decoder.Decode(&cfg); err != nil {
				// Check if we reached the end of the file stream.
				if err == io.EOF {
					break // End of YAML stream for this file
				}
				// Log other decoding errors.
				log.Printf("ERROR: can't parse document in file %s: %v", path, err)
				// Stop processing this file on the first parse error to avoid potential issues.
				break
			}
			// Ensure plugin name is not empty before adding to the map.
			if cfg.Name == "" {
				log.Printf("WARN: skipping plugin config in file %s with empty name", path)
				continue // Skip this document and proceed to the next
			}
			// Add the successfully parsed config to the map.
			plugins[cfg.Name] = cfg
		}
	}
	return plugins
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

	// Load TLS settings
	tlsCertFile := os.Getenv("ER_TLS_CERT_FILE")
	tlsKeyFile := os.Getenv("ER_TLS_KEY_FILE")
	tlsEnabled := false
	if tlsCertFile != "" && tlsKeyFile != "" {
		tlsEnabled = true
	}

	pluginsList := []string{}
	if plugins := os.Getenv("ER_PLUGINS"); plugins != "" {
		// Split the plugins by comma and trim whitespace
		pluginsList = strings.Split(plugins, ",")
	}

	cfg := Config{
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
		CORS: CORSConfig{
			Enabled: corsEnabled,
			Origins: corsOrigins,
			Methods: corsMethods,
			Headers: corsHeaders,
			MaxAge:  corsMaxAge,
		},
		// TLS settings
		TLSEnabled:  tlsEnabled,
		TLSCertFile: tlsCertFile,
		TLSKeyFile:  tlsKeyFile,
		// Plugin settings
		Plugins:   pluginsList,
		PluginMap: make(map[string]PluginConfig),
	}

	// Load config from environment variable
	configFile := os.Getenv("ER_CONFIG_FILE")
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err == nil {
			log.Printf("Loading config from %s\n", configFile)
			yaml.Unmarshal(data, &cfg)
		}
	}
	for name, plcfg := range LoadPluginConfigs(cfg.Plugins) {
		if _, exists := cfg.PluginMap[name]; !exists {
			cfg.PluginMap[name] = plcfg
		}
	}
	log.Printf("Loaded %d plugins\n", len(cfg.PluginMap))
	if cfg.CORS.Enabled {
		log.Printf(
			"CORS enabled with settings:\nOrigins = %v\nMethods = %v\nHeaders = %v\nMax_age = %d\n",
			strings.Join(cfg.CORS.Origins, ","),
			strings.Join(cfg.CORS.Methods, ","),
			strings.Join(cfg.CORS.Headers, ","),
			cfg.CORS.MaxAge,
		)
	}
	if cfg.TLSEnabled {
		log.Printf("TLS enabled with cert %s and key %s\n", cfg.TLSCertFile, cfg.TLSKeyFile)
	}
	return cfg
}
