package config

import (
	"bytes" // Required for yaml.Decoder
	"encoding/json"
	"fmt"
	"io" // Required for yaml.Decoder EOF check
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/docker/go-units"
	"gopkg.in/yaml.v3"
)

type AccessConfig struct {
	Table []string `yaml:"table,omitempty"`
	Func  []string `yaml:"func,omitempty"`
}

type PluginConfig struct {
	Name                string              `yaml:"name,omitempty"`
	Uri                 string              `yaml:"uri"`
	Path                string              `yaml:"path,omitempty"`
	FuncInvalidationMap map[string][]string `yaml:"cache_invalidation_map,omitempty"`
	EnableCache         bool                `yaml:"enable_cache,omitempty"`
	CacheName           string              `yaml:"cache_name,omitempty"`
	DbTxEnd             string              `yaml:"db_tx_end,omitempty"`
	Public              AccessConfig        `yaml:"public,omitempty"`
	Exclude             AccessConfig        `yaml:"exclude,omitempty"`
	AllowList           AccessConfig        `yaml:"allow,omitempty"`
	Title               string              `yaml:"title,omitempty"`
	DefaultLimit        int                 `yaml:"default_limit,omitempty"`
}

type CORSConfig struct {
	Enabled bool     `yaml:"enabled"`
	Origins []string `yaml:"origins"`
	Methods []string `yaml:"methods"`
	Headers []string `yaml:"headers"`
	MaxAge  int      `yaml:"max_age"`
}

// ServerConfig holds HTTP server tunables.
type ServerConfig struct {
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	KeepAlivePeriod   time.Duration `yaml:"keep_alive_period"`
	MaxHeaderBytes    int           `yaml:"max_header_bytes"`
	MaxBodySize       int64         `yaml:"max_body_size"`

	// HTTP/2 specific
	HTTP2MaxConcurrentStreams         uint32        `yaml:"http2_max_concurrent_streams"`
	HTTP2MaxReadFrameSize             uint32        `yaml:"http2_max_read_frame_size"`
	HTTP2MaxUploadBufferPerConnection int32         `yaml:"http2_max_upload_buffer_per_connection"`
	HTTP2MaxUploadBufferPerStream     int32         `yaml:"http2_max_upload_buffer_per_stream"`
	HTTP2IdleTimeout                  time.Duration `yaml:"http2_idle_timeout"`
	HTTP2ReadIdleTimeout              time.Duration `yaml:"http2_read_idle_timeout"`
	HTTP2PingTimeout                  time.Duration `yaml:"http2_ping_timeout"`
	HTTP2PermitProhibitedCipherSuites bool          `yaml:"http2_permit_prohibited_cipher_suites"`
}

type OtelConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Endpoint    string `yaml:"endpoint"`
	Protocol    string `yaml:"protocol"` // "otlp", "otlphttp", "zipkin"
	ServiceName string `yaml:"service_name"`
}

type Config struct {
	Port            string `yaml:"port"`
	CheckScope      bool   `yaml:"check_scope"`
	TokenSecret     string `yaml:"token_secret"`
	TokenUserSearch string `yaml:"token_user_search"`
	NoPluginLog     bool   `yaml:"plugin_log"`
	AccessLogOn     bool   `yaml:"access_log"`
	DefaultTimezone string `yaml:"default_timezone"`
	DefaultLimit    int    `yaml:"default_limit"`
	TokenURL        string `yaml:"token_url"`
	TokenCacheTTL   int    `yaml:"token_cache_ttl"`
	AuthFlow        string `yaml:"auth_flow"`
	// CORS settings
	CORS CORSConfig `yaml:"cors"`

	// Otel settings
	Otel OtelConfig `yaml:"otel"`

	// TLS settings
	TLSEnabled  bool   `yaml:"tls_enabled"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	// Plugin settings
	Plugins    []string                `yaml:"plugin_configs"`
	PluginMap  map[string]PluginConfig `yaml:"plugins"`
	AnonClaims map[string]any          `yaml:"anon_claims,omitempty"`
	Server     ServerConfig            `yaml:"server"`
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
			// Look for specific cache config for this DB connection
			cacheName := os.Getenv(fmt.Sprintf("ER_DB_%s_CACHENAME", connName))
			plugins[connName] = PluginConfig{
				Name:        connName,
				Uri:         parts[1],
				EnableCache: os.Getenv(fmt.Sprintf("ER_CACHE_ENABLE_%s", connName)) == "1",
				CacheName:   cacheName,
				DbTxEnd:     "commit-allow-override",
			}
		} else if strings.HasPrefix(env, "ER_CACHE_") && !strings.HasPrefix(env, "ER_CACHE_ENABLE_") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) != 2 {
				continue
			}
			envName := parts[0]
			connName := strings.ToLower(strings.TrimPrefix(envName, "ER_CACHE_"))
			plugins[connName] = PluginConfig{
				Name:    connName,
				Uri:     parts[1],
				DbTxEnd: "commit",
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
			if cfg.DbTxEnd == "" {
				cfg.DbTxEnd = "commit"
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

	// Server settings
	serverReadTimeout := 5 * time.Second
	if v := os.Getenv("ER_SERVER_READ_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			serverReadTimeout = d
		}
	}
	serverWriteTimeout := 10 * time.Second
	if v := os.Getenv("ER_SERVER_WRITE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			serverWriteTimeout = d
		}
	}
	serverIdleTimeout := 120 * time.Second
	if v := os.Getenv("ER_SERVER_IDLE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			serverIdleTimeout = d
		}
	}
	serverMaxHeaderBytes := 1 << 20
	if v := os.Getenv("ER_SERVER_MAX_HEADER_BYTES"); v != "" {
		if n, err := units.FromHumanSize(v); err == nil {
			serverMaxHeaderBytes = int(n)
		}
	}
	serverReadHeaderTimeout := 5 * time.Second
	if v := os.Getenv("ER_SERVER_READ_HEADER_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			serverReadHeaderTimeout = d
		}
	}
	serverKeepAlivePeriod := 3 * time.Minute
	if v := os.Getenv("ER_SERVER_KEEP_ALIVE_PERIOD"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			serverKeepAlivePeriod = d
		}
	}

	serverMaxBodySize := int64(10 * 1024 * 1024) // 10 MB default
	if v := os.Getenv("ER_SERVER_MAX_BODY_SIZE"); v != "" {
		if n, err := units.FromHumanSize(v); err == nil {
			serverMaxBodySize = n
		}
	}

	// HTTP/2 settings
	http2MaxConcurrentStreams := uint32(0)
	if v := os.Getenv("ER_HTTP2_MAX_CONCURRENT_STREAMS"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			http2MaxConcurrentStreams = uint32(n)
		}
	}
	http2MaxReadFrameSize := uint32(0)
	if v := os.Getenv("ER_HTTP2_MAX_READ_FRAME_SIZE"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			http2MaxReadFrameSize = uint32(n)
		}
	}
	http2MaxUploadBufferPerConn := int32(0)
	if v := os.Getenv("ER_HTTP2_MAX_UPLOAD_BUFFER_PER_CONNECTION"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 32); err == nil {
			http2MaxUploadBufferPerConn = int32(n)
		}
	}
	http2MaxUploadBufferPerStream := int32(0)
	if v := os.Getenv("ER_HTTP2_MAX_UPLOAD_BUFFER_PER_STREAM"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 32); err == nil {
			http2MaxUploadBufferPerStream = int32(n)
		}
	}
	http2IdleTimeout := time.Duration(0)
	if v := os.Getenv("ER_HTTP2_IDLE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			http2IdleTimeout = d
		}
	}
	http2ReadIdleTimeout := time.Duration(0)
	if v := os.Getenv("ER_HTTP2_READ_IDLE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			http2ReadIdleTimeout = d
		}
	}
	http2PingTimeout := time.Duration(0)
	if v := os.Getenv("ER_HTTP2_PING_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			http2PingTimeout = d
		}
	}
	http2PermitProhibitedCipherSuites := false
	if v := os.Getenv("ER_HTTP2_PERMIT_PROHIBITED_CIPHER_SUITES"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			http2PermitProhibitedCipherSuites = b
		}
	}

	tokenCacheTTL := -1
	if v := os.Getenv("ER_TOKEN_CACHE_TTL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			tokenCacheTTL = n
		}
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
		TokenCacheTTL:   tokenCacheTTL,
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
		Plugins:    pluginsList,
		PluginMap:  make(map[string]PluginConfig),
		AnonClaims: make(map[string]any),
		Server: ServerConfig{
			ReadTimeout:                       serverReadTimeout,
			WriteTimeout:                      serverWriteTimeout,
			IdleTimeout:                       serverIdleTimeout,
			MaxHeaderBytes:                    serverMaxHeaderBytes,
			MaxBodySize:                       serverMaxBodySize,
			ReadHeaderTimeout:                 serverReadHeaderTimeout,
			KeepAlivePeriod:                   serverKeepAlivePeriod,
			HTTP2MaxConcurrentStreams:         http2MaxConcurrentStreams,
			HTTP2MaxReadFrameSize:             http2MaxReadFrameSize,
			HTTP2MaxUploadBufferPerConnection: http2MaxUploadBufferPerConn,
			HTTP2MaxUploadBufferPerStream:     http2MaxUploadBufferPerStream,
			HTTP2IdleTimeout:                  http2IdleTimeout,
			HTTP2ReadIdleTimeout:              http2ReadIdleTimeout,
			HTTP2PingTimeout:                  http2PingTimeout,
			HTTP2PermitProhibitedCipherSuites: http2PermitProhibitedCipherSuites,
		},
	}

	// Load AnonClaims from environment variable if present (as JSON)
	if anonClaimsStr := os.Getenv("ER_ANON_CLAIMS"); anonClaimsStr != "" {
		var anonClaims map[string]any
		if err := json.Unmarshal([]byte(anonClaimsStr), &anonClaims); err == nil {
			cfg.AnonClaims = anonClaims
		} else {
			log.Printf("Failed to parse ER_ANON_CLAIMS: %v", err)
		}
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

	if cfg.AccessLogOn {
		log.Print("Access log enabled\n")
	}

	if cfg.CheckScope {
		log.Print("Token's scope check enabled\n")
	}

	log.Printf("Default server timezone: %s\n", cfg.DefaultTimezone)

	if cfg.DefaultLimit == 0 {
		cfg.DefaultLimit = 100
	}

	if cfg.Otel.Endpoint == "" {
		cfg.Otel.Enabled = false
	}

	if cfg.Otel.Protocol == "" {
		cfg.Otel.Protocol = "otlp"
	}

	if cfg.Otel.ServiceName == "" {
		cfg.Otel.ServiceName = "easyrest-server"
	}

	if cfg.Otel.Enabled {
		log.Printf("Otel enabled with protocol %s, endpoint %s and service name %s\n", cfg.Otel.Protocol, cfg.Otel.Endpoint, cfg.Otel.ServiceName)
	}

	for pluginName, pluginCfg := range cfg.PluginMap {
		pluginCfg.Name = pluginName
		if pluginCfg.DbTxEnd == "" {
			pluginCfg.DbTxEnd = "commit"
		}
		cfg.PluginMap[pluginName] = pluginCfg
		if pluginCfg.DefaultLimit == 0 {
			pluginCfg.DefaultLimit = cfg.DefaultLimit
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
