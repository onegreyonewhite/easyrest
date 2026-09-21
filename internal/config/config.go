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
	yaml "github.com/goccy/go-yaml"
)

type AccessConfig struct {
	Table []string `yaml:"table,omitempty"`
	Func  []string `yaml:"func,omitempty"`
}

type PluginConfig struct {
	Name               string       `yaml:"name,omitempty"`
	Uri                string       `yaml:"uri"`
	Path               string       `yaml:"path,omitempty"`
	UseQuery           bool         `yaml:"use_query,omitempty"`
	DbTxEnd            string       `yaml:"db_tx_end,omitempty"`
	Public             AccessConfig `yaml:"public,omitempty"`
	Exclude            AccessConfig `yaml:"exclude,omitempty"`
	AllowList          AccessConfig `yaml:"allow,omitempty"`
	RequestMiddlewares []string     `yaml:"request_middlewares,omitempty"`
	Title              string       `yaml:"title,omitempty"`
	DefaultLimit       int          `yaml:"default_limit,omitempty"`
}

type AuthConfig struct {
	Path     string         `yaml:"path,omitempty"`
	Settings map[string]any `yaml:"settings,omitempty"`
}

type MiddlewareConfig struct {
	Path     string         `yaml:"path,omitempty"`
	Settings map[string]any `yaml:"settings,omitempty"`
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

	// Trusted proxy settings for client IP resolution (chi middleware.ClientIP*)
	TrustedProxyMode   string `yaml:"trusted_proxy_mode"`   // "none", "xff_count", or "header"
	TrustedProxyCount  int    `yaml:"trusted_proxy_count"`  // for xff_count: number of trusted proxies
	TrustedProxyHeader string `yaml:"trusted_proxy_header"` // for header: e.g. CF-Connecting-IP, X-Real-IP

	// DisableHTMLEscape turns off <>& escaping in JSON HTTP bodies (goccy SetEscapeHTML(false)).
	DisableHTMLEscape bool `yaml:"disable_html_escape"`
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
	TokenUserSearch string `yaml:"token_user_search"`
	NoPluginLog     bool   `yaml:"plugin_log"`
	AccessLogOn     bool   `yaml:"access_log"`
	DefaultTimezone string `yaml:"default_timezone"`
	DefaultLimit    int    `yaml:"default_limit"`
	TokenCacheTTL   int    `yaml:"token_cache_ttl"`
	// CORS settings
	CORS CORSConfig `yaml:"cors"`

	// Otel settings
	Otel OtelConfig `yaml:"otel"`

	// TLS settings
	TLSEnabled  bool   `yaml:"tls_enabled"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	// Plugin settings
	Plugins                  []string                    `yaml:"plugin_configs"`
	PluginMap                map[string]PluginConfig     `yaml:"plugins"`
	AuthPlugins              map[string]AuthConfig       `yaml:"auth_plugins"`
	MiddlewarePlugins        map[string]MiddlewareConfig `yaml:"middleware_plugins"`
	GlobalRequestMiddlewares []string                    `yaml:"global_request_middlewares"`
	AnonClaims               map[string]any              `yaml:"anon_claims,omitempty"`
	Server                   ServerConfig                `yaml:"server"`
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
				Name:     connName,
				Uri:      parts[1],
				UseQuery: os.Getenv(fmt.Sprintf("ER_USE_QUERY_%s", strings.ToUpper(connName))) == "1",
				DbTxEnd:  "commit-allow-override",
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

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envCSV(key string, def []string) []string {
	parts := strings.Split(os.Getenv(key), ",")
	if len(parts) == 1 && parts[0] == "" {
		return def
	}
	return parts
}

func envFlagDefaultTrue(key string) bool {
	v := os.Getenv(key)
	if v == "" {
		return true
	}
	return v == "1"
}

func loadEnvCORS() CORSConfig {
	maxAge := 86400
	if v := os.Getenv("ER_CORS_MAX_AGE"); v != "" {
		if age, err := strconv.Atoi(v); err == nil {
			maxAge = age
		}
	}
	return CORSConfig{
		Enabled: os.Getenv("ER_CORS_ENABLED") == "1",
		Origins: envCSV("ER_CORS_ORIGINS", []string{"*"}),
		Methods: envCSV("ER_CORS_METHODS", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
		Headers: envCSV("ER_CORS_HEADERS", []string{
			"Content-Type", "Authorization", "X-Requested-With",
			"Accept", "Prefer", "If-Match", "If-None-Match", "If-Resource-Version",
			"Range", "Range-Unit",
		}),
		MaxAge: maxAge,
	}
}

func loadEnvHTTP2() ServerConfig {
	cfg := ServerConfig{}
	if v := os.Getenv("ER_HTTP2_MAX_CONCURRENT_STREAMS"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			cfg.HTTP2MaxConcurrentStreams = uint32(n)
		}
	}
	if v := os.Getenv("ER_HTTP2_MAX_READ_FRAME_SIZE"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			cfg.HTTP2MaxReadFrameSize = uint32(n)
		}
	}
	if v := os.Getenv("ER_HTTP2_MAX_UPLOAD_BUFFER_PER_CONNECTION"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 32); err == nil {
			cfg.HTTP2MaxUploadBufferPerConnection = int32(n)
		}
	}
	if v := os.Getenv("ER_HTTP2_MAX_UPLOAD_BUFFER_PER_STREAM"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 32); err == nil {
			cfg.HTTP2MaxUploadBufferPerStream = int32(n)
		}
	}
	cfg.HTTP2IdleTimeout = envDuration("ER_HTTP2_IDLE_TIMEOUT", 0)
	cfg.HTTP2ReadIdleTimeout = envDuration("ER_HTTP2_READ_IDLE_TIMEOUT", 0)
	cfg.HTTP2PingTimeout = envDuration("ER_HTTP2_PING_TIMEOUT", 0)
	if v := os.Getenv("ER_HTTP2_PERMIT_PROHIBITED_CIPHER_SUITES"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.HTTP2PermitProhibitedCipherSuites = b
		}
	}
	return cfg
}

func loadEnvServerConfig() ServerConfig {
	server := loadEnvHTTP2()
	server.ReadTimeout = envDuration("ER_SERVER_READ_TIMEOUT", 5*time.Second)
	server.WriteTimeout = envDuration("ER_SERVER_WRITE_TIMEOUT", 10*time.Second)
	server.IdleTimeout = envDuration("ER_SERVER_IDLE_TIMEOUT", 120*time.Second)
	server.ReadHeaderTimeout = envDuration("ER_SERVER_READ_HEADER_TIMEOUT", 5*time.Second)
	server.KeepAlivePeriod = envDuration("ER_SERVER_KEEP_ALIVE_PERIOD", 3*time.Minute)
	server.MaxHeaderBytes = 1 << 20
	if v := os.Getenv("ER_SERVER_MAX_HEADER_BYTES"); v != "" {
		if n, err := units.FromHumanSize(v); err == nil {
			server.MaxHeaderBytes = int(n)
		}
	}
	server.MaxBodySize = int64(10 * 1024 * 1024)
	if v := os.Getenv("ER_SERVER_MAX_BODY_SIZE"); v != "" {
		if n, err := units.FromHumanSize(v); err == nil {
			server.MaxBodySize = n
		}
	}
	server.TrustedProxyMode = "none"
	if v := os.Getenv("ER_SERVER_TRUSTED_PROXY_MODE"); v != "" {
		server.TrustedProxyMode = strings.ToLower(strings.TrimSpace(v))
	}
	server.TrustedProxyCount = 1
	if v := os.Getenv("ER_SERVER_TRUSTED_PROXY_COUNT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			server.TrustedProxyCount = n
		}
	}
	server.TrustedProxyHeader = os.Getenv("ER_SERVER_TRUSTED_PROXY_HEADER")
	if v := os.Getenv("ER_SERVER_DISABLE_HTML_ESCAPE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			server.DisableHTMLEscape = b
		}
	}
	return server
}

func loadYAMLConfig(cfg *Config) {
	configFile := os.Getenv("ER_CONFIG_FILE")
	if configFile == "" {
		return
	}
	data, err := os.ReadFile(configFile)
	if err != nil {
		return
	}
	log.Printf("Loading config from %s\n", configFile)
	yaml.Unmarshal(data, cfg)
}

func finalizePluginMap(cfg *Config) {
	for pluginName, pluginCfg := range cfg.PluginMap {
		pluginCfg.Name = pluginName
		if pluginCfg.DbTxEnd == "" {
			pluginCfg.DbTxEnd = "commit"
		}
		if pluginCfg.DefaultLimit == 0 {
			pluginCfg.DefaultLimit = cfg.DefaultLimit
		}
		cfg.PluginMap[pluginName] = pluginCfg
	}
	for name, plcfg := range LoadPluginConfigs(cfg.Plugins) {
		if _, exists := cfg.PluginMap[name]; !exists {
			cfg.PluginMap[name] = plcfg
		}
	}
}

func defaultTimezone() string {
	if tz := os.Getenv("ER_DEFAULT_TIMEZONE"); tz != "" {
		return tz
	}
	link, err := os.Readlink("/etc/localtime")
	if err != nil {
		return "GMT"
	}
	parts := strings.Split(link, "/")
	if len(parts) > 2 {
		return strings.Join(parts[len(parts)-2:], "/")
	}
	return link
}

func Load() Config {
	port := os.Getenv("ER_PORT")
	if port == "" {
		port = "8080"
	}
	tokenSecret := os.Getenv("ER_TOKEN_SECRET")
	tokenUserSearch := os.Getenv("ER_TOKEN_USER_SEARCH")
	if tokenUserSearch == "" {
		tokenUserSearch = "sub"
	}
	authFlow := os.Getenv("ER_TOKEN_AUTHFLOW")
	if authFlow == "" {
		authFlow = "password"
	}
	tlsCertFile := os.Getenv("ER_TLS_CERT_FILE")
	tlsKeyFile := os.Getenv("ER_TLS_KEY_FILE")
	pluginsList := []string{}
	if plugins := os.Getenv("ER_PLUGINS"); plugins != "" {
		pluginsList = strings.Split(plugins, ",")
	}
	tokenCacheTTL := -1
	if v := os.Getenv("ER_TOKEN_CACHE_TTL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			tokenCacheTTL = n
		}
	}

	cfg := Config{
		Port:              port,
		CheckScope:        envFlagDefaultTrue("ER_CHECK_SCOPE"),
		TokenUserSearch:   tokenUserSearch,
		NoPluginLog:       envFlagDefaultTrue("ER_NO_PLUGIN_LOG"),
		AccessLogOn:       os.Getenv("ER_ACCESSLOG") == "1",
		DefaultTimezone:   defaultTimezone(),
		TokenCacheTTL:     tokenCacheTTL,
		CORS:              loadEnvCORS(),
		TLSEnabled:        tlsCertFile != "" && tlsKeyFile != "",
		TLSCertFile:       tlsCertFile,
		TLSKeyFile:        tlsKeyFile,
		Plugins:           pluginsList,
		PluginMap:         make(map[string]PluginConfig),
		AuthPlugins:       make(map[string]AuthConfig),
		MiddlewarePlugins: make(map[string]MiddlewareConfig),
		AnonClaims:        make(map[string]any),
		Server:            loadEnvServerConfig(),
	}

	if anonClaimsStr := os.Getenv("ER_ANON_CLAIMS"); anonClaimsStr != "" {
		var anonClaims map[string]any
		if err := json.Unmarshal([]byte(anonClaimsStr), &anonClaims); err == nil {
			cfg.AnonClaims = anonClaims
		} else {
			log.Printf("Failed to parse ER_ANON_CLAIMS: %v", err)
		}
	}

	loadYAMLConfig(&cfg)

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

	if len(cfg.AuthPlugins) == 0 {
		cfg.AuthPlugins = map[string]AuthConfig{
			"jwt": {
				Settings: map[string]any{
					"jwt_secret": tokenSecret,
					"flow":       authFlow,
				},
			},
		}
	}
	finalizePluginMap(&cfg)
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
