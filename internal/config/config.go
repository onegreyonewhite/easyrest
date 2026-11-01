package config

import (
	"bytes" // Required for yaml.Decoder
	"fmt"
	"html/template"
	"io" // Required for yaml.Decoder EOF check
	"log"
	"os"
	"regexp"
	"strings"
	"time"

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
	Internal           bool         `yaml:"internal,omitempty"`
	DbTxEnd            string       `yaml:"db_tx_end,omitempty"`
	DbMaxRows          int          `yaml:"db_max_rows,omitempty"`
	DbPreferCount      string       `yaml:"db_prefer_count,omitempty"`
	Public             AccessConfig `yaml:"public,omitempty"`
	Exclude            AccessConfig `yaml:"exclude,omitempty"`
	AllowList          AccessConfig `yaml:"allow,omitempty"`
	RequestMiddlewares []string     `yaml:"request_middlewares,omitempty"`
	ContentHandlers    []string     `yaml:"content_handlers,omitempty"`
	Title              string       `yaml:"title,omitempty"`
	DefaultLimit       int          `yaml:"default_limit,omitempty"`
}

type AuthConfig struct {
	Path     string         `yaml:"path,omitempty"`
	Settings map[string]any `yaml:"settings,omitempty"`
}

// ExternalPlugin is a path plus settings for middleware and content plugins.
type ExternalPlugin struct {
	Plugin   string         `yaml:"plugin,omitempty"`
	Path     string         `yaml:"path,omitempty"`
	Settings map[string]any `yaml:"settings,omitempty"`
}

// StoragePluginConfig names a storage driver separately from the instance key.
// An empty Plugin means the map key is the driver, so "local:" still loads local.
type StoragePluginConfig struct {
	Plugin     string         `yaml:"plugin,omitempty"`
	Path       string         `yaml:"path,omitempty"`
	Settings   map[string]any `yaml:"settings,omitempty"`
	Auth       []string       `yaml:"auth,omitempty"`
	AuthScopes []string       `yaml:"auth_scopes,omitempty"`
}

// MiddlewareConfig is an external plugin reference in middleware_plugins.
type MiddlewareConfig = ExternalPlugin

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

// InternalRPCConfig is a separate net/rpc listener. A zero value does not listen.
// FD is an inherited listening socket. It cannot be combined with Address.
type InternalRPCConfig struct {
	Network string `yaml:"network,omitempty"`
	Address string `yaml:"address,omitempty"`
	FD      int    `yaml:"fd,omitempty"`
}

type OtelConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Endpoint    string `yaml:"endpoint"`
	Protocol    string `yaml:"protocol"` // "otlp", "otlphttp"
	ServiceName string `yaml:"service_name"`
}

// ApplicationAPI is one mounted API under /restapi/{name}/.
// Source, public, and storage come from ApplicationConfig.
type ApplicationAPI struct {
	Middlewares     []string                `yaml:"middlewares,omitempty"`
	ContentHandlers []string                `yaml:"content_handlers,omitempty"`
	Parsers         *[]string               `yaml:"parsers,omitempty"`
	Renderers       *[]string               `yaml:"renderers,omitempty"`
	Endpoints       map[string]RestEndpoint `yaml:"endpoints,omitempty"`
	Auth            *[]string               `yaml:"auth,omitempty"`
	AnonClaims      map[string]any          `yaml:"anon_claims,omitempty"`
}

// ApplicationConfig selects the page template and schema for GET /.
// Page is the parsed template. It is nil when both template fields are empty,
// and the server then uses the embedded page.
type ApplicationConfig struct {
	Template     string                    `yaml:"template,omitempty"`
	TemplatePath string                    `yaml:"template_path,omitempty"`
	Version      string                    `yaml:"version,omitempty"`
	Auth         string                    `yaml:"auth,omitempty"`
	Source       string                    `yaml:"source,omitempty"`
	Public       bool                      `yaml:"public,omitempty"`
	Storage      string                    `yaml:"storage,omitempty"`
	Parsers      *[]string                 `yaml:"parsers,omitempty"`
	Renderers    *[]string                 `yaml:"renderers,omitempty"`
	API          map[string]ApplicationAPI `yaml:"api,omitempty"`
	Page         *template.Template        `yaml:"-"`
}

type Config struct {
	Port            string `yaml:"port"`
	CheckScope      bool   `yaml:"check_scope"`
	TokenUserSearch string `yaml:"token_user_search"`
	PluginLog       bool   `yaml:"plugin_log"`
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
	Plugins                  []string                       `yaml:"plugin_configs"`
	PluginMap                map[string]PluginConfig        `yaml:"plugins"`
	AuthPlugins              map[string]AuthConfig          `yaml:"auth_plugins"`
	MiddlewarePlugins        map[string]MiddlewareConfig    `yaml:"middleware_plugins"`
	ContentPlugins           map[string]ExternalPlugin      `yaml:"content_plugins,omitempty"`
	StoragePlugins           map[string]StoragePluginConfig `yaml:"storage_plugins,omitempty"`
	DefaultContentHandlers   []string                       `yaml:"default_content_handlers,omitempty"`
	DefaultStoragePlugin     string                         `yaml:"default_storage_plugin,omitempty"`
	GlobalRequestMiddlewares []string                       `yaml:"global_request_middlewares"`
	AnonClaims               map[string]any                 `yaml:"anon_claims,omitempty"`
	Server                   ServerConfig                   `yaml:"server"`
	// RestAPI is filled by Load from application.api. The restapi YAML key is ignored.
	RestAPI     map[string]RestAPIApp `yaml:"-"`
	Application ApplicationConfig     `yaml:"application,omitempty"`
	InternalRPC InternalRPCConfig     `yaml:"internal_rpc,omitempty"`
}

// RestAPIApp is one mounted API under /restapi/{name}/.
type RestAPIApp struct {
	Source          string                  `yaml:"source,omitempty"`
	Public          bool                    `yaml:"public,omitempty"`
	Middlewares     []string                `yaml:"middlewares,omitempty"`
	ContentHandlers []string                `yaml:"content_handlers,omitempty"`
	Parsers         *[]string               `yaml:"-"`
	Renderers       *[]string               `yaml:"-"`
	Storage         string                  `yaml:"storage,omitempty"`
	Endpoints       map[string]RestEndpoint `yaml:"endpoints,omitempty"`
	Auth            *[]string               `yaml:"-"`
	AnonClaims      map[string]any          `yaml:"-"`
}

// RestEndpoint is one resource inside a RestAPIApp.
type RestEndpoint struct {
	Source          string                     `yaml:"source,omitempty"`
	Name            string                     `yaml:"name,omitempty"`
	URL             string                     `yaml:"url,omitempty"`
	Description     string                     `yaml:"description,omitempty"`
	Table           string                     `yaml:"table,omitempty"`
	PrimaryKey      string                     `yaml:"primary_key,omitempty"`
	Public          bool                       `yaml:"public,omitempty"`
	NoTrailingSlash bool                       `yaml:"no_trailing_slash,omitempty"`
	Filters         map[string]RestFilter      `yaml:"filters,omitempty"`
	Actions         map[string]RestAction      `yaml:"actions,omitempty"`
	DetailActions   map[string]RestCallAction  `yaml:"detail_actions,omitempty"`
	ListActions     map[string]RestCallAction  `yaml:"list_actions,omitempty"`
	StateActions    map[string]RestStateAction `yaml:"state_actions,omitempty"`
	Views           map[string]RestView        `yaml:"views,omitempty"`
	ContentHandlers []string                   `yaml:"content_handlers,omitempty"`
	Parsers         *[]string                  `yaml:"parsers,omitempty"`
	Renderers       *[]string                  `yaml:"renderers,omitempty"`
	Storage         string                     `yaml:"storage,omitempty"`
	Auth            *[]string                  `yaml:"auth,omitempty"`
	RequiredScopes  []string                   `yaml:"required_scopes,omitempty"`
}

// RestCallAction is a POST function on a detail or list path.
// URL, when set, is the path segment in place of the map key.
type RestCallAction struct {
	Func            string         `yaml:"func,omitempty"`
	Fields          map[string]any `yaml:"fields,omitempty"`
	Storage         string         `yaml:"storage,omitempty"`
	NoTrailingSlash bool           `yaml:"no_trailing_slash,omitempty"`
	URL             string         `yaml:"url,omitempty"`
	Parsers         *[]string      `yaml:"parsers,omitempty"`
	Renderers       *[]string      `yaml:"renderers,omitempty"`
	Auth            *[]string      `yaml:"auth,omitempty"`
	RequiredScopes  []string       `yaml:"required_scopes,omitempty"`
	// Handler is a registered Go function name. It is used by the embed server.
	Handler string `yaml:"handler,omitempty"`
}

// RestStateAction is a GET and PUT of one table column, or of one database function.
// Post is valid with Func or Handler, and then the write method is POST.
// URL, when set, is the path segment in place of the map key.
type RestStateAction struct {
	Table           string         `yaml:"table,omitempty"`
	SourceField     string         `yaml:"source_field,omitempty"`
	Func            string         `yaml:"func,omitempty"`
	Fields          map[string]any `yaml:"fields,omitempty"`
	Storage         string         `yaml:"storage,omitempty"`
	NoTrailingSlash bool           `yaml:"no_trailing_slash,omitempty"`
	URL             string         `yaml:"url,omitempty"`
	Post            bool           `yaml:"post,omitempty"`
	Parsers         *[]string      `yaml:"parsers,omitempty"`
	Renderers       *[]string      `yaml:"renderers,omitempty"`
	Auth            *[]string      `yaml:"auth,omitempty"`
	RequiredScopes  []string       `yaml:"required_scopes,omitempty"`
	// Handler is a registered Go function name. It is used by the embed server.
	Handler string `yaml:"handler,omitempty"`
}

// RestFilter is a list query filter. Claim, when set, is read from the JWT
// and always applied. A query value cannot override it.
type RestFilter struct {
	Field string `yaml:"field,omitempty"`
	Op    string `yaml:"op,omitempty"`
	Not   bool   `yaml:"not,omitempty"`
	Claim string `yaml:"claim,omitempty"`
}

// RestAction configures one ModelViewSet-style operation.
type RestAction struct {
	Type            string         `yaml:"type,omitempty"`
	Table           string         `yaml:"table,omitempty"`
	Fields          []string       `yaml:"fields,omitempty"`
	ExtraFields     map[string]any `yaml:"extra_fields,omitempty"`
	Label           string         `yaml:"label,omitempty"`
	Description     string         `yaml:"description,omitempty"`
	Storage         string         `yaml:"storage,omitempty"`
	NoTrailingSlash bool           `yaml:"no_trailing_slash,omitempty"`
	Parsers         *[]string      `yaml:"parsers,omitempty"`
	Renderers       *[]string      `yaml:"renderers,omitempty"`
	Auth            *[]string      `yaml:"auth,omitempty"`
	RequiredScopes  []string       `yaml:"required_scopes,omitempty"`
	// Handler is a registered Go function name. It is used by the embed server.
	Handler string `yaml:"handler,omitempty"`
}

// RestView is a Go function mounted under one endpoint.
// Path is relative to the endpoint URL. The function writes the response.
type RestView struct {
	Path            string    `yaml:"path,omitempty"`
	Methods         []string  `yaml:"methods,omitempty"`
	Handler         string    `yaml:"handler,omitempty"`
	Description     string    `yaml:"description,omitempty"`
	NoTrailingSlash bool      `yaml:"no_trailing_slash,omitempty"`
	Auth            *[]string `yaml:"auth,omitempty"`
	RequiredScopes  []string  `yaml:"required_scopes,omitempty"`
}

func LoadPluginConfigs(configs []string) map[string]PluginConfig {
	plugins := make(map[string]PluginConfig)
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
			if cfg.DbMaxRows == 0 {
				cfg.DbMaxRows = 10000
			}

			// Add the successfully parsed config to the map.
			plugins[cfg.Name] = cfg
		}
	}
	return plugins
}

func defaultCORS() CORSConfig {
	return CORSConfig{
		Origins: []string{"*"},
		Methods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		Headers: []string{
			"Content-Type", "Authorization", "X-Requested-With",
			"Accept", "Prefer", "If-Match", "If-None-Match", "If-Resource-Version",
			"Range", "Range-Unit",
		},
		MaxAge: 86400,
	}
}

func defaultServerConfig() ServerConfig {
	return ServerConfig{
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		KeepAlivePeriod:   3 * time.Minute,
		MaxHeaderBytes:    1 << 20,
		MaxBodySize:       int64(10 * 1024 * 1024),
		TrustedProxyMode:  "none",
		TrustedProxyCount: 1,
	}
}

func defaultConfig() Config {
	return Config{
		Port:              "8080",
		CheckScope:        true,
		TokenUserSearch:   "sub",
		DefaultTimezone:   defaultTimezone(),
		TokenCacheTTL:     -1,
		CORS:              defaultCORS(),
		Plugins:           []string{},
		PluginMap:         map[string]PluginConfig{},
		AuthPlugins:       map[string]AuthConfig{},
		MiddlewarePlugins: map[string]MiddlewareConfig{},
		StoragePlugins:    map[string]StoragePluginConfig{},
		AnonClaims:        map[string]any{},
		Server:            defaultServerConfig(),
	}
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
		if pluginCfg.DbMaxRows == 0 {
			pluginCfg.DbMaxRows = 10000
		}
		cfg.PluginMap[pluginName] = pluginCfg
	}
	for name, plcfg := range LoadPluginConfigs(cfg.Plugins) {
		if _, exists := cfg.PluginMap[name]; !exists {
			if plcfg.DbMaxRows == 0 {
				plcfg.DbMaxRows = 10000
			}
			cfg.PluginMap[name] = plcfg
		}
	}
}

func materializeApplicationAPI(cfg *Config) {
	if len(cfg.Application.API) == 0 {
		return
	}
	cfg.RestAPI = make(map[string]RestAPIApp, len(cfg.Application.API))
	for name, api := range cfg.Application.API {
		endpoints := api.Endpoints
		if endpoints == nil {
			endpoints = map[string]RestEndpoint{}
		}
		middlewares := api.Middlewares
		if middlewares == nil {
			middlewares = []string{}
		}
		handlers := api.ContentHandlers
		if handlers == nil {
			handlers = []string{}
		}
		cfg.RestAPI[name] = RestAPIApp{
			Source:          cfg.Application.Source,
			Public:          cfg.Application.Public,
			Storage:         cfg.Application.Storage,
			Middlewares:     middlewares,
			ContentHandlers: handlers,
			Parsers:         api.Parsers,
			Renderers:       api.Renderers,
			Endpoints:       endpoints,
			Auth:            api.Auth,
			AnonClaims:      api.AnonClaims,
		}
	}
}

func applyStorageDefaults(cfg *Config) {
	if cfg.DefaultStoragePlugin == "" {
		cfg.DefaultStoragePlugin = "local"
	}
	if cfg.RestAPI == nil {
		return
	}
	for apiName, app := range cfg.RestAPI {
		if app.Storage == "" {
			app.Storage = cfg.DefaultStoragePlugin
		}
		if app.Endpoints == nil {
			cfg.RestAPI[apiName] = app
			continue
		}
		for epName, ep := range app.Endpoints {
			if ep.Storage == "" {
				ep.Storage = app.Storage
			}
			for name, act := range ep.Actions {
				if act.Storage == "" {
					act.Storage = ep.Storage
					ep.Actions[name] = act
				}
			}
			for name, act := range ep.DetailActions {
				if act.Storage == "" {
					act.Storage = ep.Storage
					ep.DetailActions[name] = act
				}
			}
			for name, act := range ep.ListActions {
				if act.Storage == "" {
					act.Storage = ep.Storage
					ep.ListActions[name] = act
				}
			}
			for name, act := range ep.StateActions {
				if act.Storage == "" {
					act.Storage = ep.Storage
					ep.StateActions[name] = act
				}
			}
			app.Endpoints[epName] = ep
		}
		cfg.RestAPI[apiName] = app
	}
}

func defaultTimezone() string {
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

// Load builds configuration from defaults, then each file in order, then overrideYAML.
// A field absent from a later document keeps its previous value. A map key present in a
// later document replaces that map.
func Load(files []string, overrideYAML string) (Config, error) {
	cfg := defaultConfig()
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("read config %s: %w", path, err)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse config %s: %w", path, err)
		}
		log.Printf("Loading config from %s\n", path)
	}
	if strings.TrimSpace(overrideYAML) != "" {
		if err := yaml.Unmarshal([]byte(overrideYAML), &cfg); err != nil {
			return Config{}, fmt.Errorf("parse config override: %w", err)
		}
	}

	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cfg.TLSEnabled = true
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

	if len(cfg.AuthPlugins) == 0 {
		cfg.AuthPlugins = map[string]AuthConfig{
			"jwt": {
				Settings: map[string]any{
					"jwt_secret": "",
					"flow":       "password",
				},
			},
		}
	}
	finalizePluginMap(&cfg)
	materializeApplicationAPI(&cfg)
	applyStorageDefaults(&cfg)
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
	if err := validate(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func validate(cfg *Config) error {
	if err := validateApplication(cfg); err != nil {
		return err
	}
	if err := validateApplicationStorage(cfg); err != nil {
		return err
	}
	if err := validatePlugins(cfg); err != nil {
		return err
	}
	if err := validateTLS(cfg); err != nil {
		return err
	}
	if err := validateReferences(cfg); err != nil {
		return err
	}
	if err := validateRestAPI(cfg); err != nil {
		return err
	}
	if err := validateInternalRPC(cfg); err != nil {
		return err
	}
	return prepareApplicationTemplate(cfg)
}

func validateInternalRPC(cfg *Config) error {
	rpcCfg := cfg.InternalRPC
	if rpcCfg.FD != 0 && rpcCfg.Address != "" {
		return fmt.Errorf("internal_rpc fd and address cannot both be set")
	}
	if rpcCfg.Address == "" {
		return nil
	}
	switch rpcCfg.Network {
	case "tcp", "unix":
		return nil
	default:
		return fmt.Errorf("internal_rpc network %q is not tcp or unix", rpcCfg.Network)
	}
}

func validatePlugins(cfg *Config) error {
	for name, plug := range cfg.PluginMap {
		if !knownTxEnd(plug.DbTxEnd) {
			return fmt.Errorf(
				"plugin %q db_tx_end %q must be commit, rollback, commit-allow-override, or rollback-allow-override",
				name,
				plug.DbTxEnd,
			)
		}
		if !strings.Contains(plug.Uri, "://") {
			return fmt.Errorf("plugin %q uri %q must include a scheme", name, plug.Uri)
		}
	}
	return nil
}

func knownTxEnd(value string) bool {
	switch value {
	case "commit", "rollback", "commit-allow-override", "rollback-allow-override":
		return true
	default:
		return false
	}
}

func validateTLS(cfg *Config) error {
	hasCert := cfg.TLSCertFile != ""
	hasKey := cfg.TLSKeyFile != ""
	if hasCert != hasKey {
		return fmt.Errorf("tls_cert_file and tls_key_file must both be set")
	}
	return nil
}

func validateReferences(cfg *Config) error {
	if err := validateMiddlewareNames(cfg); err != nil {
		return err
	}
	if err := validateContentHandlers(cfg); err != nil {
		return err
	}
	return validateStorageNames(cfg)
}

func validateMiddlewareNames(cfg *Config) error {
	for _, name := range cfg.GlobalRequestMiddlewares {
		if err := requireMiddleware(cfg, name); err != nil {
			return err
		}
	}
	for pluginName, plug := range cfg.PluginMap {
		for _, name := range plug.RequestMiddlewares {
			if err := requireMiddleware(cfg, name); err != nil {
				return fmt.Errorf("plugin %q: %w", pluginName, err)
			}
		}
	}
	for apiName, app := range cfg.RestAPI {
		for _, name := range app.Middlewares {
			if err := requireMiddleware(cfg, name); err != nil {
				return fmt.Errorf("restapi %q: %w", apiName, err)
			}
		}
	}
	return nil
}

func requireMiddleware(cfg *Config, name string) error {
	if _, ok := cfg.MiddlewarePlugins[name]; ok {
		return nil
	}
	return fmt.Errorf("middleware %q is not in middleware_plugins", name)
}

func validateContentHandlers(cfg *Config) error {
	if err := requireContentHandlers(cfg, "default_content_handlers", cfg.DefaultContentHandlers); err != nil {
		return err
	}
	if err := requireContentHandlerPtr(cfg, "application parsers", cfg.Application.Parsers); err != nil {
		return err
	}
	if err := requireContentHandlerPtr(cfg, "application renderers", cfg.Application.Renderers); err != nil {
		return err
	}
	for pluginName, plug := range cfg.PluginMap {
		if err := requireContentHandlers(cfg, "plugin "+pluginName, plug.ContentHandlers); err != nil {
			return err
		}
	}
	for apiName, app := range cfg.RestAPI {
		where := "restapi " + apiName
		if err := requireContentHandlers(cfg, where, app.ContentHandlers); err != nil {
			return err
		}
		if err := requireContentHandlerPtr(cfg, where+" parsers", app.Parsers); err != nil {
			return err
		}
		if err := requireContentHandlerPtr(cfg, where+" renderers", app.Renderers); err != nil {
			return err
		}
		for epName, ep := range app.Endpoints {
			epWhere := where + " " + epName
			if err := requireContentHandlers(cfg, epWhere, ep.ContentHandlers); err != nil {
				return err
			}
			if err := validateEndpointContent(cfg, epWhere, ep); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateEndpointContent(cfg *Config, where string, ep RestEndpoint) error {
	if err := requireContentHandlerPtr(cfg, where+" parsers", ep.Parsers); err != nil {
		return err
	}
	if err := requireContentHandlerPtr(cfg, where+" renderers", ep.Renderers); err != nil {
		return err
	}
	for name, act := range ep.Actions {
		if err := requireContentPair(cfg, where+" "+name, act.Parsers, act.Renderers); err != nil {
			return err
		}
	}
	for name, act := range ep.DetailActions {
		if err := requireContentPair(cfg, where+" "+name, act.Parsers, act.Renderers); err != nil {
			return err
		}
	}
	for name, act := range ep.ListActions {
		if err := requireContentPair(cfg, where+" "+name, act.Parsers, act.Renderers); err != nil {
			return err
		}
	}
	for name, act := range ep.StateActions {
		if err := requireContentPair(cfg, where+" "+name, act.Parsers, act.Renderers); err != nil {
			return err
		}
	}
	return nil
}

func requireContentPair(cfg *Config, where string, parsers, renderers *[]string) error {
	if err := requireContentHandlerPtr(cfg, where+" parsers", parsers); err != nil {
		return err
	}
	return requireContentHandlerPtr(cfg, where+" renderers", renderers)
}

func requireContentHandlerPtr(cfg *Config, where string, names *[]string) error {
	if names == nil {
		return nil
	}
	return requireContentHandlers(cfg, where, *names)
}

func requireContentHandlers(cfg *Config, where string, names []string) error {
	for _, name := range names {
		if contentHandlerKnown(cfg, name) {
			continue
		}
		return fmt.Errorf("%s content handler %q is not a built-in or content plugin", where, name)
	}
	return nil
}

func contentHandlerKnown(cfg *Config, name string) bool {
	switch name {
	case "json", "ndjson", "xml", "csv", "form", "html":
		return true
	default:
		_, ok := cfg.ContentPlugins[name]
		return ok
	}
}

func validateStorageNames(cfg *Config) error {
	if err := requireStorage(cfg, "default_storage_plugin", cfg.DefaultStoragePlugin); err != nil {
		return err
	}
	for apiName, app := range cfg.RestAPI {
		if err := requireStorage(cfg, "restapi "+apiName, app.Storage); err != nil {
			return err
		}
		for epName, ep := range app.Endpoints {
			where := "restapi " + apiName + " " + epName
			if err := requireStorage(cfg, where, ep.Storage); err != nil {
				return err
			}
			for name, act := range ep.Actions {
				if err := requireStorage(cfg, where+" "+name, act.Storage); err != nil {
					return err
				}
			}
			for name, act := range ep.DetailActions {
				if err := requireStorage(cfg, where+" "+name, act.Storage); err != nil {
					return err
				}
			}
			for name, act := range ep.ListActions {
				if err := requireStorage(cfg, where+" "+name, act.Storage); err != nil {
					return err
				}
			}
			for name, act := range ep.StateActions {
				if err := requireStorage(cfg, where+" "+name, act.Storage); err != nil {
					return err
				}
			}
		}
	}
	for name, plug := range cfg.StoragePlugins {
		if err := requireAuthNameSlice(cfg, "storage_plugins "+name, plug.Auth); err != nil {
			return err
		}
	}
	return nil
}

func requireStorage(cfg *Config, where, name string) error {
	if storageKnown(cfg, name) {
		return nil
	}
	return fmt.Errorf("%s storage %q is not a built-in or storage plugin", where, name)
}

func storageKnown(cfg *Config, name string) bool {
	if name == "" {
		return true
	}
	switch name {
	case "local", "memory", "dbglob", "static":
		return true
	default:
		_, ok := cfg.StoragePlugins[name]
		return ok
	}
}

var (
	restNamePattern      = regexp.MustCompile(`^[a-z0-9_]+$`)
	restURLPattern       = regexp.MustCompile(`^[a-z0-9_./{}-]+$`)
	restSegmentPattern   = regexp.MustCompile(`^[a-z0-9_.-]+$`)
	restViewParamPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

// RestNameOK reports whether name is a restapi endpoint or action name.
func RestNameOK(name string) bool {
	return restNamePattern.MatchString(name)
}

// RestActionSegment returns the public path segment for an action.
// An empty url uses key, which must match [a-z0-9_]+.
// A set url is one segment matching [a-z0-9_.-]+, and it is not "." or "..".
func RestActionSegment(key, url string) (string, error) {
	if url == "" {
		if !RestNameOK(key) {
			return "", fmt.Errorf("action name %q must match [a-z0-9_]+", key)
		}
		return key, nil
	}
	if !restSegmentPattern.MatchString(url) || url == "." || url == ".." {
		return "", fmt.Errorf("action url %q is invalid", url)
	}
	return url, nil
}

// RestURLOK reports whether urlPath can be mounted under a restapi app.
func RestURLOK(urlPath string) bool {
	return restURLPattern.MatchString(urlPath) && !strings.Contains(urlPath, "{id}")
}

func validateRestAPI(cfg *Config) error {
	for apiName, app := range cfg.RestAPI {
		for key, ep := range app.Endpoints {
			if err := validateRestEndpoint(cfg, apiName, key, app, ep); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateRestEndpoint(cfg *Config, apiName, key string, app RestAPIApp, ep RestEndpoint) error {
	name := ep.Name
	if name == "" {
		name = key
	}
	if !RestNameOK(name) {
		return fmt.Errorf("restapi %s %s name %q must match [a-z0-9_]+", apiName, key, name)
	}
	urlPath := ep.URL
	if urlPath == "" {
		urlPath = name
	}
	if !RestURLOK(urlPath) {
		return fmt.Errorf("restapi %s %s url %q is invalid", apiName, key, urlPath)
	}
	source := ep.Source
	if source == "" {
		source = app.Source
	}
	if source == "" {
		return fmt.Errorf("restapi %s %s source is empty", apiName, key)
	}
	if _, ok := cfg.PluginMap[source]; !ok {
		return fmt.Errorf("restapi %s %s source %q is not a plugin", apiName, key, source)
	}
	pk := ep.PrimaryKey
	if pk == "" {
		pk = "id"
	}
	where := "restapi " + apiName + " " + name
	seen := map[restActionRoute]string{}
	if err := claimRestCRUD(where, seen, ep); err != nil {
		return err
	}
	for actionName, call := range ep.DetailActions {
		if err := validateRestCall(where, actionName, pk, call); err != nil {
			return err
		}
		segment, err := RestActionSegment(actionName, call.URL)
		if err != nil {
			return fmt.Errorf("%s action %s: %w", where, actionName, err)
		}
		if err := claimRestRoute(where, seen, actionName, restActionRoute{
			method:  "POST",
			suffix:  "{id}/" + segment,
			noSlash: ep.NoTrailingSlash || call.NoTrailingSlash,
		}); err != nil {
			return err
		}
	}
	for actionName, call := range ep.ListActions {
		if err := validateRestCall(where, actionName, pk, call); err != nil {
			return err
		}
		segment, err := RestActionSegment(actionName, call.URL)
		if err != nil {
			return fmt.Errorf("%s action %s: %w", where, actionName, err)
		}
		if err := claimRestRoute(where, seen, actionName, restActionRoute{
			method:  "POST",
			suffix:  segment,
			noSlash: ep.NoTrailingSlash || call.NoTrailingSlash,
		}); err != nil {
			return err
		}
	}
	for actionName, state := range ep.StateActions {
		modes := 0
		if state.Func != "" {
			modes++
		}
		if state.SourceField != "" {
			modes++
		}
		if state.Handler != "" {
			modes++
		}
		if !RestNameOK(actionName) || modes == 0 {
			return fmt.Errorf("%s state action %s needs func, source_field, or handler, and a name matching [a-z0-9_]+", where, actionName)
		}
		if modes > 1 {
			return fmt.Errorf("%s state action %s cannot set both func, source_field, and handler", where, actionName)
		}
		if state.Post && state.Func == "" && state.Handler == "" {
			return fmt.Errorf("%s state action %s post is only valid with func", where, actionName)
		}
		segment, err := RestActionSegment(actionName, state.URL)
		if err != nil {
			return fmt.Errorf("%s state action %s: %w", where, actionName, err)
		}
		writeMethod := "PUT"
		if state.Post {
			writeMethod = "POST"
		}
		suffix := segment
		if state.Func == "" && state.Handler == "" {
			suffix = "{id}/" + segment
		}
		for _, method := range []string{"GET", writeMethod} {
			if err := claimRestRoute(where, seen, actionName, restActionRoute{
				method:  method,
				suffix:  suffix,
				noSlash: ep.NoTrailingSlash || state.NoTrailingSlash,
			}); err != nil {
				return err
			}
		}
	}
	for viewName, view := range ep.Views {
		if err := validateRestView(where, viewName, urlPath, ep, view, seen); err != nil {
			return err
		}
	}
	return nil
}

type restActionRoute struct {
	method  string
	suffix  string
	noSlash bool
}

func claimRestCRUD(where string, seen map[restActionRoute]string, ep RestEndpoint) error {
	routes := []struct {
		name, method, suffix string
	}{
		{"list", "GET", ""},
		{"create", "POST", ""},
		{"retrieve", "GET", "{id}"},
		{"update", "PATCH", "{id}"},
		{"destroy", "DELETE", "{id}"},
	}
	for _, route := range routes {
		if !restCRUDEnabled(ep, route.name) {
			continue
		}
		if err := claimRestRoute(where, seen, route.name, restActionRoute{
			method:  route.method,
			suffix:  route.suffix,
			noSlash: restEndpointActionNoSlash(ep, route.name),
		}); err != nil {
			return err
		}
	}
	return nil
}

func restCRUDEnabled(ep RestEndpoint, name string) bool {
	if len(ep.Actions) == 0 {
		return true
	}
	_, ok := ep.Actions[name]
	return ok
}

func restEndpointActionNoSlash(ep RestEndpoint, action string) bool {
	if ep.NoTrailingSlash {
		return true
	}
	act, ok := ep.Actions[action]
	if !ok {
		return false
	}
	return act.NoTrailingSlash
}

func validateRestView(where, viewName, urlPath string, ep RestEndpoint, view RestView, seen map[restActionRoute]string) error {
	if !RestNameOK(viewName) {
		return fmt.Errorf("%s view %s name is invalid", where, viewName)
	}
	if view.Handler == "" {
		return fmt.Errorf("%s view %s handler is empty", where, viewName)
	}
	params, err := RestViewPath(view.Path)
	if err != nil {
		return fmt.Errorf("%s view %s: %w", where, viewName, err)
	}
	taken := map[string]struct{}{}
	for _, name := range restBraceParams(urlPath) {
		taken[name] = struct{}{}
	}
	for _, name := range params {
		if _, ok := taken[name]; ok {
			return fmt.Errorf("%s view %s path repeats {%s}", where, viewName, name)
		}
	}
	methods, err := RestViewMethods(view.Methods)
	if err != nil {
		return fmt.Errorf("%s view %s: %w", where, viewName, err)
	}
	noSlash := ep.NoTrailingSlash || view.NoTrailingSlash
	for _, method := range RestViewRouteMethods(methods) {
		if err := claimRestRoute(where, seen, viewName, restActionRoute{
			method:  method,
			suffix:  view.Path,
			noSlash: noSlash,
		}); err != nil {
			return err
		}
	}
	return nil
}

// RestViewPath checks a view path and returns its parameter names.
// An empty path mounts on the endpoint URL. A segment is a literal
// matching [a-z0-9_.-]+, or {name} with name matching [a-z][a-z0-9_]*.
func RestViewPath(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	if strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
		return nil, fmt.Errorf("view path %q is invalid", path)
	}
	seen := map[string]struct{}{}
	var params []string
	for _, seg := range strings.Split(path, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return nil, fmt.Errorf("view path %q is invalid", path)
		}
		if strings.HasPrefix(seg, "{") || strings.HasSuffix(seg, "}") {
			if len(seg) < 3 || !strings.HasPrefix(seg, "{") || !strings.HasSuffix(seg, "}") {
				return nil, fmt.Errorf("view path %q is invalid", path)
			}
			name := seg[1 : len(seg)-1]
			if !restViewParamPattern.MatchString(name) {
				return nil, fmt.Errorf("view path %q is invalid", path)
			}
			if _, ok := seen[name]; ok {
				return nil, fmt.Errorf("view path %q repeats {%s}", path, name)
			}
			seen[name] = struct{}{}
			params = append(params, name)
			continue
		}
		if !restSegmentPattern.MatchString(seg) {
			return nil, fmt.Errorf("view path %q is invalid", path)
		}
	}
	return params, nil
}

// RestViewMethods returns methods in uppercase.
// Allowed methods are GET, HEAD, POST, PUT, PATCH, DELETE, and QUERY.
func RestViewMethods(methods []string) ([]string, error) {
	if len(methods) == 0 {
		return nil, fmt.Errorf("methods are empty")
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(methods))
	for _, method := range methods {
		method = strings.ToUpper(method)
		switch method {
		case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "QUERY":
		default:
			return nil, fmt.Errorf("method %q is invalid", method)
		}
		if _, ok := seen[method]; ok {
			return nil, fmt.Errorf("method %s is repeated", method)
		}
		seen[method] = struct{}{}
		out = append(out, method)
	}
	return out, nil
}

// RestViewRouteMethods is the set of routes a view registers.
// A GET view also registers HEAD when HEAD is not listed. The HEAD request
// calls the same function, and Request.Method stays HEAD.
func RestViewRouteMethods(methods []string) []string {
	for _, method := range methods {
		if method == "HEAD" {
			return methods
		}
	}
	for _, method := range methods {
		if method == "GET" {
			out := make([]string, len(methods)+1)
			copy(out, methods)
			out[len(methods)] = "HEAD"
			return out
		}
	}
	return methods
}

func restBraceParams(path string) []string {
	var names []string
	for _, seg := range strings.Split(path, "/") {
		if len(seg) < 3 || !strings.HasPrefix(seg, "{") || !strings.HasSuffix(seg, "}") {
			continue
		}
		names = append(names, seg[1:len(seg)-1])
	}
	return names
}

func claimRestRoute(where string, seen map[restActionRoute]string, action string, route restActionRoute) error {
	if prev, ok := seen[route]; ok {
		return fmt.Errorf("%s action %s overlaps %s", where, action, prev)
	}
	seen[route] = action
	return nil
}

func validateRestCall(where, actionName, pk string, call RestCallAction) error {
	if call.Func != "" && call.Handler != "" {
		return fmt.Errorf("%s action %s cannot set both func and handler", where, actionName)
	}
	if call.Func == "" && call.Handler == "" {
		return fmt.Errorf("%s action %s func is empty", where, actionName)
	}
	if !RestNameOK(actionName) {
		return fmt.Errorf("%s action %s name is invalid", where, actionName)
	}
	if _, ok := call.Fields[pk]; ok {
		return fmt.Errorf("%s action %s fields contain primary key %q", where, actionName, pk)
	}
	if _, err := RestActionSegment(actionName, call.URL); err != nil {
		return fmt.Errorf("%s action %s: %w", where, actionName, err)
	}
	return nil
}

func prepareApplicationTemplate(cfg *Config) error {
	src := cfg.Application.Template
	if src == "" && cfg.Application.TemplatePath != "" {
		data, err := os.ReadFile(cfg.Application.TemplatePath)
		if err != nil {
			return fmt.Errorf("application.template_path %q: %w", cfg.Application.TemplatePath, err)
		}
		src = string(data)
	}
	if src == "" {
		return nil
	}
	page, err := template.New("page").Parse(src)
	if err != nil {
		return fmt.Errorf("application template: %w", err)
	}
	cfg.Application.Page = page
	return nil
}

func validateApplication(cfg *Config) error {
	if cfg.Application.Version != "" {
		if _, ok := cfg.Application.API[cfg.Application.Version]; !ok {
			return fmt.Errorf("application.version %q is not an application.api key", cfg.Application.Version)
		}
	}
	if cfg.Application.Auth != "" {
		if _, ok := cfg.AuthPlugins[cfg.Application.Auth]; !ok {
			return fmt.Errorf("application.auth %q is not an auth plugin", cfg.Application.Auth)
		}
	}
	return validateAPIAuth(cfg)
}

func validateAPIAuth(cfg *Config) error {
	for name, app := range cfg.RestAPI {
		if err := requireAuthNames(cfg, "restapi "+name, app.Auth); err != nil {
			return err
		}
		for epName, ep := range app.Endpoints {
			where := "restapi " + name + " endpoint " + epName
			if err := requireAuthNames(cfg, where, ep.Auth); err != nil {
				return err
			}
			for actionName, act := range ep.Actions {
				if err := requireAuthNames(cfg, where+" action "+actionName, act.Auth); err != nil {
					return err
				}
			}
			for actionName, act := range ep.DetailActions {
				if err := requireAuthNames(cfg, where+" detail action "+actionName, act.Auth); err != nil {
					return err
				}
			}
			for actionName, act := range ep.ListActions {
				if err := requireAuthNames(cfg, where+" list action "+actionName, act.Auth); err != nil {
					return err
				}
			}
			for actionName, act := range ep.StateActions {
				if err := requireAuthNames(cfg, where+" state action "+actionName, act.Auth); err != nil {
					return err
				}
			}
			for viewName, view := range ep.Views {
				if err := requireAuthNames(cfg, where+" view "+viewName, view.Auth); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func requireAuthNames(cfg *Config, where string, names *[]string) error {
	if names == nil {
		return nil
	}
	return requireAuthNameSlice(cfg, where, *names)
}

func requireAuthNameSlice(cfg *Config, where string, names []string) error {
	for _, name := range names {
		if _, ok := cfg.AuthPlugins[name]; ok {
			continue
		}
		return fmt.Errorf("%s auth %q is not an auth plugin", where, name)
	}
	return nil
}

// validateApplicationStorage rejects an app storage driver that cannot store uploads.
// static is the first-party driver whose Put always returns a read-only error.
// local, memory, s3, and dbglob accept Put. A custom driver is not rejected here.
func validateApplicationStorage(cfg *Config) error {
	name := resolvedApplicationStorage(cfg)
	if name == "" || storageAcceptsUpload(cfg, name) {
		return nil
	}
	return fmt.Errorf("application.storage %q does not accept uploads", name)
}

func resolvedApplicationStorage(cfg *Config) string {
	if cfg.Application.Storage != "" {
		return cfg.Application.Storage
	}
	if len(cfg.Application.API) == 0 {
		return ""
	}
	return cfg.DefaultStoragePlugin
}

func storageAcceptsUpload(cfg *Config, name string) bool {
	driver := name
	if plug, ok := cfg.StoragePlugins[name]; ok && plug.Plugin != "" {
		driver = plug.Plugin
	}
	return driver != "static"
}
