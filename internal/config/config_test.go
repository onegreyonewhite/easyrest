package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustLoad(t *testing.T, files []string, override string) Config {
	t.Helper()
	cfg, err := Load(files, override)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func writeConfig(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadPluginConfigs_FromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plugins.yaml")
	content := `
name: alpha
uri: sqlite:///a.db
---
name: beta
uri: sqlite:///b.db
db_tx_end: rollback
---
uri: sqlite:///noname.db
---
name: gamma
uri: sqlite:///c.db
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	plugins := LoadPluginConfigs([]string{
		filepath.Join(dir, "missing.yaml"),
		path,
	})

	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(":::not yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	plugins = LoadPluginConfigs([]string{path, filepath.Join(dir, "bad.yaml")})

	if _, ok := plugins[""]; ok {
		t.Error("empty name should be skipped")
	}
	alpha := plugins["alpha"]
	if alpha.DbTxEnd != "commit" {
		t.Errorf("alpha default DbTxEnd: %q", alpha.DbTxEnd)
	}
	if plugins["beta"].DbTxEnd != "rollback" {
		t.Errorf("beta DbTxEnd: %q", plugins["beta"].DbTxEnd)
	}
	if _, ok := plugins["gamma"]; !ok {
		t.Error("expected gamma")
	}
}

func TestLoad_Defaults(t *testing.T) {
	cfg := mustLoad(t, nil, "")
	if cfg.Port != "8080" {
		t.Errorf("Port: %s", cfg.Port)
	}
	if !cfg.CheckScope {
		t.Error("CheckScope")
	}
	if cfg.TokenUserSearch != "sub" {
		t.Errorf("TokenUserSearch: %s", cfg.TokenUserSearch)
	}
	if cfg.PluginLog {
		t.Error("PluginLog should default off")
	}
	if cfg.AccessLogOn {
		t.Error("AccessLogOn")
	}
	if cfg.DefaultTimezone == "" {
		t.Error("timezone")
	}
	if cfg.CORS.Enabled || cfg.CORS.MaxAge != 86400 {
		t.Errorf("CORS: %#v", cfg.CORS)
	}
	if cfg.Server.ReadTimeout != 5*time.Second {
		t.Errorf("ReadTimeout: %v", cfg.Server.ReadTimeout)
	}
	if cfg.Server.MaxBodySize != 10*1024*1024 {
		t.Errorf("MaxBodySize: %d", cfg.Server.MaxBodySize)
	}
	if cfg.Server.TrustedProxyCount != 1 || cfg.Server.TrustedProxyMode != "none" {
		t.Errorf("proxy: %#v", cfg.Server)
	}
	if cfg.Server.DisableHTMLEscape {
		t.Error("DisableHTMLEscape should default to false")
	}
	if cfg.TokenCacheTTL != -1 {
		t.Errorf("TokenCacheTTL: %d", cfg.TokenCacheTTL)
	}
	if cfg.DefaultLimit != 100 {
		t.Errorf("DefaultLimit: %d", cfg.DefaultLimit)
	}
	if cfg.Otel.Protocol != "otlp" || cfg.Otel.ServiceName != "easyrest-server" || cfg.Otel.Enabled {
		t.Errorf("Otel defaults: %#v", cfg.Otel)
	}
	jwtAuth, ok := cfg.AuthPlugins["jwt"]
	if !ok {
		t.Fatal("expected default jwt auth")
	}
	if jwtAuth.Settings["jwt_secret"] != "" {
		t.Errorf("jwt secret: %v", jwtAuth.Settings["jwt_secret"])
	}
	if jwtAuth.Settings["flow"] != "password" {
		t.Errorf("flow: %v", jwtAuth.Settings["flow"])
	}
}

func TestLoad_FileThenOverride(t *testing.T) {
	first := writeConfig(t, "a.yaml", `
port: "9090"
check_scope: false
plugin_log: true
access_log: true
token_user_search: email
default_timezone: UTC
token_cache_ttl: 60
plugins:
  demo:
    uri: sqlite:///demo.db
auth_plugins:
  jwt:
    settings:
      jwt_secret: secret
      flow: client_credentials
cors:
  enabled: true
  origins: ["https://a.com", "https://b.com"]
  methods: ["GET", "POST"]
  headers: ["Authorization"]
  max_age: 3600
tls_cert_file: /tmp/cert.pem
tls_key_file: /tmp/key.pem
anon_claims:
  role: anon
server:
  read_timeout: 2s
  write_timeout: 3s
  idle_timeout: 4s
  read_header_timeout: 1s
  keep_alive_period: 30s
  max_header_bytes: 2000000
  max_body_size: 1000000
  http2_max_concurrent_streams: 100
  http2_max_read_frame_size: 16384
  http2_max_upload_buffer_per_connection: 65536
  http2_max_upload_buffer_per_stream: 32768
  http2_read_idle_timeout: 5s
  http2_ping_timeout: 2s
  http2_permit_prohibited_cipher_suites: true
  trusted_proxy_mode: header
  trusted_proxy_count: 2
  trusted_proxy_header: X-Real-IP
`)
	second := writeConfig(t, "b.yaml", "port: \"7070\"\n")

	cfg := mustLoad(t, []string{first, second}, "port: \"8081\"\n")
	if cfg.Port != "8081" {
		t.Errorf("Port: %s", cfg.Port)
	}
	if cfg.CheckScope {
		t.Error("CheckScope should be false")
	}
	if !cfg.PluginLog {
		t.Error("PluginLog")
	}
	if !cfg.AccessLogOn {
		t.Error("AccessLogOn")
	}
	if cfg.TokenUserSearch != "email" {
		t.Errorf("TokenUserSearch: %s", cfg.TokenUserSearch)
	}
	if cfg.DefaultTimezone != "UTC" {
		t.Errorf("timezone: %s", cfg.DefaultTimezone)
	}
	if !cfg.CORS.Enabled || cfg.CORS.MaxAge != 3600 || len(cfg.CORS.Origins) != 2 {
		t.Errorf("CORS: %#v", cfg.CORS)
	}
	if !cfg.TLSEnabled {
		t.Error("TLSEnabled")
	}
	if cfg.Server.ReadTimeout != 2*time.Second {
		t.Errorf("ReadTimeout: %v", cfg.Server.ReadTimeout)
	}
	if cfg.Server.MaxBodySize != 1000000 {
		t.Errorf("MaxBodySize: %d", cfg.Server.MaxBodySize)
	}
	if cfg.Server.HTTP2MaxConcurrentStreams != 100 {
		t.Errorf("HTTP2 streams: %d", cfg.Server.HTTP2MaxConcurrentStreams)
	}
	if cfg.Server.HTTP2MaxReadFrameSize != 16384 {
		t.Errorf("HTTP2MaxReadFrameSize: %d", cfg.Server.HTTP2MaxReadFrameSize)
	}
	if cfg.Server.HTTP2MaxUploadBufferPerConnection != 65536 {
		t.Errorf("HTTP2MaxUploadBufferPerConnection: %d", cfg.Server.HTTP2MaxUploadBufferPerConnection)
	}
	if cfg.Server.HTTP2MaxUploadBufferPerStream != 32768 {
		t.Errorf("HTTP2MaxUploadBufferPerStream: %d", cfg.Server.HTTP2MaxUploadBufferPerStream)
	}
	if cfg.Server.HTTP2ReadIdleTimeout != 5*time.Second {
		t.Errorf("HTTP2ReadIdleTimeout: %v", cfg.Server.HTTP2ReadIdleTimeout)
	}
	if cfg.Server.HTTP2PingTimeout != 2*time.Second {
		t.Errorf("HTTP2PingTimeout: %v", cfg.Server.HTTP2PingTimeout)
	}
	if !cfg.Server.HTTP2PermitProhibitedCipherSuites {
		t.Error("HTTP2PermitProhibitedCipherSuites")
	}
	if cfg.Server.TrustedProxyMode != "header" || cfg.Server.TrustedProxyHeader != "X-Real-IP" {
		t.Errorf("proxy: %#v", cfg.Server)
	}
	if cfg.Server.TrustedProxyCount != 2 {
		t.Errorf("TrustedProxyCount: %d", cfg.Server.TrustedProxyCount)
	}
	if cfg.TokenCacheTTL != 60 {
		t.Errorf("TokenCacheTTL: %d", cfg.TokenCacheTTL)
	}
	if cfg.AnonClaims["role"] != "anon" {
		t.Errorf("AnonClaims: %#v", cfg.AnonClaims)
	}
	jwtAuth := cfg.AuthPlugins["jwt"]
	if jwtAuth.Settings["jwt_secret"] != "secret" {
		t.Errorf("jwt secret: %v", jwtAuth.Settings["jwt_secret"])
	}
	if jwtAuth.Settings["flow"] != "client_credentials" {
		t.Errorf("flow: %v", jwtAuth.Settings["flow"])
	}
	if _, ok := cfg.PluginMap["demo"]; !ok {
		t.Errorf("PluginMap missing demo: %#v", cfg.PluginMap)
	}
}

func TestLoad_LegacyHTTP2IdleTimeoutIgnored(t *testing.T) {
	path := writeConfig(t, "legacy.yaml", `
server:
  idle_timeout: 4s
  http2_idle_timeout: 10s
  http2_max_concurrent_streams: 50
`)
	cfg := mustLoad(t, []string{path}, "")
	if cfg.Server.IdleTimeout != 4*time.Second {
		t.Errorf("IdleTimeout: %v", cfg.Server.IdleTimeout)
	}
	if cfg.Server.HTTP2MaxConcurrentStreams != 50 {
		t.Errorf("HTTP2MaxConcurrentStreams: %d", cfg.Server.HTTP2MaxConcurrentStreams)
	}
}

func TestLoad_SecondFileKeepsPlugins(t *testing.T) {
	first := writeConfig(t, "a.yaml", `
port: "1000"
plugins:
  keep:
    uri: sqlite:///keep.db
`)
	second := writeConfig(t, "b.yaml", "port: \"2000\"\n")
	cfg := mustLoad(t, []string{first, second}, "")
	if cfg.Port != "2000" {
		t.Errorf("Port: %s", cfg.Port)
	}
	if cfg.PluginMap["keep"].Uri != "sqlite:///keep.db" {
		t.Errorf("plugins wiped: %#v", cfg.PluginMap)
	}
}

func TestLoad_BadFile(t *testing.T) {
	_, err := Load([]string{"/tmp/easyrest-missing-config-file.yaml"}, "")
	if err == nil {
		t.Fatal("missing file should error")
	}
	bad := writeConfig(t, "bad.yaml", ":\n  - [")
	_, err = Load([]string{bad}, "")
	if err == nil {
		t.Fatal("invalid yaml should error")
	}
	_, err = Load(nil, ":\n  - [")
	if err == nil || !strings.Contains(err.Error(), "override") {
		t.Fatalf("override error: %v", err)
	}
}

func TestLoad_CheckScopeFalse(t *testing.T) {
	path := writeConfig(t, "cfg.yaml", "check_scope: false\n")
	cfg := mustLoad(t, []string{path}, "")
	if cfg.CheckScope {
		t.Error("CheckScope should be false")
	}
}

func TestLoad_MiddlewareConfigFromYAML(t *testing.T) {
	path := writeConfig(t, "cfg.yaml", `
global_request_middlewares:
  - rate_limit
middleware_plugins:
  rate_limit:
    settings:
      max_rps: 100
  audit:
    path: ~/bin/easyrest-middleware-audit
plugins:
  test:
    uri: sqlite:///test.db
    request_middlewares:
      - audit
`)
	cfg := mustLoad(t, []string{path}, "")
	if len(cfg.GlobalRequestMiddlewares) != 1 {
		t.Fatalf("GlobalRequestMiddlewares: %#v", cfg.GlobalRequestMiddlewares)
	}
	if cfg.GlobalRequestMiddlewares[0] != "rate_limit" {
		t.Errorf("expected rate_limit first, got %q", cfg.GlobalRequestMiddlewares[0])
	}
	rateLimit, ok := cfg.MiddlewarePlugins["rate_limit"]
	if !ok {
		t.Fatal("expected rate_limit middleware plugin")
	}
	if fmt.Sprint(rateLimit.Settings["max_rps"]) != "100" {
		t.Errorf("rate_limit settings: %#v", rateLimit.Settings)
	}
	audit, ok := cfg.MiddlewarePlugins["audit"]
	if !ok || audit.Path != "~/bin/easyrest-middleware-audit" {
		t.Errorf("audit middleware: %#v", audit)
	}
	testPlugin, ok := cfg.PluginMap["test"]
	if !ok {
		t.Fatal("expected test plugin")
	}
	if len(testPlugin.RequestMiddlewares) != 1 || testPlugin.RequestMiddlewares[0] != "audit" {
		t.Fatalf("RequestMiddlewares: %#v", testPlugin.RequestMiddlewares)
	}
}

func TestLoad_UnknownReferences(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "missing middleware",
			yaml: `
middleware_plugins:
  rate_limit: {}
global_request_middlewares:
  - missing_mw
`,
			wantErr: "middleware",
		},
		{
			name: "missing api middleware",
			yaml: `
plugins:
  app:
    uri: sqlite://memory
middleware_plugins:
  audit: {}
application:
  source: app
  api:
    v1:
      middlewares:
        - missing_mw
`,
			wantErr: "middleware",
		},
		{
			name: "missing content handler",
			yaml: `
plugins:
  app:
    uri: sqlite://memory
    content_handlers:
      - bogus
`,
			wantErr: "content handler",
		},
		{
			name: "html content handler is built in",
			yaml: `
plugins:
  app:
    uri: sqlite://memory
    content_handlers:
      - html
`,
		},
		{
			name:    "unknown default storage",
			yaml:    "default_storage_plugin: nope\n",
			wantErr: "storage",
		},
		{
			name: "unknown restapi storage",
			yaml: `
plugins:
  app:
    uri: sqlite://memory
storage_plugins:
  files: {}
application:
  source: app
  storage: files
  api:
    v1:
      endpoints:
        users:
          actions:
            create:
              storage: warehouse
`,
			wantErr: "storage",
		},
		{
			name: "preserved storage names",
			yaml: `
plugins:
  app:
    uri: sqlite://memory
default_storage_plugin: memory
application:
  source: app
  storage: local
  api:
    v1:
      endpoints:
        users:
          actions:
            create:
              storage: dbglob
          detail_actions:
            export:
              func: export_users
              storage: static
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, "cfg.yaml", tt.yaml)
			_, err := Load([]string{path}, "")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load err = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoad_RestEndpointAndURI(t *testing.T) {
	app := `
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  api:
    v1:
      endpoints:
`
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "bad endpoint name",
			yaml:    app + "        Bad-Name: {}\n",
			wantErr: "name",
		},
		{
			name:    "url contains id",
			yaml:    app + "        users:\n          url: \"users/{id}\"\n",
			wantErr: "url",
		},
		{
			name: "missing source",
			yaml: `
application:
  api:
    v1:
      endpoints:
        users: {}
`,
			wantErr: "source",
		},
		{
			name: "unknown source",
			yaml: `
plugins:
  app:
    uri: sqlite://memory
application:
  source: missing
  api:
    v1:
      endpoints:
        users: {}
`,
			wantErr: "source",
		},
		{
			name: "internal source",
			yaml: `
plugins:
  hidden:
    uri: sqlite://memory
    internal: true
application:
  source: hidden
  api:
    v1:
      endpoints:
        users: {}
`,
		},
		{
			name:    "detail action without func",
			yaml:    app + "        users:\n          detail_actions:\n            export: {}\n",
			wantErr: "func",
		},
		{
			name:    "detail action bad name",
			yaml:    app + "        users:\n          detail_actions:\n            Export:\n              func: export_users\n",
			wantErr: "name",
		},
		{
			name:    "detail action names primary key",
			yaml:    app + "        users:\n          detail_actions:\n            export:\n              func: export_users\n              fields:\n                id:\n                  type: string\n",
			wantErr: "primary key",
		},
		{
			name:    "state action without source field",
			yaml:    app + "        users:\n          state_actions:\n            avatar: {}\n",
			wantErr: "source_field",
		},
		{
			name: "plugin uri without scheme",
			yaml: `
plugins:
  app:
    uri: sqlite-memory
`,
			wantErr: "uri",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, "cfg.yaml", tt.yaml)
			_, err := Load([]string{path}, "")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load err = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoad_ContentPair(t *testing.T) {
	path := writeConfig(t, "pair.yaml", `
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  parsers:
    - csv
    - html
  api:
    v1:
      renderers:
        - json
      endpoints:
        users:
          parsers: []
          actions:
            list:
              renderers:
                - xml
            create: {}
          detail_actions:
            publish:
              func: publish_user
              parsers:
                - form
          state_actions:
            flag:
              func: flag_user
              renderers:
                - ndjson
`)
	cfg := mustLoad(t, []string{path}, "")
	if cfg.Application.Renderers != nil {
		t.Fatalf("application renderers %#v", cfg.Application.Renderers)
	}
	if cfg.Application.Parsers == nil || len(*cfg.Application.Parsers) != 2 || (*cfg.Application.Parsers)[0] != "csv" {
		t.Fatalf("application parsers %#v", cfg.Application.Parsers)
	}
	app := cfg.RestAPI["v1"]
	if app.Parsers != nil || app.Renderers == nil || (*app.Renderers)[0] != "json" {
		t.Fatalf("api parsers %#v renderers %#v", app.Parsers, app.Renderers)
	}
	ep := app.Endpoints["users"]
	if ep.Parsers == nil || len(*ep.Parsers) != 0 || ep.Renderers != nil {
		t.Fatalf("endpoint parsers %#v renderers %#v", ep.Parsers, ep.Renderers)
	}
	list := ep.Actions["list"]
	if list.Parsers != nil || list.Renderers == nil || (*list.Renderers)[0] != "xml" {
		t.Fatalf("list parsers %#v renderers %#v", list.Parsers, list.Renderers)
	}
	create := ep.Actions["create"]
	if create.Parsers != nil || create.Renderers != nil {
		t.Fatalf("create parsers %#v renderers %#v", create.Parsers, create.Renderers)
	}
	publish := ep.DetailActions["publish"]
	if publish.Parsers == nil || (*publish.Parsers)[0] != "form" || publish.Renderers != nil {
		t.Fatalf("publish parsers %#v renderers %#v", publish.Parsers, publish.Renderers)
	}
	flag := ep.StateActions["flag"]
	if flag.Renderers == nil || (*flag.Renderers)[0] != "ndjson" || flag.Parsers != nil {
		t.Fatalf("flag parsers %#v renderers %#v", flag.Parsers, flag.Renderers)
	}

	omitted := writeConfig(t, "omitted.yaml", `
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  api:
    v1: {}
`)
	cfg = mustLoad(t, []string{omitted}, "")
	if cfg.Application.Parsers != nil || cfg.Application.Renderers != nil || cfg.RestAPI["v1"].Parsers != nil {
		t.Fatalf("omitted application %#v api %#v", cfg.Application.Parsers, cfg.RestAPI["v1"].Parsers)
	}

	bad := writeConfig(t, "bad.yaml", `
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  parsers:
    - nope
`)
	if _, err := Load([]string{bad}, ""); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("Load err = %v", err)
	}
}

func TestLoad_ContentHandlersFromYAML(t *testing.T) {
	path := writeConfig(t, "cfg.yaml", `
default_content_handlers:
  - json
  - csv
content_plugins:
  json:
    settings:
      pretty: false
  custom:
    path: ~/bin/easyrest-content-custom
plugins:
  app:
    uri: sqlite:///app.db
    content_handlers:
      - csv
      - json
application:
  source: app
  api:
    v1:
      content_handlers:
        - xml
      endpoints:
        users:
          content_handlers:
            - ndjson
            - json
`)
	cfg := mustLoad(t, []string{path}, "")
	if len(cfg.DefaultContentHandlers) != 2 || cfg.DefaultContentHandlers[0] != "json" || cfg.DefaultContentHandlers[1] != "csv" {
		t.Fatalf("default handlers %#v", cfg.DefaultContentHandlers)
	}
	if cfg.ContentPlugins["json"].Settings["pretty"] != false {
		t.Fatalf("json settings %#v", cfg.ContentPlugins["json"])
	}
	if cfg.ContentPlugins["custom"].Path != "~/bin/easyrest-content-custom" {
		t.Fatalf("custom plugin %#v", cfg.ContentPlugins["custom"])
	}
	if got := cfg.PluginMap["app"].ContentHandlers; len(got) != 2 || got[0] != "csv" {
		t.Fatalf("plugin handlers %#v", got)
	}
	app := cfg.RestAPI["v1"]
	if len(app.ContentHandlers) != 1 || app.ContentHandlers[0] != "xml" {
		t.Fatalf("app handlers %#v", app.ContentHandlers)
	}
	ep := app.Endpoints["users"]
	if len(ep.ContentHandlers) != 2 || ep.ContentHandlers[0] != "ndjson" || ep.ContentHandlers[1] != "json" {
		t.Fatalf("endpoint handlers %#v", ep.ContentHandlers)
	}
	var asMiddleware MiddlewareConfig = cfg.ContentPlugins["custom"]
	if asMiddleware.Path == "" {
		t.Fatal("MiddlewareConfig alias did not share ExternalPlugin")
	}
}

func TestLoad_ConfigFileOverlay(t *testing.T) {
	path := writeConfig(t, "cfg.yaml", `
port: "7070"
default_limit: 50
check_scope: false
plugins:
  fromfile:
    uri: sqlite:///fromfile.db
auth_plugins:
  apikey:
    settings:
      keys: ["k1"]
otel:
  enabled: true
  endpoint: "localhost:4317"
  protocol: otlphttp
  service_name: test-svc
`)
	cfg := mustLoad(t, []string{path}, "")
	if cfg.Port != "7070" {
		t.Errorf("Port from file: %s", cfg.Port)
	}
	if cfg.DefaultLimit != 50 {
		t.Errorf("DefaultLimit: %d", cfg.DefaultLimit)
	}
	if _, ok := cfg.AuthPlugins["apikey"]; !ok {
		t.Errorf("AuthPlugins: %#v", cfg.AuthPlugins)
	}
	if !cfg.Otel.Enabled || cfg.Otel.ServiceName != "test-svc" {
		t.Errorf("Otel: %#v", cfg.Otel)
	}
	fromfile := cfg.PluginMap["fromfile"]
	if fromfile.Name != "fromfile" || fromfile.DbTxEnd != "commit" || fromfile.DefaultLimit != 50 {
		t.Errorf("plugin: %#v", fromfile)
	}
}

func TestLoad_PluginDefaultLimitInheritsGlobal(t *testing.T) {
	path := writeConfig(t, "cfg.yaml", `
default_limit: 25
plugins:
  inherit:
    uri: sqlite:///inherit.db
  override:
    uri: sqlite:///override.db
    default_limit: 7
`)
	cfg := mustLoad(t, []string{path}, "")
	if cfg.PluginMap["inherit"].DefaultLimit != 25 {
		t.Errorf("inherit DefaultLimit: %d", cfg.PluginMap["inherit"].DefaultLimit)
	}
	if cfg.PluginMap["override"].DefaultLimit != 7 {
		t.Errorf("override DefaultLimit: %d", cfg.PluginMap["override"].DefaultLimit)
	}
}

func TestLoad_DbMaxRowsAndPreferCount(t *testing.T) {
	path := writeConfig(t, "cfg.yaml", `
plugins:
  inherit:
    uri: sqlite:///inherit.db
  override:
    uri: sqlite:///override.db
    db_max_rows: 50
    db_prefer_count: planned
`)
	cfg := mustLoad(t, []string{path}, "")
	inherit := cfg.PluginMap["inherit"]
	if inherit.DbMaxRows != 10000 || inherit.DbPreferCount != "" {
		t.Errorf("defaults: %+v", inherit)
	}
	override := cfg.PluginMap["override"]
	if override.DbMaxRows != 50 || override.DbPreferCount != "planned" {
		t.Errorf("overrides: %+v", override)
	}

	docPath := writeConfig(t, "plugins.yaml", `
name: alpha
uri: sqlite:///a.db
---
name: beta
uri: sqlite:///b.db
db_max_rows: 7
db_prefer_count: exact
`)
	docs := LoadPluginConfigs([]string{docPath})
	if docs["alpha"].DbMaxRows != 10000 || docs["alpha"].DbPreferCount != "" {
		t.Errorf("yaml doc defaults: %+v", docs["alpha"])
	}
	if docs["beta"].DbMaxRows != 7 || docs["beta"].DbPreferCount != "exact" {
		t.Errorf("yaml doc overrides: %+v", docs["beta"])
	}
}

func TestLoad_Internal(t *testing.T) {
	path := writeConfig(t, "cfg.yaml", `
plugins:
  public:
    uri: sqlite:///public.db
  hidden:
    uri: sqlite:///hidden.db
    internal: true
`)
	cfg := mustLoad(t, []string{path}, "")
	if cfg.PluginMap["public"].Internal {
		t.Fatal("omitted internal must stay false")
	}
	if !cfg.PluginMap["hidden"].Internal {
		t.Fatal("internal: true was not kept")
	}
}

func TestLoad_DisableHTMLEscapeYAML(t *testing.T) {
	path := writeConfig(t, "cfg.yaml", `
server:
  disable_html_escape: true
`)
	cfg := mustLoad(t, []string{path}, "")
	if !cfg.Server.DisableHTMLEscape {
		t.Fatal("expected yaml to enable DisableHTMLEscape")
	}
}

func TestLoad_StorageCascade(t *testing.T) {
	path := writeConfig(t, "cfg.yaml", `
plugins:
  app:
    uri: sqlite://memory
default_storage_plugin: local
storage_plugins:
  s3: {}
  files: {}
application:
  source: app
  storage: memory
  api:
    v1:
      endpoints:
        users:
          actions:
            create:
              storage: local
            update: {}
          detail_actions:
            export:
              func: export_users
          list_actions:
            import:
              func: import_users
              storage: s3
          state_actions:
            avatar:
              source_field: avatar
    v2:
      endpoints:
        orders:
          storage: files
`)
	cfg := mustLoad(t, []string{path}, "")
	if cfg.DefaultStoragePlugin != "local" {
		t.Fatalf("default storage %q, want local", cfg.DefaultStoragePlugin)
	}
	app := cfg.RestAPI["v1"]
	if app.Storage != "memory" {
		t.Fatalf("app storage %q, want application.storage", app.Storage)
	}
	users := app.Endpoints["users"]
	if users.Storage != "memory" {
		t.Fatalf("endpoint storage %q, want the app value", users.Storage)
	}
	if users.Actions["create"].Storage != "local" {
		t.Fatalf("create storage %q, want the explicit action value", users.Actions["create"].Storage)
	}
	if users.Actions["update"].Storage != "memory" {
		t.Fatalf("update storage %q, want the endpoint value", users.Actions["update"].Storage)
	}
	if users.DetailActions["export"].Storage != "memory" {
		t.Fatalf("detail action storage %q", users.DetailActions["export"].Storage)
	}
	if users.ListActions["import"].Storage != "s3" {
		t.Fatalf("list action storage %q, want the explicit value", users.ListActions["import"].Storage)
	}
	if users.StateActions["avatar"].Storage != "memory" {
		t.Fatalf("state action storage %q", users.StateActions["avatar"].Storage)
	}
	orders := cfg.RestAPI["v2"].Endpoints["orders"]
	if cfg.RestAPI["v2"].Storage != "memory" {
		t.Fatalf("v2 storage %q, want the shared application storage", cfg.RestAPI["v2"].Storage)
	}
	if orders.Storage != "files" {
		t.Fatalf("orders storage %q, want the endpoint value", orders.Storage)
	}

	omitted := mustLoad(t, nil, "")
	if omitted.DefaultStoragePlugin != "local" {
		t.Fatalf("omitted default %q, want local", omitted.DefaultStoragePlugin)
	}
}

func TestDefaultTimezone(t *testing.T) {
	got := defaultTimezone()
	if got == "" {
		t.Fatal("expected timezone from localtime or GMT")
	}
}

func TestLoad_Application(t *testing.T) {
	empty := mustLoad(t, nil, "")
	if empty.Port != "8080" {
		t.Fatalf("empty application changed port to %q", empty.Port)
	}
	if empty.Application.Template != "" || empty.Application.Version != "" || empty.Application.Auth != "" || len(empty.Application.API) != 0 {
		t.Fatalf("empty application: %#v", empty.Application)
	}

	path := writeConfig(t, "cfg.yaml", `
plugins:
  shop:
    uri: sqlite://memory
application:
  template: "<html></html>"
  template_path: ./page.html.tmpl
  version: shop
  auth: jwt
  api:
    shop: {}
`)
	cfg := mustLoad(t, []string{path}, "")
	if cfg.Application.Template != "<html></html>" {
		t.Fatalf("template %q", cfg.Application.Template)
	}
	if cfg.Application.TemplatePath != "./page.html.tmpl" {
		t.Fatalf("template_path %q", cfg.Application.TemplatePath)
	}
	if cfg.Application.Version != "shop" || cfg.Application.Auth != "jwt" {
		t.Fatalf("version/auth %#v", cfg.Application)
	}
}

func TestLoad_ApplicationVersionAuth(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "unknown version",
			yaml:    "application:\n  version: missing\n",
			wantErr: "application.version",
		},
		{
			name: "plugin name is not a version",
			yaml: `
plugins:
  hidden:
    uri: sqlite://memory
    internal: true
application:
  version: hidden
`,
			wantErr: "application.version",
		},
		{
			name: "use_query name is not a version",
			yaml: `
plugins:
  q:
    uri: sqlite://memory
    use_query: true
application:
  version: q
`,
			wantErr: "application.version",
		},
		{
			name: "api key wins over internal plugin",
			yaml: `
plugins:
  shop:
    uri: sqlite://memory
    internal: true
    use_query: true
application:
  source: shop
  version: shop
  api:
    shop: {}
`,
		},
		{
			name: "empty auth with version",
			yaml: `
plugins:
  shop:
    uri: sqlite://memory
application:
  source: shop
  version: shop
  api:
    shop: {}
`,
		},
		{
			name: "unknown auth",
			yaml: `
plugins:
  shop:
    uri: sqlite://memory
application:
  source: shop
  version: shop
  auth: nope
  api:
    shop: {}
`,
			wantErr: "application.auth",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, "cfg.yaml", tt.yaml)
			_, err := Load([]string{path}, "")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load err = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoad_ApplicationTemplate(t *testing.T) {
	missing := writeConfig(t, "cfg.yaml", "application:\n  template_path: /no/such/easyrest-page.html\n")
	if _, err := Load([]string{missing}, ""); err == nil || !strings.Contains(err.Error(), "template_path") {
		t.Fatalf("missing template_path err = %v", err)
	}

	bad := writeConfig(t, "bad.yaml", "application:\n  template: '{{'\n")
	if _, err := Load([]string{bad}, ""); err == nil || !strings.Contains(err.Error(), "template") {
		t.Fatalf("bad template err = %v", err)
	}

	both := writeConfig(t, "both.yaml", `
plugins:
  shop:
    uri: sqlite://memory
application:
  template: "inline-page"
  template_path: /no/such/easyrest-page.html
`)
	cfg, err := Load([]string{both}, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Application.Page == nil {
		t.Fatal("inline template was not parsed")
	}
	var buf strings.Builder
	if err := cfg.Application.Page.Execute(&buf, nil); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "inline-page" {
		t.Fatalf("executed %q, want inline template", buf.String())
	}

	plain := mustLoad(t, nil, "")
	if plain.Application.Page != nil {
		t.Fatal("empty application parsed a template")
	}
}

func TestLoad_TxEndAndTLS(t *testing.T) {
	badTx := writeConfig(t, "tx.yaml", `
plugins:
  app:
    uri: sqlite://memory
    db_tx_end: savepoint
`)
	if _, err := Load([]string{badTx}, ""); err == nil || !strings.Contains(err.Error(), "db_tx_end") {
		t.Fatalf("bad db_tx_end err = %v", err)
	}

	okTx := writeConfig(t, "ok.yaml", `
plugins:
  app:
    uri: sqlite://memory
    db_tx_end: commit-allow-override
`)
	cfg := mustLoad(t, []string{okTx}, "")
	if cfg.PluginMap["app"].DbTxEnd != "commit-allow-override" {
		t.Fatalf("db_tx_end %q", cfg.PluginMap["app"].DbTxEnd)
	}

	onlyCert := writeConfig(t, "cert.yaml", "tls_cert_file: /tmp/cert.pem\n")
	if _, err := Load([]string{onlyCert}, ""); err == nil || !strings.Contains(err.Error(), "tls") {
		t.Fatalf("cert only err = %v", err)
	}
	onlyKey := writeConfig(t, "key.yaml", "tls_key_file: /tmp/key.pem\n")
	if _, err := Load([]string{onlyKey}, ""); err == nil || !strings.Contains(err.Error(), "tls") {
		t.Fatalf("key only err = %v", err)
	}
}

func TestLoad_ApplicationAPI(t *testing.T) {
	path := writeConfig(t, "cfg.yaml", `
plugins:
  app:
    uri: sqlite://memory
middleware_plugins:
  ratelimit: {}
application:
  source: app
  public: true
  storage: local
  version: v1
  api:
    v1:
      middlewares: [ratelimit]
      content_handlers: [json]
      endpoints:
        users:
          table: people
restapi:
  ignored:
    source: app
    endpoints:
      secret: {}
`)
	cfg := mustLoad(t, []string{path}, "")
	if _, ok := cfg.RestAPI["ignored"]; ok {
		t.Fatal("restapi yaml key populated RestAPI")
	}
	got := cfg.RestAPI["v1"]
	if got.Source != "app" || !got.Public || got.Storage != "local" {
		t.Fatalf("shared fields %#v", got)
	}
	if len(got.Middlewares) != 1 || got.Middlewares[0] != "ratelimit" {
		t.Fatalf("middlewares %#v", got.Middlewares)
	}
	if len(got.ContentHandlers) != 1 || got.ContentHandlers[0] != "json" {
		t.Fatalf("content handlers %#v", got.ContentHandlers)
	}
	if got.Endpoints["users"].Table != "people" {
		t.Fatalf("endpoint %#v", got.Endpoints["users"])
	}

	pluginVersion := writeConfig(t, "plugin.yaml", `
plugins:
  app:
    uri: sqlite://memory
application:
  version: app
  api:
    v1: {}
`)
	if _, err := Load([]string{pluginVersion}, ""); err == nil || !strings.Contains(err.Error(), "application.version") {
		t.Fatalf("plugin version err = %v", err)
	}

	empty := mustLoad(t, nil, "")
	if empty.Application.Version != "" || len(empty.RestAPI) != 0 {
		t.Fatalf("empty application %#v rest %#v", empty.Application, empty.RestAPI)
	}
}

func TestLoad_ApplicationStorageUpload(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "static instance",
			yaml: `
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  storage: static
  api:
    v1: {}
`,
			wantErr: "application.storage",
		},
		{
			name: "static driver",
			yaml: `
plugins:
  app:
    uri: sqlite://memory
storage_plugins:
  assets:
    plugin: static
application:
  source: app
  storage: assets
  api:
    v1: {}
`,
			wantErr: "application.storage",
		},
		{
			name: "default static",
			yaml: `
plugins:
  app:
    uri: sqlite://memory
default_storage_plugin: static
application:
  source: app
  api:
    v1: {}
`,
			wantErr: "application.storage",
		},
		{
			name: "local",
			yaml: `
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  storage: local
  api:
    v1: {}
`,
		},
		{
			name: "s3",
			yaml: `
plugins:
  app:
    uri: sqlite://memory
storage_plugins:
  s3: {}
application:
  source: app
  storage: s3
  api:
    v1: {}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, "cfg.yaml", tt.yaml)
			_, err := Load([]string{path}, "")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load err = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
	for _, name := range []string{"memory", "dbglob"} {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, "cfg.yaml", "plugins:\n  app:\n    uri: sqlite://memory\napplication:\n  source: app\n  storage: "+name+"\n  api:\n    v1: {}\n")
			if _, err := Load([]string{path}, ""); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLoad_ApplicationAPIAuth(t *testing.T) {
	listed := writeConfig(t, "listed.yaml", `
plugins:
  app:
    uri: sqlite://memory
auth_plugins:
  jwt: {}
  basic: {}
application:
  source: app
  api:
    v1:
      auth: [basic]
`)
	cfg := mustLoad(t, []string{listed}, "")
	if cfg.RestAPI["v1"].Auth == nil || len(*cfg.RestAPI["v1"].Auth) != 1 || (*cfg.RestAPI["v1"].Auth)[0] != "basic" {
		t.Fatalf("auth %#v", cfg.RestAPI["v1"].Auth)
	}

	omitted := writeConfig(t, "omitted.yaml", `
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  api:
    v1: {}
`)
	cfg = mustLoad(t, []string{omitted}, "")
	if cfg.RestAPI["v1"].Auth != nil {
		t.Fatalf("omitted auth %#v", cfg.RestAPI["v1"].Auth)
	}

	empty := writeConfig(t, "empty.yaml", `
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  api:
    v1:
      auth: []
`)
	cfg = mustLoad(t, []string{empty}, "")
	if cfg.RestAPI["v1"].Auth == nil || len(*cfg.RestAPI["v1"].Auth) != 0 {
		t.Fatalf("empty auth %#v", cfg.RestAPI["v1"].Auth)
	}

	bad := writeConfig(t, "bad.yaml", `
plugins:
  app:
    uri: sqlite://memory
auth_plugins:
  jwt: {}
application:
  source: app
  api:
    v1:
      auth: [nope]
`)
	if _, err := Load([]string{bad}, ""); err == nil || !strings.Contains(err.Error(), "auth") {
		t.Fatalf("unknown auth err = %v", err)
	}

	badEndpoint := writeConfig(t, "bad-endpoint.yaml", `
plugins:
  app:
    uri: sqlite://memory
auth_plugins:
  jwt: {}
application:
  source: app
  api:
    v1:
      endpoints:
        users:
          auth: [missing]
`)
	if _, err := Load([]string{badEndpoint}, ""); err == nil || !strings.Contains(err.Error(), "auth") {
		t.Fatalf("unknown endpoint auth err = %v", err)
	}
}

func TestLoad_StateFunc(t *testing.T) {
	both := writeConfig(t, "both.yaml", `
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  api:
    v1:
      endpoints:
        users:
          state_actions:
            settings:
              func: load_settings
              source_field: avatar
`)
	if _, err := Load([]string{both}, ""); err == nil || !strings.Contains(err.Error(), "source_field") {
		t.Fatalf("func and source_field err = %v", err)
	}

	onlyFunc := writeConfig(t, "func.yaml", `
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  api:
    v1:
      endpoints:
        users:
          state_actions:
            settings:
              func: load_settings
`)
	cfg := mustLoad(t, []string{onlyFunc}, "")
	got := cfg.RestAPI["v1"].Endpoints["users"].StateActions["settings"]
	if got.Func != "load_settings" || got.SourceField != "" {
		t.Fatalf("state %#v", got)
	}

	neither := writeConfig(t, "neither.yaml", `
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  api:
    v1:
      endpoints:
        users:
          state_actions:
            avatar: {}
`)
	if _, err := Load([]string{neither}, ""); err == nil || !strings.Contains(err.Error(), "source_field") {
		t.Fatalf("neither err = %v", err)
	}
}

func TestLoad_StateURL(t *testing.T) {
	path := writeConfig(t, "state-url.yaml", `
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  api:
    v1:
      endpoints:
        discovery:
          url: .well-known
          state_actions:
            openid_configuration:
              url: openid-configuration
              func: app.openid_configuration
`)
	cfg := mustLoad(t, []string{path}, "")
	got := cfg.RestAPI["v1"].Endpoints["discovery"].StateActions["openid_configuration"]
	if got.URL != "openid-configuration" || got.Func != "app.openid_configuration" {
		t.Fatalf("state %#v", got)
	}
}

func TestRestActionSegment(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		url     string
		want    string
		wantErr string
	}{
		{name: "empty url uses key", key: "openid_configuration", want: "openid_configuration"},
		{name: "hyphenated segment", key: "openid_configuration", url: "openid-configuration", want: "openid-configuration"},
		{name: "slash", key: "openid_configuration", url: "a/b", wantErr: "invalid"},
		{name: "dot", key: "openid_configuration", url: ".", wantErr: "invalid"},
		{name: "dot dot", key: "openid_configuration", url: "..", wantErr: "invalid"},
		{name: "braces", key: "openid_configuration", url: "{id}", wantErr: "invalid"},
		{name: "uppercase", key: "openid_configuration", url: "OpenId", wantErr: "invalid"},
		{name: "space", key: "openid_configuration", url: "open id", wantErr: "invalid"},
		{name: "bad key", key: "Export", wantErr: "name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RestActionSegment(tt.key, tt.url)
			if tt.wantErr == "" {
				if err != nil || got != tt.want {
					t.Fatalf("RestActionSegment(%q, %q) = %q, %v", tt.key, tt.url, got, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("RestActionSegment(%q, %q) = %q, %v, want error %q", tt.key, tt.url, got, err, tt.wantErr)
			}
		})
	}
}

func TestLoad_StateURLRejected(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		url     string
		wantErr string
	}{
		{name: "slash", action: "openid_configuration", url: "a/b", wantErr: "invalid"},
		{name: "bad key", action: "Export", url: "openid-configuration", wantErr: "[a-z0-9_]+"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, "state-url.yaml", fmt.Sprintf(`
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  api:
    v1:
      endpoints:
        discovery:
          url: .well-known
          state_actions:
            %s:
              url: %s
              func: app.openid_configuration
`, tt.action, tt.url))
			_, err := Load([]string{path}, "")
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load err = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoad_CallURL(t *testing.T) {
	path := writeConfig(t, "call-url.yaml", `
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  api:
    v1:
      endpoints:
        users:
          detail_actions:
            archive:
              url: store
              func: app.archive_user
          list_actions:
            export:
              url: pull
              func: app.export_users
`)
	cfg := mustLoad(t, []string{path}, "")
	users := cfg.RestAPI["v1"].Endpoints["users"]
	if users.DetailActions["archive"].URL != "store" || users.ListActions["export"].URL != "pull" {
		t.Fatalf("detail %#v list %#v", users.DetailActions["archive"], users.ListActions["export"])
	}

	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "list slash",
			yaml: `
          list_actions:
            export:
              url: a/b
              func: app.export_users
`,
			wantErr: "invalid",
		},
		{
			name: "detail slash",
			yaml: `
          detail_actions:
            archive:
              url: a/b
              func: app.archive_user
`,
			wantErr: "invalid",
		},
		{
			name: "bad list key",
			yaml: `
          list_actions:
            Export:
              url: pull
              func: app.export_users
`,
			wantErr: "name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bad := writeConfig(t, "call-url.yaml", `
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  api:
    v1:
      endpoints:
        users:
`+tt.yaml)
			_, err := Load([]string{bad}, "")
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load err = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoad_StatePost(t *testing.T) {
	okPath := writeConfig(t, "post.yaml", `
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  api:
    v1:
      endpoints:
        users:
          state_actions:
            settings:
              func: load_settings
              post: true
`)
	cfg := mustLoad(t, []string{okPath}, "")
	got := cfg.RestAPI["v1"].Endpoints["users"].StateActions["settings"]
	if !got.Post || got.Func != "load_settings" {
		t.Fatalf("state %#v", got)
	}

	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name:    "column",
			body:    "source_field: avatar\n              post: true",
			wantErr: "post",
		},
		{
			name:    "neither",
			body:    "post: true",
			wantErr: "source_field",
		},
		{
			name:    "both",
			body:    "func: load_settings\n              source_field: avatar\n              post: true",
			wantErr: "both",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, "post.yaml", fmt.Sprintf(`
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  api:
    v1:
      endpoints:
        users:
          state_actions:
            settings:
              %s
`, tt.body))
			_, err := Load([]string{path}, "")
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load err = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoad_ActionPathOverlap(t *testing.T) {
	base := `
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  api:
    v1:
      endpoints:
        users:
`
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name: "two state urls",
			body: `
          state_actions:
            one:
              url: shared
              func: app.one
            two:
              url: shared
              func: app.two
`,
			wantErr: "overlaps",
		},
		{
			name: "post state and list",
			body: `
          list_actions:
            export:
              func: app.export_users
          state_actions:
            dump:
              url: export
              func: app.dump
              post: true
`,
			wantErr: "overlaps",
		},
		{
			name: "put state beside list",
			body: `
          list_actions:
            export:
              func: app.export_users
          state_actions:
            dump:
              url: export
              func: app.dump
`,
		},
		{
			name: "different slash",
			body: `
          list_actions:
            export:
              func: app.export_users
              no_trailing_slash: true
          state_actions:
            dump:
              url: export
              func: app.dump
              post: true
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, "overlap.yaml", base+tt.body)
			_, err := Load([]string{path}, "")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load err = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoad_InternalRPC(t *testing.T) {
	empty := mustLoad(t, nil, "")
	if empty.InternalRPC.Address != "" || empty.InternalRPC.FD != 0 {
		t.Fatalf("empty %#v", empty.InternalRPC)
	}

	listed := writeConfig(t, "rpc.yaml", `
internal_rpc:
  network: unix
  address: /tmp/easyrest.sock
`)
	cfg := mustLoad(t, []string{listed}, "")
	if cfg.InternalRPC.Network != "unix" || cfg.InternalRPC.Address != "/tmp/easyrest.sock" {
		t.Fatalf("stored %#v", cfg.InternalRPC)
	}

	both := writeConfig(t, "both.yaml", `
internal_rpc:
  network: unix
  address: /tmp/easyrest.sock
  fd: 3
`)
	if _, err := Load([]string{both}, ""); err == nil || !strings.Contains(err.Error(), "internal_rpc") {
		t.Fatalf("fd and address err = %v", err)
	}
}

func TestLoad_RestView(t *testing.T) {
	base := `
plugins:
  app:
    uri: sqlite://memory
application:
  source: app
  api:
    v1:
      endpoints:
        users:
`
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name: "valid sse beside crud",
			body: `
          views:
            sse:
              path: "{id}/sse"
              methods: [GET]
              handler: userEvents
`,
		},
		{
			name: "invalid path",
			body: `
          views:
            sse:
              path: "{id}/sse/"
              methods: [GET]
              handler: userEvents
`,
			wantErr: "sse",
		},
		{
			name: "unknown method",
			body: `
          views:
            sse:
              path: "{id}/sse"
              methods: [TRACE]
              handler: userEvents
`,
			wantErr: "sse",
		},
		{
			name: "duplicate method",
			body: `
          views:
            sse:
              path: "{id}/sse"
              methods: [GET, get]
              handler: userEvents
`,
			wantErr: "sse",
		},
		{
			name: "empty handler",
			body: `
          views:
            sse:
              path: "{id}/sse"
              methods: [GET]
`,
			wantErr: "sse",
		},
		{
			name: "overlaps retrieve",
			body: `
          views:
            sse:
              path: "{id}"
              methods: [GET]
              handler: userEvents
`,
			wantErr: "sse",
		},
		{
			name: "overlaps detail action",
			body: `
          detail_actions:
            archive:
              func: app.archive_user
          views:
            sse:
              path: "{id}/archive"
              methods: [POST]
              handler: userEvents
`,
			wantErr: "sse",
		},
		{
			name: "repeats endpoint param",
			body: `
          url: orgs/{org_id}/users
          views:
            sse:
              path: "{org_id}/sse"
              methods: [GET]
              handler: userEvents
`,
			wantErr: "sse",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, "view.yaml", base+tt.body)
			cfg, err := Load([]string{path}, "")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				view := cfg.RestAPI["v1"].Endpoints["users"].Views["sse"]
				if view.Path != "{id}/sse" || view.Handler != "userEvents" || len(view.Methods) != 1 || view.Methods[0] != "GET" {
					t.Fatalf("view %#v", view)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load err = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
