package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func clearEREnv(t *testing.T) {
	t.Helper()
	for _, e := range os.Environ() {
		if len(e) > 3 && e[:3] == "ER_" {
			key := e
			for i := 0; i < len(e); i++ {
				if e[i] == '=' {
					key = e[:i]
					break
				}
			}
			t.Setenv(key, "")
			os.Unsetenv(key)
		}
	}
}

func TestLoadPluginConfigs_FromEnv(t *testing.T) {
	clearEREnv(t)
	t.Setenv("ER_DB_APP", "sqlite:///tmp/app.db")
	t.Setenv("ER_CACHE_ENABLE_APP", "1")
	t.Setenv("ER_USE_QUERY_APP", "1")
	// CacheName lookup uses lowercase conn name in env key
	t.Setenv("ER_DB_app_CACHENAME", "redis")
	t.Setenv("ER_CACHE_REDIS", "redis://localhost:6379")

	plugins := LoadPluginConfigs(nil)

	app, ok := plugins["app"]
	if !ok {
		t.Fatalf("expected app plugin, got %#v", plugins)
	}
	if app.Uri != "sqlite:///tmp/app.db" {
		t.Errorf("Uri: %s", app.Uri)
	}
	if !app.EnableCache {
		t.Error("expected EnableCache")
	}
	if !app.UseQuery {
		t.Error("expected UseQuery")
	}
	if app.CacheName != "redis" {
		t.Errorf("CacheName: %q", app.CacheName)
	}
	if app.DbTxEnd != "commit-allow-override" {
		t.Errorf("DbTxEnd: %q", app.DbTxEnd)
	}

	redis, ok := plugins["redis"]
	if !ok {
		t.Fatalf("expected redis cache plugin from ER_CACHE_*")
	}
	if redis.Uri != "redis://localhost:6379" {
		t.Errorf("redis Uri: %s", redis.Uri)
	}
	if redis.DbTxEnd != "commit" {
		t.Errorf("redis DbTxEnd: %q", redis.DbTxEnd)
	}
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

	// unreadable path should be skipped
	plugins := LoadPluginConfigs([]string{
		filepath.Join(dir, "missing.yaml"),
		path,
		filepath.Join(dir, "bad.yaml"),
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

func TestLoad_EnvOverridesAndDefaults(t *testing.T) {
	clearEREnv(t)
	t.Setenv("ER_PORT", "9090")
	t.Setenv("ER_CHECK_SCOPE", "1")
	t.Setenv("ER_TOKEN_SECRET", "secret")
	t.Setenv("ER_TOKEN_USER_SEARCH", "email")
	t.Setenv("ER_NO_PLUGIN_LOG", "0")
	t.Setenv("ER_ACCESSLOG", "1")
	t.Setenv("ER_DEFAULT_TIMEZONE", "UTC")
	t.Setenv("ER_TOKEN_AUTHFLOW", "client_credentials")
	t.Setenv("ER_CORS_ENABLED", "1")
	t.Setenv("ER_CORS_ORIGINS", "https://a.com,https://b.com")
	t.Setenv("ER_CORS_METHODS", "GET,POST")
	t.Setenv("ER_CORS_HEADERS", "Authorization")
	t.Setenv("ER_CORS_MAX_AGE", "3600")
	t.Setenv("ER_TLS_CERT_FILE", "/tmp/cert.pem")
	t.Setenv("ER_TLS_KEY_FILE", "/tmp/key.pem")
	t.Setenv("ER_PLUGINS", "")
	t.Setenv("ER_SERVER_READ_TIMEOUT", "2s")
	t.Setenv("ER_SERVER_WRITE_TIMEOUT", "3s")
	t.Setenv("ER_SERVER_IDLE_TIMEOUT", "4s")
	t.Setenv("ER_SERVER_READ_HEADER_TIMEOUT", "1s")
	t.Setenv("ER_SERVER_KEEP_ALIVE_PERIOD", "30s")
	t.Setenv("ER_SERVER_MAX_HEADER_BYTES", "2MB")
	t.Setenv("ER_SERVER_MAX_BODY_SIZE", "1MB")
	t.Setenv("ER_HTTP2_MAX_CONCURRENT_STREAMS", "100")
	t.Setenv("ER_HTTP2_MAX_READ_FRAME_SIZE", "16384")
	t.Setenv("ER_HTTP2_MAX_UPLOAD_BUFFER_PER_CONNECTION", "65536")
	t.Setenv("ER_HTTP2_MAX_UPLOAD_BUFFER_PER_STREAM", "32768")
	t.Setenv("ER_HTTP2_IDLE_TIMEOUT", "10s")
	t.Setenv("ER_HTTP2_READ_IDLE_TIMEOUT", "5s")
	t.Setenv("ER_HTTP2_PING_TIMEOUT", "2s")
	t.Setenv("ER_HTTP2_PERMIT_PROHIBITED_CIPHER_SUITES", "true")
	t.Setenv("ER_SERVER_TRUSTED_PROXY_MODE", "header")
	t.Setenv("ER_SERVER_TRUSTED_PROXY_COUNT", "2")
	t.Setenv("ER_SERVER_TRUSTED_PROXY_HEADER", "X-Real-IP")
	t.Setenv("ER_TOKEN_CACHE_TTL", "60")
	t.Setenv("ER_ANON_CLAIMS", `{"role":"anon"}`)
	t.Setenv("ER_DB_DEMO", "sqlite:///demo.db")

	cfg := Load()

	if cfg.Port != "9090" {
		t.Errorf("Port: %s", cfg.Port)
	}
	if !cfg.CheckScope {
		t.Error("CheckScope")
	}
	if cfg.TokenUserSearch != "email" {
		t.Errorf("TokenUserSearch: %s", cfg.TokenUserSearch)
	}
	if cfg.NoPluginLog {
		t.Error("NoPluginLog should be false")
	}
	if !cfg.AccessLogOn {
		t.Error("AccessLogOn")
	}
	if cfg.DefaultTimezone != "UTC" {
		t.Errorf("timezone: %s", cfg.DefaultTimezone)
	}
	if !cfg.CORS.Enabled || cfg.CORS.MaxAge != 3600 {
		t.Errorf("CORS: %#v", cfg.CORS)
	}
	if len(cfg.CORS.Origins) != 2 {
		t.Errorf("Origins: %v", cfg.CORS.Origins)
	}
	if !cfg.TLSEnabled {
		t.Error("TLSEnabled")
	}
	if cfg.Server.ReadTimeout != 2*time.Second {
		t.Errorf("ReadTimeout: %v", cfg.Server.ReadTimeout)
	}
	if cfg.Server.MaxBodySize != 1000000 { // go-units uses decimal MB
		t.Errorf("MaxBodySize: %d", cfg.Server.MaxBodySize)
	}
	if cfg.Server.HTTP2MaxConcurrentStreams != 100 {
		t.Errorf("HTTP2 streams: %d", cfg.Server.HTTP2MaxConcurrentStreams)
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
	if cfg.DefaultLimit != 100 {
		t.Errorf("DefaultLimit: %d", cfg.DefaultLimit)
	}
	if cfg.Otel.Protocol != "otlp" || cfg.Otel.ServiceName != "easyrest-server" {
		t.Errorf("Otel defaults: %#v", cfg.Otel)
	}
	jwtAuth, ok := cfg.AuthPlugins["jwt"]
	if !ok {
		t.Fatal("expected default jwt auth")
	}
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

func TestLoad_InvalidAnonClaimsAndCheckScopeOff(t *testing.T) {
	clearEREnv(t)
	t.Setenv("ER_CHECK_SCOPE", "0")
	t.Setenv("ER_ANON_CLAIMS", "not-json")
	t.Setenv("ER_DEFAULT_TIMEZONE", "GMT")
	t.Setenv("ER_TOKEN_SECRET", "x")

	cfg := Load()
	if cfg.CheckScope {
		t.Error("CheckScope should be false")
	}
	if len(cfg.AnonClaims) != 0 {
		t.Errorf("AnonClaims should stay empty on parse error: %#v", cfg.AnonClaims)
	}
}

func TestLoad_ConfigFileOverlay(t *testing.T) {
	clearEREnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	content := `
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
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ER_CONFIG_FILE", path)
	t.Setenv("ER_DEFAULT_TIMEZONE", "UTC")
	t.Setenv("ER_TOKEN_SECRET", "s")

	cfg := Load()
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
	if fromfile.Name != "fromfile" {
		t.Errorf("plugin name not set: %#v", fromfile)
	}
	if fromfile.DbTxEnd != "commit" {
		t.Errorf("DbTxEnd default: %q", fromfile.DbTxEnd)
	}
}

func TestLoad_InvalidDurationAndSizeIgnored(t *testing.T) {
	clearEREnv(t)
	t.Setenv("ER_SERVER_READ_TIMEOUT", "notadur")
	t.Setenv("ER_SERVER_MAX_BODY_SIZE", "nope")
	t.Setenv("ER_CORS_MAX_AGE", "abc")
	t.Setenv("ER_SERVER_TRUSTED_PROXY_COUNT", "0")
	t.Setenv("ER_DEFAULT_TIMEZONE", "UTC")
	t.Setenv("ER_TOKEN_SECRET", "s")

	cfg := Load()
	if cfg.Server.ReadTimeout != 5*time.Second {
		t.Errorf("expected default ReadTimeout, got %v", cfg.Server.ReadTimeout)
	}
	if cfg.Server.MaxBodySize != 10*1024*1024 {
		t.Errorf("expected default MaxBodySize, got %d", cfg.Server.MaxBodySize)
	}
	if cfg.CORS.MaxAge != 86400 {
		t.Errorf("expected default MaxAge, got %d", cfg.CORS.MaxAge)
	}
	if cfg.Server.TrustedProxyCount != 1 {
		t.Errorf("expected default TrustedProxyCount, got %d", cfg.Server.TrustedProxyCount)
	}
}
