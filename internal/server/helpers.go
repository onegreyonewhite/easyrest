package server

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/go-hclog"
	hplugin "github.com/hashicorp/go-plugin"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// Global configuration and dbPlugins loaded only once.
var (
	cfg        config.Config
	cfgOnce    sync.Once
	DbPlugins  = make(map[string]easyrest.DBPlugin)
	AllowedOps = map[string]string{
		"eq":    "=",
		"neq":   "!=",
		"lt":    "<",
		"lte":   "<=",
		"gt":    ">",
		"gte":   ">=",
		"like":  "LIKE",
		"ilike": "ILIKE",
		"is":    "IS",
		"in":    "IN",
	}
	allowedFuncs = [5]string{
		"count",
		"sum",
		"avg",
		"min",
		"max",
	}
)

// schemaCache caches GetSchema results per dbKey.
var (
	schemaCache      = make(map[string]any)
	schemaCacheMutex sync.RWMutex
)

// Pool for JSON encoding.
var jsonBufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// GetConfig loads configuration only once.
func GetConfig() config.Config {
	cfgOnce.Do(func() {
		cfg = config.Load()
	})
	return cfg
}

// SetConfig sets a new configuration.
func SetConfig(newConfig config.Config) {
	cfg = newConfig
}

// IsAllowedFunction checks if the provided function name is allowed.
func IsAllowedFunction(item string) bool {
	for _, v := range allowedFuncs {
		if v == item {
			return true
		}
	}
	return false
}

// escapeSQLLiteral escapes single quotes in SQL string literals.
func escapeSQLLiteral(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// getNestedValue traverses a nested map using dot-separated keys.
// If the full path is found, it returns the value and true; otherwise false.
func getNestedValue(data map[string]any, path string) (any, bool) {
	parts := strings.Split(path, ".")
	var current any = data
	for _, p := range parts {
		if m, ok := current.(map[string]any); ok {
			if val, exists := m[p]; exists {
				current = val
			} else {
				return nil, false
			}
		} else {
			return nil, false
		}
	}
	return current, true
}

// substitutePluginContext replaces values starting with "erctx." or "request."
// with the corresponding value from flatCtx or pluginCtx.
func substitutePluginContext(input string, flatCtx map[string]string, pluginCtx map[string]any) string {
	if strings.HasPrefix(input, "erctx.") {
		key := input[len("erctx."):]
		normalizedKey := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
		if val, ok := flatCtx[normalizedKey]; ok {
			return val
		}
	} else if strings.HasPrefix(input, "request.") {
		key := input[len("request."):]
		if v, ok := getNestedValue(pluginCtx, key); ok {
			rv := reflect.ValueOf(v)
			switch rv.Kind() {
			case reflect.Map, reflect.Slice, reflect.Array:
				if bytes, err := json.Marshal(v); err == nil {
					return string(bytes)
				}
			}
			return fmt.Sprintf("%v", v)
		}
	}
	return input
}

// substituteValue recursively substitutes string values in arbitrary data structures.
func substituteValue(val any, flatCtx map[string]string, pluginCtx map[string]any) any {
	switch s := val.(type) {
	case string:
		if strings.HasPrefix(s, "erctx.") || strings.HasPrefix(s, "request.") {
			return substitutePluginContext(s, flatCtx, pluginCtx)
		}
		return s
	case map[string]any:
		for k, v := range s {
			s[k] = substituteValue(v, flatCtx, pluginCtx)
		}
		return s
	case []any:
		for i, v := range s {
			s[i] = substituteValue(v, flatCtx, pluginCtx)
		}
		return s
	default:
		return val
	}
}

// ParseCSV splits a comma-separated string.
func ParseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// respondJSON writes a JSON response with the given status code and data.
func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	// Get buffer from pool
	buf := jsonBufferPool.Get().(*bytes.Buffer)
	defer jsonBufferPool.Put(buf)
	buf.Reset()

	// Use optimized encoder
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false) // Disable HTML escaping for better performance

	if err := enc.Encode(data); err != nil {
		w.Write([]byte("{}"))
		return
	}

	// Copy data from buffer to ResponseWriter
	w.Write(buf.Bytes())
}

// DecodeTokenWithoutValidation decodes a JWT token without validating its signature.
func DecodeTokenWithoutValidation(tokenStr string) (jwt.MapClaims, error) {
	parts := bytes.Split([]byte(tokenStr), []byte("."))
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	decoder := base64.URLEncoding.WithPadding(base64.NoPadding)
	decoded, err := decoder.DecodeString(string(parts[1]))
	if err != nil {
		return nil, err
	}

	var claims map[string]any
	err = json.Unmarshal(decoded, &claims)
	return jwt.MapClaims(claims), err
}

// CheckScope verifies if the claims contain the required scope.
func CheckScope(claims jwt.MapClaims, required string) bool {
	scopeVal, ok := claims["scope"]
	if !ok {
		return false
	}
	scopesStr, ok := scopeVal.(string)
	if !ok {
		return false
	}
	scopes := strings.Fields(scopesStr)
	for _, s := range scopes {
		if s == required {
			return true
		}
		if (strings.HasSuffix(required, "read") && s == "read") ||
			(strings.HasSuffix(required, "write") && s == "write") {
			return true
		}
	}
	return false
}

// extractUserIDFromClaims extracts the user ID from JWT claims.
func extractUserIDFromClaims(claims jwt.MapClaims) string {
	config := GetConfig()
	searchPath := config.TokenUserSearch
	if val, ok := claims[searchPath]; ok {
		return fmt.Sprintf("%v", val)
	}
	return ""
}

// getTokenClaims retrieves token claims from the request context.
func getTokenClaims(r *http.Request) jwt.MapClaims {
	if claims, ok := r.Context().Value(TokenClaimsKey).(jwt.MapClaims); ok {
		return claims
	}
	return nil
}

func checkFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("file is not executable: %s", path)
	}
	return path, nil
}

// findPluginPath searches for a plugin executable in various locations:
// 1. In PATH
// 2. In current working directory
// 3. In the same directory as the current executable
// For each location, it checks both the base name and OS-specific name
func findPluginPath(pluginExec string) (string, error) {
	// Get OS and architecture for OS-specific plugin name
	osName := runtime.GOOS
	archName := runtime.GOARCH
	osSpecificName := fmt.Sprintf("%s-%s-%s", pluginExec, osName, archName)

	// 1. Search in PATH
	if basePath, err := exec.LookPath(pluginExec); err == nil {
		if path, err := checkFile(basePath); err == nil {
			return path, nil
		}
	}
	if basePath, err := exec.LookPath(osSpecificName); err == nil {
		if path, err := checkFile(basePath); err == nil {
			return path, nil
		}
	}

	// 2. Search in current working directory
	cwd, err := os.Getwd()
	if err == nil {
		basePath := filepath.Join(cwd, pluginExec)
		if path, err := checkFile(basePath); err == nil {
			return path, nil
		}
		osSpecificPath := filepath.Join(cwd, osSpecificName)
		if path, err := checkFile(osSpecificPath); err == nil {
			return path, nil
		}
	}

	// 3. Search in the same directory as the current executable
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		basePath := filepath.Join(execDir, pluginExec)
		if path, err := checkFile(basePath); err == nil {
			return path, nil
		}
		osSpecificPath := filepath.Join(execDir, osSpecificName)
		if path, err := checkFile(osSpecificPath); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("plugin not found: %s", pluginExec)
}

// LoadDBPlugins loads all configured database plugins.
func LoadDBPlugins() {
	cfg := GetConfig()
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "ER_DB_") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) != 2 {
				continue
			}
			envName := parts[0]
			uri := parts[1]
			connName := strings.ToLower(strings.TrimPrefix(envName, "ER_DB_"))
			splitURI := strings.SplitN(uri, "://", 2)
			if len(splitURI) != 2 {
				stdlog.Printf("Invalid URI for %s: %s", connName, uri)
				continue
			}
			pluginType := splitURI[0]
			pluginExec := "easyrest-plugin-" + pluginType
			pluginPath, err := findPluginPath(pluginExec)
			if err != nil {
				stdlog.Printf("Plugin %s not found: %v", pluginExec, err)
				continue
			}

			absPluginPath, err := filepath.Abs(pluginPath)
			if err != nil {
				stdlog.Printf("Error getting absolute path for plugin %s: %v", pluginExec, err)
				continue
			}

			pluginConfig := hplugin.ClientConfig{
				HandshakeConfig: easyrest.Handshake,
				Plugins: map[string]hplugin.Plugin{
					"db": &easyrest.DBPluginPlugin{},
				},
				Cmd:              exec.Command(absPluginPath),
				AllowedProtocols: []hplugin.Protocol{hplugin.ProtocolNetRPC},
			}
			if cfg.NoPluginLog {
				pluginConfig.Logger = hclog.New(&hclog.LoggerOptions{
					Output: io.Discard,
				})
			}
			client := hplugin.NewClient(&pluginConfig)
			rpcClient, err := client.Client()
			if err != nil {
				stdlog.Printf("Error creating RPC client for plugin %s: %v", connName, err)
				continue
			}
			raw, err := rpcClient.Dispense("db")
			if err != nil {
				stdlog.Printf("Error dispensing plugin %s: %v", connName, err)
				continue
			}
			dbPlug, ok := raw.(easyrest.DBPlugin)
			if !ok {
				stdlog.Printf("Error: plugin %s does not implement DBPlugin interface", connName)
				continue
			}
			err = dbPlug.InitConnection(uri)
			if err != nil {
				stdlog.Printf("Error initializing connection for plugin %s: %v", connName, err)
				continue
			}
			DbPlugins[connName] = dbPlug
			stdlog.Printf("Connection %s initialized using plugin %s", connName, pluginExec)
		}
	}
}
