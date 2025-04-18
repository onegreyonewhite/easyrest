package server

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	hplugin "github.com/hashicorp/go-plugin"
	"github.com/onegreyonewhite/easyrest/internal/cache"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// Global configuration and dbPlugins loaded only once.
var (
	cfg           config.Config
	cfgOnce       sync.Once
	DbPlugins     atomic.Pointer[map[string]easyrest.DBPlugin]
	CachePlugins  atomic.Pointer[map[string]easyrest.CachePlugin]
	pluginClients atomic.Pointer[map[string]*hplugin.Client]
	AllowedOps    = map[string]string{
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

func init() {
	// Initialize atomic pointers with empty maps
	emptyDbPlugins := make(map[string]easyrest.DBPlugin)
	DbPlugins.Store(&emptyDbPlugins)
	emptyCachePlugins := make(map[string]easyrest.CachePlugin)
	CachePlugins.Store(&emptyCachePlugins)
	emptyPluginClients := make(map[string]*hplugin.Client)
	pluginClients.Store(&emptyPluginClients)
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

func ReloadConfig() {
	cfgOnce = sync.Once{}
	schemaCache = make(map[string]any)
}

func StopPlugins() {
	// Get the current clients map pointer
	oldClientsPtr := pluginClients.Load()

	// Atomically set empty maps
	emptyDbPlugins := make(map[string]easyrest.DBPlugin)
	DbPlugins.Store(&emptyDbPlugins)
	emptyCachePlugins := make(map[string]easyrest.CachePlugin)
	CachePlugins.Store(&emptyCachePlugins)
	emptyPluginClients := make(map[string]*hplugin.Client)
	pluginClients.Store(&emptyPluginClients)

	// Kill clients from the old map
	if oldClientsPtr != nil {
		oldClients := *oldClientsPtr
		for connName, client := range oldClients {
			stdlog.Printf("Stopping plugin client for connection: %s", connName)
			client.Kill()
		}
	}
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

// respondJSON serializes v to JSON and writes it to w with Content-Type header.
func respondJSON(w http.ResponseWriter, status int, v interface{}) {
	buf := jsonBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer jsonBufferPool.Put(buf)

	// Use goccy/go-json with optimized settings
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)

	if err := enc.Encode(v); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// parseRequest parses the request body according to the Content-Type.
// The parameter expectArray indicates whether an array of objects (true) or a single object (false) is expected.
func parseRequest(r *http.Request, expectArray bool) (interface{}, error) {
	contentType := r.Header.Get("Content-Type")
	if idx := strings.Index(contentType, ";"); idx != -1 {
		contentType = contentType[:idx]
	}
	contentType = strings.TrimSpace(contentType)

	switch contentType {
	case "application/json", "":
		// By default, use JSON.
		if expectArray {
			var data []map[string]any
			if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
				return nil, fmt.Errorf("JSON parse error: %w", err)
			}
			return data, nil
		} else {
			var data map[string]any
			if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
				return nil, fmt.Errorf("JSON parse error: %w", err)
			}
			return data, nil
		}

	case "text/csv":
		reader := csv.NewReader(r.Body)
		records, err := reader.ReadAll()
		if err != nil {
			return nil, fmt.Errorf("CSV parse error: %w", err)
		}

		if len(records) < 1 {
			return nil, fmt.Errorf("empty CSV data")
		}

		headers := records[0]
		result := make([]map[string]any, 0, len(records)-1)

		for i := 1; i < len(records); i++ {
			row := make(map[string]any)
			for j, header := range headers {
				if j < len(records[i]) {
					row[header] = records[i][j]
				} else {
					row[header] = ""
				}
			}
			result = append(result, row)
		}

		// If only a single object is expected, but CSV typically represents an array.
		if !expectArray && len(result) > 0 {
			return result[0], nil
		}
		return result, nil

	case "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			return nil, fmt.Errorf("form parse error: %w", err)
		}

		if expectArray {
			// It is difficult to represent an array of objects for form-urlencoded.
			// Return an array with a single object if an array is expected.
			result := make([]map[string]any, 1)
			data := make(map[string]any)
			for key, values := range r.Form {
				if len(values) == 1 {
					data[key] = values[0]
				} else {
					data[key] = values
				}
			}
			result[0] = data
			return result, nil
		} else {
			data := make(map[string]any)
			for key, values := range r.Form {
				if len(values) == 1 {
					data[key] = values[0]
				} else {
					data[key] = values
				}
			}
			return data, nil
		}

	case "application/xml":
		if expectArray {
			// XML does not have a standard representation for an array of objects.
			// Expect something like <items><item>...</item><item>...</item></items>.
			var result struct {
				Items []map[string]any `xml:"item"`
			}
			if err := xml.NewDecoder(r.Body).Decode(&result); err != nil {
				return nil, fmt.Errorf("XML parse error: %w", err)
			}
			return result.Items, nil
		} else {
			// For XML, a root element is required.
			var wrapper struct {
				Data map[string]any `xml:",any"`
			}
			if err := xml.NewDecoder(r.Body).Decode(&wrapper); err != nil {
				return nil, fmt.Errorf("XML parse error: %w", err)
			}
			return wrapper.Data, nil
		}

	default:
		return nil, fmt.Errorf("unsupported Content-Type: %s", contentType)
	}
}

// makeResponse transforms the data according to the Accept header and sends the response.
func makeResponse(w http.ResponseWriter, r *http.Request, status int, v any) {
	// Determine output format based on the Accept header
	acceptHeader := r.Header.Get("Accept")
	contentType := r.Header.Get("Content-Type")

	// If Accept is not set or equals */*, use Content-Type
	if acceptHeader == "" || acceptHeader == "*/*" {
		acceptHeader = contentType
		w.Header().Add("Vary", "Content-Type")
	}

	// If Accept contains multiple types, take the first
	if idx := strings.Index(acceptHeader, ","); idx != -1 {
		acceptHeader = acceptHeader[:idx]
	}
	// Remove parameters like charset
	if idx := strings.Index(acceptHeader, ";"); idx != -1 {
		acceptHeader = acceptHeader[:idx]
	}
	acceptHeader = strings.TrimSpace(acceptHeader)

	w.Header().Add("Vary", "Accept")

	switch acceptHeader {
	case "application/json", "":
		// By default, use JSON.
		respondJSON(w, status, v)
		return

	case "text/csv":
		w.Header().Set("Content-Type", "text/csv")
		w.WriteHeader(status)

		writer := csv.NewWriter(w)

		// Convert the data into the required format for CSV.
		var records [][]string

		// Handle the case of an array of objects.
		if data, ok := v.([]map[string]any); ok && len(data) > 0 {
			// Collect all headers from all objects.
			headers := make(map[string]bool)
			for _, item := range data {
				for key := range item {
					headers[key] = true
				}
			}

			// Convert the header map into a slice.
			headerSlice := make([]string, 0, len(headers))
			for header := range headers {
				headerSlice = append(headerSlice, header)
			}

			// Add the header row.
			records = append(records, headerSlice)

			// Add the data rows.
			for _, item := range data {
				row := make([]string, len(headerSlice))
				for i, header := range headerSlice {
					if val, ok := item[header]; ok {
						row[i] = fmt.Sprintf("%v", val)
					}
				}
				records = append(records, row)
			}
		} else if data, ok := v.(map[string]any); ok {
			// Handle the case of a single object.
			headers := make([]string, 0, len(data))
			values := make([]string, 0, len(data))

			for key, val := range data {
				headers = append(headers, key)
				values = append(values, fmt.Sprintf("%v", val))
			}

			records = append(records, headers, values)
		} else {
			// If the data type is not suitable for CSV.
			http.Error(w, "Data format not suitable for CSV", http.StatusInternalServerError)
			return
		}

		if err := writer.WriteAll(records); err != nil {
			http.Error(w, "Error writing CSV", http.StatusInternalServerError)
			return
		}

		return

	case "application/xml":
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(status)

		fmt.Fprintf(w, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")

		// Handle different types of data.
		if data, ok := v.([]map[string]any); ok {
			// For an array of objects.
			fmt.Fprintf(w, "<items>\n")
			for _, item := range data {
				fmt.Fprintf(w, "  <item>\n")
				for key, val := range item {
					fmt.Fprintf(w, "    <%s>%v</%s>\n", key, val, key)
				}
				fmt.Fprintf(w, "  </item>\n")
			}
			fmt.Fprintf(w, "</items>")
		} else if data, ok := v.(map[string]any); ok {
			// For a single object.
			fmt.Fprintf(w, "<item>\n")
			for key, val := range data {
				fmt.Fprintf(w, "  <%s>%v</%s>\n", key, val, key)
			}
			fmt.Fprintf(w, "</item>")
		} else {
			// If the data type is unknown.
			http.Error(w, "Data format not suitable for XML", http.StatusInternalServerError)
			return
		}

		return

	case "application/x-www-form-urlencoded":
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.WriteHeader(status)

		var values url.Values = make(url.Values)

		if data, ok := v.(map[string]any); ok {
			for key, val := range data {
				values.Set(key, fmt.Sprintf("%v", val))
			}
		} else if data, ok := v.([]map[string]any); ok && len(data) > 0 {
			// For an array, take only the first object.
			for key, val := range data[0] {
				values.Set(key, fmt.Sprintf("%v", val))
			}
		} else {
			http.Error(w, "Data format not suitable for form-urlencoded", http.StatusInternalServerError)
			return
		}

		w.Write([]byte(values.Encode()))
		return

	default:
		// If the format is not supported, use JSON.
		respondJSON(w, status, v)
	}
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

// --- ETag Helper Functions ---

// getFirstCachePlugin retrieves the cache plugin based on configuration or fallback logic.
// Priority:
// 1. Cache plugin specified by `CacheName` in the config for the given `dbKey`.
// 2. Cache plugin with the same name as `dbKey`.
// 3. The first available cache plugin.
// Returns nil if no cache plugins are configured or loaded.
func getFirstCachePlugin(dbKey string) easyrest.CachePlugin {
	cfg := GetConfig()
	currentCachePlugins := *CachePlugins.Load()
	if len(currentCachePlugins) == 0 {
		return nil // No cache plugins available
	}

	dbPluginCfg, ok := cfg.PluginMap[dbKey]

	if !ok || !dbPluginCfg.EnableCache {
		return nil
	}

	// Priority 1: Check CacheName in the config for this dbKey
	if dbPluginCfg.CacheName != "" {
		if specifiedCachePlugin, found := currentCachePlugins[dbPluginCfg.CacheName]; found {
			return specifiedCachePlugin
		}
		// Log if specified cache plugin not found, but continue to fallback
		stdlog.Printf("WARN: Cache plugin '%s' specified for DB '%s' not found or loaded. Falling back...", dbPluginCfg.CacheName, dbKey)
	}

	// Priority 2: Try to find a cache plugin with the same name as dbKey
	if matchingCachePlugin, found := currentCachePlugins[dbKey]; found {
		return matchingCachePlugin
	}

	// Priority 3: Return the first one found (iteration order is not guaranteed)
	for _, plugin := range currentCachePlugins {
		return plugin
	}

	return nil // Should not happen if len > 0, but safeguard
}

// getOrGenerateETag fetches ETag from cache or generates a new one.
func getOrGenerateETag(cachePlugin easyrest.CachePlugin, key string) string {
	currentETag, err := cachePlugin.Get(key)
	if err == nil && currentETag != "" {
		return currentETag // Found in cache
	}

	// Not found or error occurred, generate a new one
	newETag := uuid.NewString()
	// Store the new ETag in cache (use a long TTL, e.g., 24 hours or adjust as needed)
	err = cachePlugin.Set(key, newETag, 24*time.Hour)
	if err != nil {
		// Log the error but proceed with the newly generated ETag
		stdlog.Printf("Error setting ETag in cache for key '%s': %v", key, err)
	}
	return newETag
}

// updateETag generates a new ETag and stores it in the cache.
func updateETag(cachePlugin easyrest.CachePlugin, key string) string {
	newETag := uuid.NewString()
	err := cachePlugin.Set(key, newETag, 24*time.Hour) // Use the same TTL as getOrGenerateETag
	if err != nil {
		stdlog.Printf("Error updating ETag in cache for key '%s': %v", key, err)
	}
	return newETag
}

// --- End ETag Helper Functions ---

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

// LoadPlugins loads all configured database and cache plugins.
func LoadPlugins() {
	cfg := GetConfig()
	// Create new maps for the plugins and clients
	newDbPlugins := make(map[string]easyrest.DBPlugin)
	newCachePlugins := make(map[string]easyrest.CachePlugin)
	newPluginClients := make(map[string]*hplugin.Client)

	for connName, pluginCfg := range cfg.PluginMap {
		// Determine executable path (same as before)
		splitURI := strings.SplitN(pluginCfg.Uri, "://", 2)
		if len(splitURI) != 2 {
			stdlog.Printf("Invalid URI for %s: %s", connName, pluginCfg.Uri)
			continue
		}
		pluginTypeHint := splitURI[0] // Use this only for executable name guess
		pluginExec := "easyrest-plugin-" + pluginTypeHint
		var pluginPath string
		if pluginCfg.Path != "" {
			pluginPath = pluginCfg.Path
			if strings.HasPrefix(pluginPath, "~/") {
				homeDir, err := os.UserHomeDir()
				if err != nil {
					stdlog.Printf("Error getting home directory for plugin %s: %v", connName, err)
					continue
				}
				pluginPath = filepath.Join(homeDir, pluginPath[2:])
			}
		} else {
			var err error
			pluginPath, err = findPluginPath(pluginExec)
			if err != nil {
				stdlog.Printf("Plugin executable for %s (%s or %s-os-arch) not found: %v", connName, pluginExec, pluginExec, err)
				continue
			}
		}

		absPluginPath, err := filepath.Abs(pluginPath)
		if err != nil {
			stdlog.Printf("Error getting absolute path for plugin %s (%s): %v", connName, pluginPath, err)
			continue
		}

		// Define that this plugin *might* serve db and cache interfaces
		pluginInterfaceMap := map[string]hplugin.Plugin{
			"db":    &easyrest.DBPluginPlugin{},
			"cache": &easyrest.CachePluginPlugin{},
		}

		// Configure the client
		pluginClientConfig := hplugin.ClientConfig{
			HandshakeConfig:  easyrest.Handshake,
			Plugins:          pluginInterfaceMap,
			Cmd:              exec.Command(absPluginPath),
			AllowedProtocols: []hplugin.Protocol{hplugin.ProtocolNetRPC},
		}
		if cfg.NoPluginLog {
			pluginClientConfig.Logger = hclog.New(&hclog.LoggerOptions{
				Output: io.Discard,
			})
		}

		// Create the plugin client process
		client := hplugin.NewClient(&pluginClientConfig)
		rpcClient, err := client.Client()
		if err != nil {
			stdlog.Printf("Error creating RPC client process for plugin %s (%s): %v", connName, pluginPath, err)
			client.Kill() // Kill the client process if RPC connection failed
			continue
		}

		pluginAddedSuccessfully := false
		logMsgParts := []string{} // To build the final log message

		// --- Attempt to load DB Plugin ---
		rawDB, errDBDispense := rpcClient.Dispense("db")
		if errDBDispense == nil {
			dbPlug, ok := rawDB.(easyrest.DBPlugin)
			if ok {
				errDBInit := dbPlug.InitConnection(pluginCfg.Uri)
				if errDBInit == nil {
					newDbPlugins[connName] = dbPlug
					pluginAddedSuccessfully = true
					logMsgParts = append(logMsgParts, "DB")
				} else {
					stdlog.Printf("Error initializing DB connection for plugin %s: %v", connName, errDBInit)
				}
			} else {
				// This usually indicates a programming error (plugin mismatch)
				stdlog.Printf("Error: Plugin %s (%s) dispensed 'db' but type assertion to DBPlugin failed", connName, pluginPath)
			}
		} else {
			// Only log dispense error if it's not the typical "unknown service" which means the interface isn't implemented
			if !strings.Contains(errDBDispense.Error(), "unknown service") {
				stdlog.Printf("Error dispensing 'db' interface for plugin %s: %v", connName, errDBDispense)
			}
		}

		// --- Attempt to load Cache Plugin ---
		rawCache, errCacheDispense := rpcClient.Dispense("cache")
		if errCacheDispense == nil {
			cachePlug, ok := rawCache.(easyrest.CachePlugin)
			if ok {
				errCacheInit := cachePlug.InitConnection(pluginCfg.Uri) // Use the same URI for cache init for now
				if errCacheInit == nil {
					newCachePlugins[connName] = cachePlug
					pluginAddedSuccessfully = true
					logMsgParts = append(logMsgParts, "Cache")
				} else {
					stdlog.Printf("Error initializing Cache connection for plugin %s: %v", connName, errCacheInit)
				}
			} else {
				stdlog.Printf("Error: Plugin %s (%s) dispensed 'cache' but type assertion to CachePlugin failed", connName, pluginPath)
			}
		} else {
			if !strings.Contains(errCacheDispense.Error(), "unknown service") {
				stdlog.Printf("Error dispensing 'cache' interface for plugin %s: %v", connName, errCacheDispense)
			}
		}

		// --- Finalize Client Management ---
		if pluginAddedSuccessfully {
			newPluginClients[connName] = client
			stdlog.Printf("Connection %s (%s) initialized with interfaces: [%s]", connName, pluginExec, strings.Join(logMsgParts, ", "))
		} else {
			stdlog.Printf("Connection %s (%s) failed to initialize any supported interfaces. Stopping client.", connName, pluginExec)
			client.Kill() // Kill the client if no interfaces were loaded
		}
	} // End loop over cfg.PluginMap

	// Get the pointer to the old clients map *before* swapping
	oldClientsPtr := pluginClients.Load()

	// Initialize internal fallback cache if no external cache plugins were loaded or supported the cache interface
	if len(newCachePlugins) == 0 && len(cfg.PluginMap) > 0 { // Only add internal if external were configured but none loaded/supported cache
		stdlog.Println("No external cache plugins loaded or configured plugins did not support 'cache' interface. Initializing internal fallback cache.")
		internalCache := cache.NewSimpleCachePlugin()
		if err := internalCache.InitConnection(""); err != nil { // Pass empty URI for internal
			stdlog.Printf("Error initializing internal fallback cache: %v", err)
		} else {
			// Use a distinct key for the internal cache
			internalCacheKey := "_internal_cache"
			newCachePlugins[internalCacheKey] = internalCache
			stdlog.Printf("Internal fallback cache initialized successfully under key '%s'", internalCacheKey)
		}
	} else if len(newCachePlugins) > 0 {
		stdlog.Printf("Loaded %d external cache plugin(s). Internal fallback cache not needed.", len(newCachePlugins))
	} else {
		stdlog.Println("No plugins configured, skipping cache initialization.")
	}

	// Atomically swap to the new maps
	DbPlugins.Store(&newDbPlugins)
	CachePlugins.Store(&newCachePlugins)
	pluginClients.Store(&newPluginClients)

	// Kill the old clients *after* the swap
	if oldClientsPtr != nil {
		oldClients := *oldClientsPtr
		if len(oldClients) > 0 {
			stdlog.Printf("Stopping %d old plugin client(s)...", len(oldClients))
			for _, client := range oldClients {
				client.Kill()
			}
			stdlog.Printf("Finished stopping old plugin clients.")
		}
	}
}
