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

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/go-hclog"
	hplugin "github.com/hashicorp/go-plugin"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// Global configuration and dbPlugins loaded only once.
var (
	cfg           config.Config
	cfgOnce       sync.Once
	DbPlugins     atomic.Pointer[map[string]easyrest.DBPlugin]
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
	cfg = config.Load()
}

func StopDBPlugins() {
	// Get the current clients map pointer
	oldClientsPtr := pluginClients.Load()

	// Atomically set empty maps
	emptyDbPlugins := make(map[string]easyrest.DBPlugin)
	DbPlugins.Store(&emptyDbPlugins)
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
				Items []map[string]interface{} `xml:"item"`
			}
			if err := xml.NewDecoder(r.Body).Decode(&result); err != nil {
				return nil, fmt.Errorf("XML parse error: %w", err)
			}
			return result.Items, nil
		} else {
			// For XML, a root element is required.
			var wrapper struct {
				Data map[string]interface{} `xml:",any"`
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
func makeResponse(w http.ResponseWriter, r *http.Request, status int, v interface{}) {
	// Determine output format based on the Accept header
	acceptHeader := r.Header.Get("Accept")
	contentType := r.Header.Get("Content-Type")

	// If Accept is not set or equals */*, use Content-Type
	if acceptHeader == "" || acceptHeader == "*/*" {
		acceptHeader = contentType
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

		encoder := xml.NewEncoder(w)
		encoder.Indent("", "  ")

		// Wrap the data in a root element.
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
	// Create new maps for the plugins and clients
	newDbPlugins := make(map[string]easyrest.DBPlugin)
	newPluginClients := make(map[string]*hplugin.Client)

	for connName, pluginCfg := range cfg.PluginMap {
		splitURI := strings.SplitN(pluginCfg.Uri, "://", 2)
		if len(splitURI) != 2 {
			stdlog.Printf("Invalid URI for %s: %s", connName, pluginCfg.Uri)
			continue
		}
		pluginType := splitURI[0]
		pluginExec := "easyrest-plugin-" + pluginType
		var pluginPath string
		if pluginCfg.Path != "" {
			pluginPath = pluginCfg.Path
			stdlog.Printf("Plugin path from config: %s\n", pluginPath)
			if strings.HasPrefix(pluginPath, "~/") {
				homeDir, err := os.UserHomeDir()
				if err != nil {
					stdlog.Printf("Error getting home directory: %v", err)
					continue
				}
				pluginPath = filepath.Join(homeDir, pluginPath[2:])
			}
		} else {
			pluginFindedPath, err := findPluginPath(pluginExec)

			if err != nil {
				stdlog.Printf("Plugin %s not found: %v", pluginExec, err)
				continue
			} else {
				pluginPath = pluginFindedPath
			}
		}

		absPluginPath, err := filepath.Abs(pluginPath)
		if err != nil {
			stdlog.Printf("Error getting absolute path for plugin %s: %v", pluginExec, err)
			continue
		}

		var Plugins map[string]hplugin.Plugin
		if pluginCfg.Type == "db" {
			Plugins = map[string]hplugin.Plugin{
				"db": &easyrest.DBPluginPlugin{},
			}
		} else {
			stdlog.Printf("Plugin type %s not supported", pluginCfg.Type)
			continue
		}

		pluginConfig := hplugin.ClientConfig{
			HandshakeConfig:  easyrest.Handshake,
			Plugins:          Plugins,
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
			client.Kill()
			continue
		}
		raw, err := rpcClient.Dispense("db")
		if err != nil {
			stdlog.Printf("Error dispensing plugin %s: %v", connName, err)
			client.Kill()
			continue
		}
		dbPlug, ok := raw.(easyrest.DBPlugin)
		if !ok {
			stdlog.Printf("Error: plugin %s does not implement DBPlugin interface", connName)
			client.Kill()
			continue
		}
		err = dbPlug.InitConnection(pluginCfg.Uri)
		if err != nil {
			stdlog.Printf("Error initializing connection for plugin %s: %v", connName, err)
			client.Kill()
			continue
		}
		newDbPlugins[connName] = dbPlug
		newPluginClients[connName] = client
		stdlog.Printf("Connection %s initialized using plugin %s", connName, pluginExec)
	}

	// Get the pointer to the old clients map *before* swapping
	oldClientsPtr := pluginClients.Load()

	// Atomically swap to the new maps
	DbPlugins.Store(&newDbPlugins)
	pluginClients.Store(&newPluginClients)

	// Kill the old clients *after* the swap
	if oldClientsPtr != nil {
		oldClients := *oldClientsPtr
		if len(oldClients) > 0 {
			stdlog.Printf("Stopping %d old plugin client(s)...", len(oldClients))
			for connName, client := range oldClients {
				stdlog.Printf("Stopping old plugin client for connection: %s", connName)
				client.Kill()
			}
			stdlog.Printf("Finished stopping old plugin clients.")
		}
	}
}
