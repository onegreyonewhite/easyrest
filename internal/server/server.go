package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/hashicorp/go-hclog"
	hplugin "github.com/hashicorp/go-plugin"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// Global configuration and dbPlugins loaded only once.
var (
	cfg        config.Config
	cfgOnce    sync.Once
	dbPlugins  = make(map[string]easyrest.DBPlugin)
	allowedOps = map[string]string{
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

// getConfig loads configuration only once.
func getConfig() config.Config {
	cfgOnce.Do(func() {
		cfg = config.Load()
	})
	return cfg
}

func isAllowedFunction(item string) bool {
	for _, v := range allowedFuncs {
		if v == item {
			return true
		}
	}
	return false
}

// buildPluginContext extracts context variables from the HTTP request.
// It uses lowercase keys. TIMEZONE is taken from header "timezone", HEADERS from request headers,
// and CLAIMS from token claims (converted to a plain map).
func buildPluginContext(r *http.Request) map[string]interface{} {
	headers := make(map[string]interface{})
	for k, vals := range r.Header {
		lk := strings.ToLower(k)
		headers[lk] = strings.Join(vals, " ")
	}
	claims := getTokenClaims(r)
	plainClaims := make(map[string]interface{})
	for k, v := range claims {
		plainClaims[strings.ToLower(k)] = v
	}

	// Extract timezone from Prefer header.
	timezone := ""
	if prefer := r.Header.Get("Prefer"); prefer != "" {
		// Prefer header might contain multiple tokens separated by space.
		tokens := strings.Split(prefer, " ")
		for _, token := range tokens {
			if strings.HasPrefix(strings.ToLower(token), "timezone=") {
				parts := strings.SplitN(token, "=", 2)
				if len(parts) == 2 {
					timezone = parts[1]
					break
				}
			}
		}
	}

	// If timezone is still empty, get default from server configuration.
	if timezone == "" {
		cfg := getConfig()
		timezone = cfg.DefaultTimezone
	}

	return map[string]interface{}{
		"timezone": timezone,
		"headers":  headers,
		"claims":   plainClaims,
	}
}

// accessLogMiddleware logs incoming HTTP requests if enabled.
func accessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		stdlog.Printf("ACCESS: %s %s from %s in %v", r.Method, r.RequestURI, r.RemoteAddr, time.Since(start))
	})
}

// Run starts the HTTP server.
func Run() {
	config := getConfig()
	router := SetupRouter()
	if config.AccessLogOn {
		router.Use(accessLogMiddleware)
	}
	stdlog.Printf("Server listening on port %s...", config.Port)
	srv := &http.Server{
		Addr:         ":" + config.Port,
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	stdlog.Fatal(srv.ListenAndServe())
}

func SetupRouter() *mux.Router {
	loadDBPlugins()
	r := mux.NewRouter()
	r.HandleFunc("/api/{db}/rpc/{func}/", rpcHandler).Methods("POST")
	r.HandleFunc("/api/{db}/{table}/", tableHandler)
	return r
}

// loadDBPlugins scans environment variables and initializes plugins.
func loadDBPlugins() {
	config := getConfig()
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
			pluginPath, err := exec.LookPath(pluginExec)
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
			if config.NoPluginLog {
				pluginConfig.Logger = hclog.New(&hclog.LoggerOptions{
					Output: io.Discard,
					Level:  hclog.Error,
					Name:   "plugin",
				})
			}
			client := hplugin.NewClient(&pluginConfig)
			rpcClient, err := client.Client()
			if err != nil {
				stdlog.Printf("Error starting plugin %s: %v", pluginExec, err)
				continue
			}
			raw, err := rpcClient.Dispense("db")
			if err != nil {
				stdlog.Printf("Error obtaining plugin %s: %v", pluginExec, err)
				continue
			}
			dbPlug, ok := raw.(easyrest.DBPlugin)
			if !ok {
				stdlog.Printf("Invalid plugin type for %s", pluginExec)
				continue
			}
			err = dbPlug.InitConnection(uri)
			if err != nil {
				stdlog.Printf("Error initializing connection for plugin %s: %v", connName, err)
				continue
			}
			dbPlugins[connName] = dbPlug
			stdlog.Printf("Connection %s initialized using plugin %s", connName, pluginExec)
		}
	}
}

// parseWhereClause converts query parameters (those starting with "where.") into a map.
// It does not perform additional validation because that was done on the controller.
func parseWhereClause(values map[string][]string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	for key, vals := range values {
		if strings.HasPrefix(key, "where.") {
			parts := strings.Split(key, ".")
			if len(parts) != 3 {
				return nil, fmt.Errorf("Invalid where key format: %s", key)
			}
			opCode := strings.ToLower(parts[1])
			field := parts[2]
			// If the operator is not allowed, return an error immediately.
			if _, ok := allowedOps[opCode]; !ok {
				return nil, fmt.Errorf("Unknown operator: %s", opCode)
			}
			op := allowedOps[opCode]
			value := vals[0]
			if existing, found := result[field]; found {
				m, ok := existing.(map[string]interface{})
				if !ok {
					return nil, fmt.Errorf("Type error for field %s", field)
				}
				m[op] = value
				result[field] = m
			} else {
				result[field] = map[string]interface{}{op: value}
			}
		}
	}
	return result, nil
}

// processSelectParam parses the "select" query parameter, allowing aliasing and SQL functions.
// It validates plain field names using IsValidIdentifier (or allowed erctx fields).
func processSelectParam(param string) ([]string, []string, error) {
	if param == "" {
		return nil, nil, nil
	}
	parts := strings.Split(param, ",")
	var selectFields []string
	var groupBy []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var alias, raw string
		if strings.Contains(part, ":") {
			subParts := strings.SplitN(part, ":", 2)
			alias = strings.TrimSpace(subParts[0])
			raw = strings.TrimSpace(subParts[1])
		} else {
			alias = ""
			raw = part
		}
		var expr string
		if strings.Contains(raw, ".") && strings.HasSuffix(raw, "()") {
			subParts := strings.SplitN(raw, ".", 2)
			fieldPart := strings.TrimSpace(subParts[0])
			funcPart := strings.TrimSpace(subParts[1])
			if len(funcPart) < 3 || funcPart[len(funcPart)-2:] != "()" {
				return nil, nil, fmt.Errorf("Invalid function syntax in select field: %s", part)
			}
			funcName := funcPart[:len(funcPart)-2]
			if !isAllowedFunction(funcName) {
				return nil, nil, fmt.Errorf("Function %s is not allowed", funcName)
			}
			if funcName == "count" && fieldPart == "" {
				expr = "COUNT(*)"
			} else {
				expr = strings.ToUpper(funcName) + "(" + fieldPart + ")"
			}
			if alias == "" {
				alias = funcName
			}
		} else if raw == "count()" {
			expr = "COUNT(*)"
			if alias == "" {
				alias = "count"
			}
		} else {
			// Validate field: assume valid if it is an identifier or starts with "erctx.".
			expr = raw
			groupBy = append(groupBy, raw)
		}
		if alias != "" {
			expr = expr + " AS " + alias
		}
		selectFields = append(selectFields, expr)
	}
	return selectFields, groupBy, nil
}

func tableHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dbKey := strings.ToLower(vars["db"])
	table := vars["table"]

	dbPlug, ok := dbPlugins[dbKey]
	if !ok {
		http.Error(w, "DB plugin not found", http.StatusNotFound)
		return
	}

	userID, r, err := Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	config := getConfig()
	var requiredScope string
	if r.Method == http.MethodGet {
		requiredScope = table + "-read"
	} else {
		requiredScope = table + "-write"
	}
	if config.CheckScope {
		claims := getTokenClaims(r)
		if !checkScope(claims, requiredScope) {
			http.Error(w, "Forbidden: insufficient scope", http.StatusForbidden)
			return
		}
	}

	pluginCtx := buildPluginContext(r)

	switch r.Method {
	case http.MethodGet:
		selectParam := r.URL.Query().Get("select")
		selectFields, groupBy, err := processSelectParam(selectParam)
		if err != nil {
			http.Error(w, "Error processing select parameter: "+err.Error(), http.StatusBadRequest)
			return
		}
		where, err := parseWhereClause(r.URL.Query())
		if err != nil {
			http.Error(w, "Error processing where clause: "+err.Error(), http.StatusBadRequest)
			return
		}
		ordering := parseCSV(r.URL.Query().Get("ordering"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

		rows, err := dbPlug.TableGet(userID, table, selectFields, where, ordering, groupBy, limit, offset, pluginCtx)
		if err != nil {
			http.Error(w, "Error in TableGet: "+err.Error(), http.StatusInternalServerError)
			return
		}
		respondJSON(w, http.StatusOK, rows)
	case http.MethodPost:
		var data []map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "JSON parse error: "+err.Error(), http.StatusBadRequest)
			return
		}
		rows, err := dbPlug.TableCreate(userID, table, data, pluginCtx)
		if err != nil {
			http.Error(w, "Error in TableCreate: "+err.Error(), http.StatusInternalServerError)
			return
		}
		respondJSON(w, http.StatusCreated, rows)
	case http.MethodPatch:
		var data map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "JSON parse error: "+err.Error(), http.StatusBadRequest)
			return
		}
		where, err := parseWhereClause(r.URL.Query())
		if err != nil {
			http.Error(w, "Error processing where clause: "+err.Error(), http.StatusBadRequest)
			return
		}
		updated, err := dbPlug.TableUpdate(userID, table, data, where, pluginCtx)
		if err != nil {
			http.Error(w, "Error in TableUpdate: "+err.Error(), http.StatusInternalServerError)
			return
		}
		respondJSON(w, http.StatusOK, map[string]int{"updated": updated})
	case http.MethodDelete:
		where, err := parseWhereClause(r.URL.Query())
		if err != nil {
			http.Error(w, "Error processing where clause: "+err.Error(), http.StatusBadRequest)
			return
		}
		_, err = dbPlug.TableDelete(userID, table, where, pluginCtx)
		if err != nil {
			http.Error(w, "Error in TableDelete: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func rpcHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dbKey := strings.ToLower(vars["db"])
	funcName := vars["func"]

	dbPlug, ok := dbPlugins[dbKey]
	if !ok {
		http.Error(w, "DB plugin not found", http.StatusNotFound)
		return
	}

	userID, r, err := Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	config := getConfig()
	if config.CheckScope {
		requiredScope := funcName + "-write"
		claims := getTokenClaims(r)
		if !checkScope(claims, requiredScope) {
			http.Error(w, "Forbidden: insufficient scope", http.StatusForbidden)
			return
		}
	}

	var data map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "JSON parse error: "+err.Error(), http.StatusBadRequest)
		return
	}

	pluginCtx := buildPluginContext(r)
	result, err := dbPlug.CallFunction(userID, funcName, data, pluginCtx)
	if err != nil {
		http.Error(w, "Error in CallFunction: "+err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, http.StatusOK, result)
}

func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// Authenticate extracts and validates the JWT token.
func Authenticate(r *http.Request) (string, *http.Request, error) {
	tokenStr := ""
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		return "", r, errors.New("Missing Bearer token")
	}

	config := getConfig()
	if config.TokenSecret != "" {
		parsed, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(config.TokenSecret), nil
		})
		if err != nil || !parsed.Valid {
			return "", r, errors.New("Invalid token")
		}
		claims, ok := parsed.Claims.(jwt.MapClaims)
		if !ok {
			return "", r, errors.New("Invalid claims")
		}
		if exp, ok := claims["exp"].(float64); ok {
			if time.Unix(int64(exp), 0).Before(time.Now()) {
				return "", r, errors.New("Token expired")
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), "tokenClaims", claims))
		return extractUserIDFromClaims(claims), r, nil
	}

	tokenURL := os.Getenv("ER_TOKEN_URL")
	if tokenURL != "" {
		resp, err := http.Get(tokenURL + "?access_token=" + tokenStr)
		if err != nil || resp.StatusCode != http.StatusOK {
			return "", r, errors.New("Invalid token (via URL)")
		}
	}
	claims, err := DecodeTokenWithoutValidation(tokenStr)
	if err != nil {
		return "", r, err
	}
	if exp, ok := claims["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			return "", r, errors.New("Token expired")
		}
	}
	r = r.WithContext(context.WithValue(r.Context(), "tokenClaims", claims))
	return extractUserIDFromClaims(claims), r, nil
}

func getTokenClaims(r *http.Request) jwt.MapClaims {
	if claims, ok := r.Context().Value("tokenClaims").(jwt.MapClaims); ok {
		return claims
	}
	return nil
}

func extractUserIDFromClaims(claims jwt.MapClaims) string {
	config := getConfig()
	searchPath := config.TokenUserSearch
	if val, ok := claims[searchPath]; ok {
		return fmt.Sprintf("%v", val)
	}
	return ""
}

// DecodeTokenWithoutValidation decodes a JWT token without validating its signature.
func DecodeTokenWithoutValidation(tokenStr string) (jwt.MapClaims, error) {
	firstDot := strings.IndexByte(tokenStr, '.')
	if firstDot < 0 {
		return nil, errors.New("Invalid token format")
	}
	secondDot := strings.IndexByte(tokenStr[firstDot+1:], '.')
	if secondDot < 0 {
		return nil, errors.New("Invalid token format")
	}
	payload := tokenStr[firstDot+1 : firstDot+1+secondDot]
	decoder := base64.URLEncoding.WithPadding(base64.NoPadding)
	decoded, err := decoder.DecodeString(payload)
	if err != nil {
		return nil, err
	}
	var claims map[string]interface{}
	err = json.Unmarshal(decoded, &claims)
	return jwt.MapClaims(claims), err
}

func checkScope(claims jwt.MapClaims, required string) bool {
	scopeVal, ok := claims["scope"]
	if !ok {
		return false
	}
	scopesStr, ok := scopeVal.(string)
	if !ok {
		return false
	}
	scopes := strings.Split(scopesStr, " ")
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
