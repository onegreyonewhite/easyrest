package server

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"maps"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/onegreyonewhite/easyrest/internal/config"
	cachepkg "github.com/patrickmn/go-cache"
)

type contextKey string

const TokenClaimsKey contextKey = "tokenClaims"

var (
	bearerRegex = regexp.MustCompile(`^Bearer\s+(.+)$`)
)

var httpClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		MaxConnsPerHost:     100,
		MaxIdleConnsPerHost: 100,
	},
}

// BuildPluginContext extracts context variables from the HTTP request.
func BuildPluginContext(r *http.Request) map[string]any {
	cfg := GetConfig()
	vars := mux.Vars(r)
	dbKey := vars["db"]
	dbConfig := cfg.PluginMap[dbKey]
	headers := make(map[string]any)
	for k, vals := range r.Header {
		lk := strings.ToLower(k)
		headers[lk] = strings.Join(vals, " ")
	}
	claims := getTokenClaims(r)
	plainClaims := make(map[string]any)
	for k, v := range claims {
		plainClaims[strings.ToLower(k)] = v
	}

	timezone := ""
	tx, txAllowOverride := strings.CutSuffix(dbConfig.DbTxEnd, "-allow-override")
	prefer := make(map[string]any)
	if preferStr := r.Header.Get("Prefer"); preferStr != "" {
		tokens := strings.Split(preferStr, " ")
		for _, token := range tokens {
			parts := strings.SplitN(token, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.ToLower(parts[0])
			val := parts[1]
			if key == "timezone" {
				timezone = val
			} else if key == "tx" && txAllowOverride {
				if val == "commit" || val == "rollback" {
					tx = val
				}
			}
			prefer[key] = val
		}
	}
	if timezone == "" {
		timezone = cfg.DefaultTimezone
	}

	prefer["tx"] = tx

	return map[string]any{
		"timezone":   timezone,
		"headers":    headers,
		"claims":     plainClaims,
		"jwt.claims": plainClaims,
		"method":     r.Method,
		"path":       r.URL.Path,
		"query":      r.URL.RawQuery,
		"prefer":     prefer,
	}
}

// AccessLogMiddleware logs incoming HTTP requests if enabled.
func AccessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		stdlog.Printf("ACCESS: %s %s from %s in %v", r.Method, r.RequestURI, r.RemoteAddr, time.Since(start))
	})
}

// Authenticate extracts and validates the JWT token.
func Authenticate(r *http.Request) (string, *http.Request, error) {
	authHeader := r.Header.Get("Authorization")
	config := GetConfig()
	if authHeader == "" {
		if len(config.AnonClaims) > 0 {
			claims := jwt.MapClaims{}
			maps.Copy(claims, config.AnonClaims)
			r = r.WithContext(context.WithValue(r.Context(), TokenClaimsKey, claims))
			return "", r, nil
		}
		return "", r, errors.New("missing authorization header")
	}

	matches := bearerRegex.FindStringSubmatch(authHeader)
	if len(matches) != 2 {
		return "", r, errors.New("invalid authorization header format")
	}
	tokenStr := matches[1]

	// Check cache for claims and user_id
	if claimsCache != nil {
		if cached, found := claimsCache.Get(tokenStr); found {
			if entry, ok := cached.(claimsCacheEntry); ok {
				// Set claims in context and return cached user_id
				r = r.WithContext(context.WithValue(r.Context(), TokenClaimsKey, entry.Claims))
				return entry.UserID, r, nil
			}
		}
	}

	if config.TokenSecret != "" {
		parsed, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(config.TokenSecret), nil
		})
		if err != nil || !parsed.Valid {
			return "", r, errors.New("invalid token")
		}
		claims, ok := parsed.Claims.(jwt.MapClaims)
		if !ok {
			return "", r, errors.New("invalid claims")
		}

		expTime, err := claims.GetExpirationTime()
		if err == nil && expTime != nil && expTime.Before(time.Now()) {
			return "", r, errors.New("token expired")
		}

		r = r.WithContext(context.WithValue(r.Context(), TokenClaimsKey, claims))
		userID := extractUserIDFromClaims(claims)
		// Store in cache
		if claimsCache != nil {
			claimsCache.SetDefault(tokenStr, claimsCacheEntry{Claims: claims, UserID: userID})
		}
		return userID, r, nil
	}

	tokenURL := os.Getenv("ER_TOKEN_URL")
	if tokenURL != "" {
		req, err := http.NewRequestWithContext(r.Context(), "GET", tokenURL, nil)
		if err != nil {
			return "", r, fmt.Errorf("error creating request: %v", err)
		}
		q := req.URL.Query()
		q.Add("access_token", tokenStr)
		req.URL.RawQuery = q.Encode()

		resp, err := httpClient.Do(req)
		if err != nil {
			return "", r, errors.New("error validating token")
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return "", r, errors.New("invalid token (via URL)")
		}

		var authResponse map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
			return "", r, errors.New("invalid response from auth server")
		}

		claims := jwt.MapClaims(authResponse)
		r = r.WithContext(context.WithValue(r.Context(), TokenClaimsKey, claims))
		userID := extractUserIDFromClaims(claims)
		// Store in cache
		if claimsCache != nil {
			claimsCache.SetDefault(tokenStr, claimsCacheEntry{Claims: claims, UserID: userID})
		}
		return userID, r, nil
	}

	claims, err := DecodeTokenWithoutValidation(tokenStr)
	if err != nil {
		return "", r, err
	}

	expTime, err := claims.GetExpirationTime()
	if err == nil && expTime != nil && expTime.Before(time.Now()) {
		return "", r, errors.New("token expired")
	}

	r = r.WithContext(context.WithValue(r.Context(), TokenClaimsKey, claims))
	userID := extractUserIDFromClaims(claims)
	// Store in cache
	if claimsCache != nil {
		claimsCache.SetDefault(tokenStr, claimsCacheEntry{Claims: claims, UserID: userID})
	}
	return userID, r, nil
}

// proxyHeadersHandler wraps the original handler to process X-Forwarded-* headers
func proxyHeadersHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Process X-Forwarded-* headers
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			r.URL.Scheme = proto
		} else if proto := r.Header.Get("X-Forwarded-Protocol"); proto != "" {
			r.URL.Scheme = proto
		}
		if host := r.Header.Get("X-Forwarded-Host"); host != "" {
			r.Host = host
		}
		if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
			// Take the first IP if multiple are present
			ips := strings.Split(ip, ",")
			r.RemoteAddr = strings.TrimSpace(ips[0])
		}
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware handles CORS headers based on configuration
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := GetConfig()
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range cfg.CORS.Origins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(cfg.CORS.Methods, ", "))
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(cfg.CORS.Headers, ", "))
			w.Header().Set("Access-Control-Max-Age", strconv.Itoa(cfg.CORS.MaxAge))
		}

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// healthHandler returns OK for health checks.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// SetupRouter initializes the router and endpoints.
func SetupRouter() *mux.Router {
	cfg := GetConfig()
	// Initialize claims cache with default expiration and cleanup interval
	if claimsCache == nil && cfg.TokenCacheTTL >= 0 {
		defaultExpiration := time.Duration(cfg.TokenCacheTTL) * time.Second
		cleanupInterval := time.Duration(cfg.TokenCacheTTL) * time.Second * 10
		claimsCache = cachepkg.New(defaultExpiration, cleanupInterval)
	}
	LoadPlugins()
	r := mux.NewRouter()

	// Add CORS middleware first
	if cfg.CORS.Enabled {
		r.Use(corsMiddleware)
	}

	// Add proxy headers handler
	r.Use(proxyHeadersHandler)

	// Schema endpoint.
	r.HandleFunc("/api/{db}/", schemaHandler).Methods("GET")
	// Call RPC function endpoint.
	r.HandleFunc("/api/{db}/rpc/{func}/", rpcHandler).Methods("POST")
	// Call table endpoint.
	r.HandleFunc("/api/{db}/{table}/", tableHandler)
	// Add health check endpoint.
	r.HandleFunc("/health", healthHandler).Methods("GET")
	return r
}

// Run starts the HTTP server.
func Run(conf config.Config) {
	SetConfig(conf)
	router := SetupRouter()
	if conf.AccessLogOn {
		router.Use(AccessLogMiddleware)
	}

	// Create server with optimized settings
	srv := &http.Server{
		Addr:              ":" + conf.Port,
		Handler:           router,
		ReadTimeout:       conf.Server.ReadTimeout,
		WriteTimeout:      conf.Server.WriteTimeout,
		IdleTimeout:       conf.Server.IdleTimeout,
		MaxHeaderBytes:    conf.Server.MaxHeaderBytes,
		ReadHeaderTimeout: conf.Server.ReadHeaderTimeout,
		ConnState: func(conn net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				// Set TCP keepalive
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					tcpConn.SetKeepAlive(true)
					tcpConn.SetKeepAlivePeriod(conf.Server.KeepAlivePeriod)
				}
			case http.StateIdle:
				// Clear buffers when idle
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					tcpConn.SetReadBuffer(0)
					tcpConn.SetWriteBuffer(0)
				}
			}
		},
	}

	h2s := &http2.Server{
		MaxConcurrentStreams:         conf.Server.HTTP2MaxConcurrentStreams,
		MaxReadFrameSize:             conf.Server.HTTP2MaxReadFrameSize,
		MaxUploadBufferPerConnection: conf.Server.HTTP2MaxUploadBufferPerConnection,
		MaxUploadBufferPerStream:     conf.Server.HTTP2MaxUploadBufferPerStream,
		IdleTimeout:                  conf.Server.HTTP2IdleTimeout,
		ReadIdleTimeout:              conf.Server.HTTP2ReadIdleTimeout,
		PingTimeout:                  conf.Server.HTTP2PingTimeout,
		PermitProhibitedCipherSuites: conf.Server.HTTP2PermitProhibitedCipherSuites,
	}

	// Create context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Run server in a goroutine
	go func() {
		if conf.TLSEnabled {
			http2.ConfigureServer(srv, h2s)
			stdlog.Printf("TLS server listening on port %s...", conf.Port)
			if err := srv.ListenAndServeTLS(conf.TLSCertFile, conf.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				stdlog.Fatalf("Server error: %v", err)
			}
		} else {
			stdlog.Printf("Server listening on port %s...", conf.Port)
			srv.Handler = h2c.NewHandler(router, h2s)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				stdlog.Fatalf("Server error: %v", err)
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-sigChan
		if sig == syscall.SIGHUP {
			stdlog.Println("Received SIGHUP - reloading configuration")
			ReloadConfig()
			LoadPlugins()
		} else {
			stdlog.Printf("Received signal %v - shutting down the server", sig)
			if err := srv.Shutdown(ctx); err != nil {
				stdlog.Printf("Forced server shutdown due to error: %v", err)
			}
			StopPlugins()
			break
		}
	}

	stdlog.Println("Server exiting")
}
