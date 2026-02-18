package server

import (
	"context"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"maps"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/onegreyonewhite/easyrest/internal/config"
	cachepkg "github.com/patrickmn/go-cache"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/zipkin"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

type contextKey string

const TokenClaimsKey contextKey = "tokenClaims"

// BuildPluginContext extracts context variables from the HTTP request.
func BuildPluginContext(r *http.Request) map[string]any {
	cfg := GetConfig()
	dbKey := chi.URLParam(r, "db")
	dbConfig := cfg.PluginMap[dbKey]
	headers := make(map[string]any, len(r.Header))
	for k, vals := range r.Header {
		lk := strings.ToLower(k)
		headers[lk] = strings.Join(vals, " ")
	}
	claims := getTokenClaims(r)
	plainClaims := make(map[string]any, len(claims))
	for k, v := range claims {
		plainClaims[strings.ToLower(k)] = v
	}

	timezone := ""
	tx, txAllowOverride := strings.CutSuffix(dbConfig.DbTxEnd, "-allow-override")
	prefer := make(map[string]any)
	if preferStr := r.Header.Get("Prefer"); preferStr != "" {
		tokens := strings.SplitSeq(preferStr, " ")
		for token := range tokens {
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

	pluginCtx := map[string]any{
		"timezone":   timezone,
		"headers":    headers,
		"claims":     plainClaims,
		"jwt.claims": plainClaims,
		"method":     r.Method,
		"path":       r.URL.Path,
		"query":      r.URL.RawQuery,
		"prefer":     prefer,
	}
	if cfg.Otel.Enabled {
		carrier := propagation.HeaderCarrier(r.Header)
		traceparent := carrier.Get("traceparent")
		if traceparent != "" {
			pluginCtx["traceparent"] = traceparent
			pluginCtx["otelHost"] = cfg.Otel.Endpoint
			pluginCtx["otelProtocol"] = cfg.Otel.Protocol
			pluginCtx["otelServiceName"] = cfg.Otel.ServiceName
		}
	}
	if role, ok := plainClaims["role"].(string); ok && role != "" {
		pluginCtx["role"] = role
	}
	return pluginCtx
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
	authHeaderValue := r.Header.Get("Authorization")
	config := GetConfig()

	// Check cache for claims and user_id using the raw Authorization header value as key
	if claimsCache != nil && authHeaderValue != "" {
		if cached, found := claimsCache.Get(authHeaderValue); found {
			if entry, ok := cached.(claimsCacheEntry); ok {
				// Set claims in context and return cached user_id
				r = r.WithContext(context.WithValue(r.Context(), TokenClaimsKey, entry.Claims))
				return entry.UserID, r, nil
			}
		}
	}

	authPlugins := AuthPlugins.Load()
	claims := jwt.MapClaims{}
	authorized := false
	var authErr error

	// Prepare headers map for plugins
	headersForPlugin := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		headersForPlugin[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	pluginMethod := r.Method
	pluginPath := r.URL.Path
	pluginQuery := r.URL.RawQuery

	for pluginName, plugin := range *authPlugins {
		pluginClaims, err := plugin.Authenticate(headersForPlugin, pluginMethod, pluginPath, pluginQuery)
		if err == nil {
			maps.Copy(claims, pluginClaims)
			authorized = true
			break
		}
		authErr = fmt.Errorf("plugin %s: %w", pluginName, err)
	}

	if !authorized {
		if len(config.AnonClaims) > 0 {
			claims := jwt.MapClaims{}
			maps.Copy(claims, config.AnonClaims)
			r = r.WithContext(context.WithValue(r.Context(), TokenClaimsKey, claims))
			return "", r, nil
		}
		return "", r, fmt.Errorf("authentication failed: %w", authErr)
	}

	r = r.WithContext(context.WithValue(r.Context(), TokenClaimsKey, claims))
	userID := extractUserIDFromClaims(claims)
	// Store in cache using the raw Authorization header value as key
	if claimsCache != nil {
		claimsCache.SetDefault(authHeaderValue, claimsCacheEntry{Claims: claims, UserID: userID})
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
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		} else if len(origin) > 1024 {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		cfg := GetConfig()
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
func SetupRouter() chi.Router {
	cfg := GetConfig()
	// Initialize claims cache with default expiration and cleanup interval
	if claimsCache == nil && cfg.TokenCacheTTL >= 0 {
		defaultExpiration := time.Duration(cfg.TokenCacheTTL) * time.Second
		cleanupInterval := time.Duration(cfg.TokenCacheTTL) * time.Second * 10
		claimsCache = cachepkg.New(defaultExpiration, cleanupInterval)
	}
	LoadPlugins()
	r := chi.NewRouter()

	// Add CORS middleware first
	if cfg.CORS.Enabled {
		r.Use(corsMiddleware)
	}

	// Add proxy headers handler
	r.Use(proxyHeadersHandler)

	r.Use(middleware.GetHead)
	r.Use(middleware.Recoverer)

	// Schema endpoint.
	r.Get("/api/{db}/", schemaHandler)
	// Call RPC function endpoint.
	r.Post("/api/{db}/rpc/{func}/", rpcHandler)
	// Call table endpoint (supports multiple methods inside handler).
	r.HandleFunc("/api/{db}/{table}/", tableHandler)
	// Add health check endpoint.
	r.Get("/health", healthHandler)
	return r
}

func InitOtel(otelCfg config.OtelConfig) (shutdown func(context.Context) error, err error) {
	var exp sdktrace.SpanExporter
	switch otelCfg.Protocol {
	case "otlp":
		exp, err = otlptracegrpc.New(context.Background(), otlptracegrpc.WithEndpoint(otelCfg.Endpoint), otlptracegrpc.WithInsecure())
	case "otlphttp":
		exp, err = otlptracehttp.New(context.Background(), otlptracehttp.WithEndpoint(otelCfg.Endpoint))
	case "zipkin":
		exp, err = zipkin.New(otelCfg.Endpoint)
	default:
		return nil, fmt.Errorf("unsupported otel protocol: %s", otelCfg.Protocol)
	}
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(otelCfg.ServiceName),
		)),
	)
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}

// Run starts the HTTP server.
func Run(conf config.Config) {
	SetConfig(conf)
	var otelShutdown func(context.Context) error
	if conf.Otel.Enabled {
		var err error
		otelShutdown, err = InitOtel(conf.Otel)
		if err != nil {
			stdlog.Printf("Failed to initialize OpenTelemetry: %v", err)
		}
	}
	router := SetupRouter()
	var handler http.Handler = router
	if conf.AccessLogOn {
		handler = AccessLogMiddleware(handler)
	}
	if otelShutdown != nil {
		handler = otelhttp.NewHandler(handler, "server-request")
	}

	// Create server with optimized settings
	srv := &http.Server{
		Addr:              ":" + conf.Port,
		Handler:           handler,
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
			srv.Handler = h2c.NewHandler(handler, h2s)
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

	// graceful shutdown OpenTelemetry
	if otelShutdown != nil {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		if err := otelShutdown(ctx2); err != nil {
			stdlog.Printf("Error shutting down OpenTelemetry: %v", err)
		}
	}

	stdlog.Println("Server exiting")
}
