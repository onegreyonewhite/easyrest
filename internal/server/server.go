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
	"sync/atomic"
	"syscall"
	"time"

	"maps"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	cachepkg "github.com/patrickmn/go-cache"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	"go.opentelemetry.io/otel/trace"
)

type contextKey string

// routeMount adds routes on every router build, including a SIGHUP reload.
type routeMount func(chi.Router)

var routeHook atomic.Pointer[routeMount]

// SetRoutes stores the function buildRouter calls after the built-in routes.
// A nil mount clears the hook. The function runs again on every rebuild.
func SetRoutes(mount func(chi.Router)) {
	if mount == nil {
		routeHook.Store(nil)
		return
	}
	wrapped := routeMount(mount)
	routeHook.Store(&wrapped)
}

const TokenClaimsKey contextKey = "tokenClaims"
const requestPluginHeadersKey contextKey = "pluginHeaders"

func buildRequestHeaderMaps(h http.Header) (map[string]string, map[string]any) {
	authHeaders := make(map[string]string, len(h))
	pluginHeaders := make(map[string]any, len(h))
	for k, vals := range h {
		lk := strings.ToLower(k)
		if len(vals) == 1 {
			authHeaders[lk] = vals[0]
			pluginHeaders[lk] = vals[0]
			continue
		}
		if lk == "cookie" {
			authHeaders[lk] = strings.Join(vals, ", ")
			pluginHeaders[lk] = strings.Join(vals, "; ")
			continue
		}
		authHeaders[lk] = strings.Join(vals, ", ")
		pluginHeaders[lk] = strings.Join(vals, " ")
	}
	return authHeaders, pluginHeaders
}

func pluginHeadersFromRequest(r *http.Request) map[string]any {
	if headers, ok := r.Context().Value(requestPluginHeadersKey).(map[string]any); ok && headers != nil {
		return headers
	}
	_, pluginHeaders := buildRequestHeaderMaps(r.Header)
	return pluginHeaders
}

// BuildPluginContext extracts context variables from the HTTP request.
func BuildPluginContext(r *http.Request) map[string]any {
	return buildPluginContext(r, strings.ToLower(chi.URLParam(r, "db")), chi.URLParam(r, "table"), chi.URLParam(r, "func"))
}

func buildPluginContext(r *http.Request, dbKey, table, fn string) map[string]any {
	cfg := currentConfig()
	dbKey = strings.ToLower(dbKey)
	dbConfig := cfg.PluginMap[dbKey]
	headers := pluginHeadersFromRequest(r)
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
	if _, ok := prefer["count"]; !ok && knownCountMode(dbConfig.DbPreferCount) {
		prefer["count"] = dbConfig.DbPreferCount
	}

	pluginCtx := make(map[string]any, 15+len(r.Cookies()))
	pluginCtx["timezone"] = timezone
	pluginCtx["headers"] = headers
	pluginCtx["claims"] = plainClaims
	pluginCtx["jwt.claims"] = plainClaims
	pluginCtx["method"] = r.Method
	pluginCtx["path"] = r.URL.Path
	pluginCtx["query"] = r.URL.RawQuery
	pluginCtx["prefer"] = prefer
	pluginCtx["db_max_rows"] = dbConfig.DbMaxRows
	if table != "" {
		pluginCtx[easyrest.CtxTable] = table
	}
	if fn != "" {
		pluginCtx[easyrest.CtxFunction] = fn
	}
	// Add cookies as individual keys "cookie.[name]"
	for _, c := range r.Cookies() {
		pluginCtx["cookie."+c.Name] = c.Value
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
	clientIP := middleware.GetClientIP(r.Context())
	if clientIP == "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil {
			clientIP = host
		} else {
			clientIP = r.RemoteAddr
		}
	}
	pluginCtx["client_ip"] = clientIP
	pluginCtx[easyrest.CtxDBType] = easyrest.DBTypeFromURI(dbConfig.Uri)
	pluginCtx["request"] = requestPublic(r)
	if internalCall(r) {
		if id := r.Header.Get(sharedTxHeader); id != "" {
			pluginCtx[easyrest.SharedTxKey] = id
		}
	}
	return pluginCtx
}

func requestPublic(r *http.Request) map[string]any {
	forwarded := forwardedParams(r.Header.Get("Forwarded"))
	// tls_enabled is the public scheme for this listener. A server request leaves URL.Scheme empty, and a proxy proto must not change it.
	var scheme string
	if currentConfig().TLSEnabled {
		scheme = "https"
	} else {
		scheme = firstHeaderToken(r.Header.Get("X-Forwarded-Proto"))
		if scheme == "" {
			scheme = forwarded["proto"]
		}
		if scheme == "" {
			scheme = r.URL.Scheme
		}
		if scheme == "" {
			scheme = "http"
		}
	}
	host := firstHeaderToken(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = forwarded["host"]
	}
	if host == "" {
		host = r.Header.Get("Host")
	}
	if host == "" {
		host = r.Host
	}
	request := map[string]any{
		"scheme": scheme,
		"host":   host,
		"prefix": requestPrefix(r.Header.Get("X-Forwarded-Prefix")),
	}
	if value := r.Header.Get("X-Forwarded-For"); value != "" {
		request["forwarded_for"] = value
	}
	if value := r.Header.Get("X-Real-IP"); value != "" {
		request["real_ip"] = value
	}
	if value := r.Header.Get("Via"); value != "" {
		request["via"] = value
	}
	return request
}

func requestPrefix(value string) string {
	prefix := strings.Trim(strings.TrimSpace(value), "/")
	if prefix == "" {
		return ""
	}
	return "/" + prefix
}

func firstHeaderToken(value string) string {
	token, _, _ := strings.Cut(value, ",")
	return strings.TrimSpace(token)
}

func forwardedParams(header string) map[string]string {
	element, _, _ := strings.Cut(header, ",")
	out := map[string]string{}
	for param := range strings.SplitSeq(element, ";") {
		key, value, ok := strings.Cut(param, "=")
		if !ok {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(key))] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return out
}

// AccessLogMiddleware logs incoming HTTP requests if enabled.
func AccessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		clientIP := middleware.GetClientIP(r.Context())
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}
		stdlog.Printf("ACCESS: %s %s from %s in %v", r.Method, r.RequestURI, clientIP, time.Since(start))
	})
}

// Authenticate extracts and validates the JWT token.
func Authenticate(r *http.Request) (string, *http.Request, error) {
	if existingClaims, ok := r.Context().Value(TokenClaimsKey).(jwt.MapClaims); ok && len(existingClaims) > 0 {
		return extractUserIDFromClaims(existingClaims, currentConfig().TokenUserSearch), r, nil
	}

	authHeaderValue := authCacheKey(r)
	cfg := currentConfig()

	// Check cache for claims and user_id using every declared credential.
	if claimsCache != nil && authHeaderValue != "" {
		if cached, found := claimsCache.Get(authHeaderValue); found {
			if entry, ok := cached.(claimsCacheEntry); ok {
				r = r.WithContext(context.WithValue(r.Context(), TokenClaimsKey, entry.Claims))
				return entry.UserID, r, nil
			}
		}
	}

	tried := tryAuthPlugins(r, nil)
	if !tried.ok {
		if len(cfg.AnonClaims) > 0 {
			claims := jwt.MapClaims{}
			maps.Copy(claims, cfg.AnonClaims)
			r = r.WithContext(context.WithValue(r.Context(), TokenClaimsKey, claims))
			return "", r, nil
		}
		return "", r, fmt.Errorf("authentication failed: %w", tried.err)
	}

	userID, r := applyAuthSuccess(r, tried.claims, tried.headers)
	// Store in cache using every declared credential as the key
	if claimsCache != nil && authHeaderValue != "" {
		claimsCache.SetDefault(authHeaderValue, claimsCacheEntry{Claims: tried.claims, UserID: userID})
	}
	return userID, r, nil
}

func authenticateAllowed(r *http.Request, names []string, appAnon map[string]any) (string, *http.Request, error) {
	if len(names) == 0 {
		return finishAnon(r, appAnon, true)
	}
	allow := make(map[string]struct{}, len(names))
	for _, name := range names {
		allow[name] = struct{}{}
	}
	tried := tryAuthPlugins(r, allow)
	if tried.ok {
		userID, r := applyAuthSuccess(r, tried.claims, tried.headers)
		return userID, r, nil
	}
	userID, r, err := finishAnon(r, appAnon, false)
	if err != nil {
		if tried.err != nil {
			return "", r, fmt.Errorf("authentication failed: %w", tried.err)
		}
		return "", r, fmt.Errorf("authentication failed")
	}
	return userID, r, nil
}

// triedAuth is the first successful plugin, or the last plugin error.
type triedAuth struct {
	claims  jwt.MapClaims
	headers map[string]any
	err     error
	ok      bool
}

// tryAuthPlugins tries plugins in trial order. A nil allow set tries every loaded plugin.
func tryAuthPlugins(r *http.Request, allow map[string]struct{}) triedAuth {
	loaded := AuthPlugins.Load()
	headersForPlugin, pluginHeaders := authHeadersForPlugins(r)
	if allow != nil && loaded == nil {
		return triedAuth{headers: pluginHeaders}
	}
	var authErr error
	for _, pluginName := range authPluginOrderSnapshot() {
		if allow != nil {
			if _, ok := allow[pluginName]; !ok {
				continue
			}
		}
		plugin := (*loaded)[pluginName]
		if allow != nil && plugin == nil {
			continue
		}
		pluginClaims, err := plugin.Authenticate(headersForPlugin, r.Method, r.URL.Path, r.URL.RawQuery)
		if err != nil {
			authErr = fmt.Errorf("plugin %s: %w", pluginName, err)
			continue
		}
		claims := jwt.MapClaims{}
		maps.Copy(claims, pluginClaims)
		return triedAuth{claims: claims, headers: pluginHeaders, ok: true}
	}
	return triedAuth{headers: pluginHeaders, err: authErr}
}

func applyAuthSuccess(r *http.Request, claims jwt.MapClaims, headers map[string]any) (string, *http.Request) {
	ctx := context.WithValue(r.Context(), TokenClaimsKey, claims)
	ctx = context.WithValue(ctx, requestPluginHeadersKey, headers)
	r = r.WithContext(ctx)
	return extractUserIDFromClaims(claims, currentConfig().TokenUserSearch), r
}

func finishAnon(r *http.Request, appAnon map[string]any, allowEmpty bool) (string, *http.Request, error) {
	claimsMap := appAnon
	if claimsMap == nil {
		claimsMap = currentConfig().AnonClaims
	}
	if len(claimsMap) == 0 && !allowEmpty {
		return "", r, fmt.Errorf("authentication failed")
	}
	if len(claimsMap) == 0 {
		r = r.WithContext(context.WithValue(r.Context(), TokenClaimsKey, jwt.MapClaims{}))
		return "", r, nil
	}
	claims := jwt.MapClaims{}
	maps.Copy(claims, claimsMap)
	r = r.WithContext(context.WithValue(r.Context(), TokenClaimsKey, claims))
	return extractUserIDFromClaims(claims, currentConfig().TokenUserSearch), r, nil
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
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware handles CORS headers based on configuration
func corsMiddleware(next http.Handler) http.Handler {
	cfg := GetConfig()
	joinedMethods := strings.Join(cfg.CORS.Methods, ", ")
	joinedHeaders := strings.Join(cfg.CORS.Headers, ", ")
	maxAgeStr := strconv.Itoa(cfg.CORS.MaxAge)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		} else if len(origin) > 1024 {
			w.WriteHeader(http.StatusForbidden)
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
			w.Header().Set("Access-Control-Allow-Methods", joinedMethods)
			w.Header().Set("Access-Control-Allow-Headers", joinedHeaders)
			w.Header().Set("Access-Control-Expose-Headers", "ETag, Resource-Version, Vary, Preference-Applied")
			w.Header().Set("Access-Control-Max-Age", maxAgeStr)
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

// spanNameMiddleware renames the active OTel span using the matched chi route pattern.
func spanNameMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		rc := chi.RouteContext(r.Context())
		if rc == nil {
			return
		}
		pattern := rc.RoutePattern()
		if pattern == "" {
			return
		}
		span := trace.SpanFromContext(r.Context())
		if span.IsRecording() {
			span.SetName(r.Method + " " + pattern)
		}
	})
}

// clientIPMiddleware selects chi ClientIP middleware based on server config.
func clientIPMiddleware(cfg config.ServerConfig) func(http.Handler) http.Handler {
	switch strings.ToLower(strings.TrimSpace(cfg.TrustedProxyMode)) {
	case "header":
		header := cfg.TrustedProxyHeader
		if header == "" {
			header = "X-Real-IP"
		}
		return middleware.ClientIPFromHeader(header)
	case "xff_count":
		count := cfg.TrustedProxyCount
		if count <= 0 {
			count = 1
		}
		return middleware.ClientIPFromXFFTrustedProxies(count)
	default:
		return func(next http.Handler) http.Handler {
			return middleware.ClientIPFromRemoteAddr(next)
		}
	}
}

// SetupRouter loads plugins and builds the router. Tests use this entry point.
func SetupRouter() chi.Router {
	LoadPlugins()
	return buildRouter()
}

// buildRouter initializes the router and endpoints from the active config.
// A rest spec hook error is logged. The router is still returned.
func buildRouter() chi.Router {
	r, err := newRouter()
	if err != nil {
		stdlog.Printf("restapi spec hook: %v", err)
	}
	return r
}

// newRouter builds the router and returns a rest spec hook error with that router.
func newRouter() (chi.Router, error) {
	cfg := GetConfig()
	// Initialize claims cache with default expiration and cleanup interval
	if claimsCache == nil && cfg.TokenCacheTTL > 0 {
		defaultExpiration := time.Duration(cfg.TokenCacheTTL) * time.Second
		cleanupInterval := time.Duration(cfg.TokenCacheTTL) * time.Second * 10
		claimsCache = cachepkg.New(defaultExpiration, cleanupInterval)
	}
	r := chi.NewRouter()

	chi.RegisterMethod("QUERY")

	// Add recovery middleware
	r.Use(middleware.Recoverer)

	// Add CORS middleware first
	if cfg.CORS.Enabled {
		r.Use(corsMiddleware)
	}

	r.Use(clientIPMiddleware(cfg.Server))

	// Add proxy headers handler
	r.Use(proxyHeadersHandler)

	r.Use(middleware.GetHead)
	r.Use(spanNameMiddleware)

	// Schema endpoint.
	r.Get("/", rootCatalogHandler)
	r.Get("/api/{db}/", schemaHandler)
	// Read-only SQL query endpoint.
	r.Method("QUERY", "/api/{db}/", http.HandlerFunc(queryHandler))
	// Call RPC function endpoint.
	r.Post("/api/{db}/rpc/{func}/", rpcHandler)
	// Table CRUD. HandleFunc registers mALL first so PUT/HEAD/OPTIONS/QUERY keep
	// today's 405 after the table preamble. Later Get/Post/Patch/Delete replace
	// only those method slots (chi setEndpoint mALL vs single-method). Do not
	// reorder; do not use MethodNotAllowed or Route/Mount here.
	tables := r.With(
		sanitizeTableMiddleware,
		requirePluginMiddleware(tableResource),
		authenticateMiddleware,
		tableScopeMiddleware,
		tablePreRequestMiddleware,
	)
	const tablePath = "/api/{db}/{table}/"
	tables.HandleFunc(tablePath, tableMethodNotAllowed)
	tables.Get(tablePath, tableGet)
	tables.Post(tablePath, tablePost)
	tables.Patch(tablePath, tablePatch)
	tables.Delete(tablePath, tableDelete)
	// Add health check endpoint.
	r.Get("/health", healthHandler)
	mountRestAPI(r)
	mountStorage(r)
	if err := publishRestAPI(); err != nil {
		return r, err
	}
	publishStorage()
	if mount := routeHook.Load(); mount != nil && *mount != nil {
		(*mount)(r)
	}
	return r, nil
}

func InitOtel(otelCfg config.OtelConfig) (shutdown func(context.Context) error, err error) {
	var exp sdktrace.SpanExporter
	switch otelCfg.Protocol {
	case "otlp":
		exp, err = otlptracegrpc.New(context.Background(), otlptracegrpc.WithEndpoint(otelCfg.Endpoint), otlptracegrpc.WithInsecure())
	case "otlphttp":
		exp, err = otlptracehttp.New(context.Background(), otlptracehttp.WithEndpoint(otelCfg.Endpoint))
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

type swapHandler struct {
	current atomic.Pointer[http.Handler]
}

func (s *swapHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := s.current.Load()
	if h == nil || *h == nil {
		http.Error(w, "server not ready", http.StatusServiceUnavailable)
		return
	}
	(*h).ServeHTTP(w, r)
}

func (s *swapHandler) store(h http.Handler) {
	s.current.Store(&h)
}

// LiveHandler builds the HTTP handler from the active config.
// Run serves this handler and swaps it in again after SIGHUP.
func LiveHandler() (http.Handler, error) {
	return buildLiveHandler(GetConfig())
}

// buildLiveHandler builds the swappable request handler. Plugins are already loaded.
// A rest spec hook error is returned with the handler that was built.
func buildLiveHandler(cfg config.Config) (http.Handler, error) {
	router, err := newRouter()
	var handler http.Handler = router
	if cfg.AccessLogOn {
		handler = AccessLogMiddleware(handler)
	}
	return handler, err
}

func newHTTPServer(conf *config.Config, handler http.Handler) *http.Server {
	sc := conf.Server
	srv := &http.Server{
		Addr:              ":" + conf.Port,
		Handler:           handler,
		ReadTimeout:       sc.ReadTimeout,
		WriteTimeout:      sc.WriteTimeout,
		IdleTimeout:       sc.IdleTimeout,
		MaxHeaderBytes:    sc.MaxHeaderBytes,
		ReadHeaderTimeout: sc.ReadHeaderTimeout,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams:          sc.HTTP2MaxConcurrentStreams,
			MaxReadFrameSize:              sc.HTTP2MaxReadFrameSize,
			MaxReceiveBufferPerConnection: sc.HTTP2MaxUploadBufferPerConnection,
			MaxReceiveBufferPerStream:     sc.HTTP2MaxUploadBufferPerStream,
			SendPingTimeout:               sc.HTTP2ReadIdleTimeout,
			PingTimeout:                   sc.HTTP2PingTimeout,
			PermitProhibitedCipherSuites:  sc.HTTP2PermitProhibitedCipherSuites,
		},
		ConnState: func(conn net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					tcpConn.SetKeepAlive(true)
					tcpConn.SetKeepAlivePeriod(sc.KeepAlivePeriod)
				}
			case http.StateIdle:
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					tcpConn.SetReadBuffer(0)
					tcpConn.SetWriteBuffer(0)
				}
			}
		},
	}
	if !conf.TLSEnabled {
		protos := new(http.Protocols)
		protos.SetHTTP1(true)
		protos.SetUnencryptedHTTP2(true)
		srv.Protocols = protos
	}
	return srv
}

// Run starts the HTTP server from the configuration set by SetupApplication.
// It stops on SIGINT or SIGTERM. SIGHUP reloads config without stopping.
func Run() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := Serve(ctx); err != nil {
		stdlog.Fatalf("server: %v", err)
	}
}

// Serve runs the HTTP server until ctx is canceled.
// SIGHUP reloads config and rebuilds routes. Listen failures are returned.
func Serve(ctx context.Context) error {
	conf := GetConfig()
	var otelShutdown func(context.Context) error
	if conf.Otel.Enabled {
		var err error
		otelShutdown, err = InitOtel(conf.Otel)
		if err != nil {
			stdlog.Printf("Failed to initialize OpenTelemetry: %v", err)
		}
	}
	swap := &swapHandler{}
	live, err := buildLiveHandler(conf)
	if err != nil {
		return err
	}
	swap.store(live)
	var handler http.Handler = swap
	if otelShutdown != nil {
		handler = otelhttp.NewHandler(handler, "server-request")
	}

	srv := newHTTPServer(&conf, handler)

	rpcLis, err := listenInternalRPC(conf.InternalRPC)
	if err != nil {
		return fmt.Errorf("internal rpc: %w", err)
	}
	if rpcLis != nil {
		go serveInternalRPC(rpcLis)
	}

	listenErr := make(chan error, 1)
	go func() {
		if conf.TLSEnabled {
			stdlog.Printf("TLS server listening on port %s...", conf.Port)
			err := srv.ListenAndServeTLS(conf.TLSCertFile, conf.TLSKeyFile)
			if err != nil && err != http.ErrServerClosed {
				listenErr <- err
			}
			return
		}
		stdlog.Printf("Server listening on port %s...", conf.Port)
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			listenErr <- err
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	defer signal.Stop(sigChan)

	for {
		select {
		case <-ctx.Done():
			stdlog.Println("Shutting down the server")
			if rpcLis != nil {
				_ = rpcLis.Close()
			}
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := srv.Shutdown(shutdownCtx); err != nil {
				stdlog.Printf("Forced server shutdown due to error: %v", err)
			}
			cancel()
			StopPlugins()
			if otelShutdown != nil {
				ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
				if err := otelShutdown(ctx2); err != nil {
					stdlog.Printf("Error shutting down OpenTelemetry: %v", err)
				}
				cancel2()
			}
			stdlog.Println("Server exiting")
			return nil
		case err := <-listenErr:
			if err != nil {
				return fmt.Errorf("listen: %w", err)
			}
		case sig := <-sigChan:
			if sig == syscall.SIGHUP {
				stdlog.Println("Received SIGHUP - reloading configuration")
				if err := reloadApplication(); err != nil {
					stdlog.Printf("reload config: %v", err)
					continue
				}
				reloaded, hookErr := buildLiveHandler(GetConfig())
				if hookErr != nil {
					stdlog.Printf("restapi spec hook: %v", hookErr)
				}
				if reloaded != nil {
					swap.store(reloaded)
				}
			}
		}
	}
}
