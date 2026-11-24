// Package embed runs the easyrest server inside another program.
// It uses the same setup and listen path as the easyrest-server binary
// and can add routes, plugin factories, and Go rest handlers.
package embed

import (
	"context"
	"errors"
	"net/http"
	"os/signal"
	"syscall"

	"github.com/go-chi/chi/v5"
	"github.com/onegreyonewhite/easyrest/internal/server"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	"golang.org/x/sync/errgroup"
)

type (
	// Call is one invocation of a Go rest handler.
	Call = server.Call
	// RestHandler replaces a rest table call or function call.
	// The name is RestHandler because Handler is the HTTP handler constructor.
	RestHandler = server.Handler
	// HandlerError is a rest handler failure with an HTTP status.
	HandlerError = server.HandlerError
	// View writes the HTTP response for one restapi view.
	View = server.View
	// PluginCaller is the in-process internal RPC available to a rest handler.
	PluginCaller = server.PluginCaller
)

// Service runs until ctx is canceled or it fails.
// Return nil after ctx is done. Return a non-nil error to stop the process.
type Service func(ctx context.Context) error

// ErrCacheMiss is a cache store miss.
var ErrCacheMiss = easyrest.ErrCacheMiss

// Option configures one embedded server before it loads config.
type Option func(*settings)

type settings struct {
	routes     func(chi.Router)
	handlers   map[string]RestHandler
	views      map[string]View
	db         map[string]func() easyrest.DBPlugin
	query      map[string]func() easyrest.DBQueryPlugin
	auth       map[string]func() easyrest.AuthPlugin
	middleware map[string]func() easyrest.MiddlewarePlugin
	content    map[string]func() easyrest.ContentPlugin
	storage    map[string]func() easyrest.StoragePlugin
	services   []Service
	specHooks  []func(name string, doc map[string]any) error
}

// WithRoutes adds routes after the built-in routes on every router build,
// including a SIGHUP reload. Mount a chi.Router here for a separate tree.
// Leave /, /api, /health, /restapi, and /media to the server.
func WithRoutes(mount func(chi.Router)) Option {
	return func(s *settings) { s.routes = mount }
}

// WithDB registers an in-process database plugin under a URI scheme.
func WithDB(scheme string, factory func() easyrest.DBPlugin) Option {
	return func(s *settings) {
		if s.db == nil {
			s.db = map[string]func() easyrest.DBPlugin{}
		}
		s.db[scheme] = factory
	}
}

// WithQuery registers an in-process query plugin under a URI scheme.
func WithQuery(scheme string, factory func() easyrest.DBQueryPlugin) Option {
	return func(s *settings) {
		if s.query == nil {
			s.query = map[string]func() easyrest.DBQueryPlugin{}
		}
		s.query[scheme] = factory
	}
}

// WithAuth registers an in-process auth plugin under an auth_plugins key.
func WithAuth(name string, factory func() easyrest.AuthPlugin) Option {
	return func(s *settings) {
		if s.auth == nil {
			s.auth = map[string]func() easyrest.AuthPlugin{}
		}
		s.auth[name] = factory
	}
}

// WithMiddleware registers an in-process middleware plugin under its driver name.
func WithMiddleware(name string, factory func() easyrest.MiddlewarePlugin) Option {
	return func(s *settings) {
		if s.middleware == nil {
			s.middleware = map[string]func() easyrest.MiddlewarePlugin{}
		}
		s.middleware[name] = factory
	}
}

// WithContent registers an in-process content plugin under a content_plugins key.
func WithContent(name string, factory func() easyrest.ContentPlugin) Option {
	return func(s *settings) {
		if s.content == nil {
			s.content = map[string]func() easyrest.ContentPlugin{}
		}
		s.content[name] = factory
	}
}

// WithStorage registers an in-process storage plugin under its driver name.
func WithStorage(name string, factory func() easyrest.StoragePlugin) Option {
	return func(s *settings) {
		if s.storage == nil {
			s.storage = map[string]func() easyrest.StoragePlugin{}
		}
		s.storage[name] = factory
	}
}

// WithView registers a Go function for a rest view handler name.
// The config field handler selects it. Register it before the server loads config.
// The function writes the response after authentication and request middleware.
func WithView(name string, view View) Option {
	return func(s *settings) {
		if s.views == nil {
			s.views = map[string]View{}
		}
		s.views[name] = view
	}
}

// WithRestHandler registers a Go function for a rest action handler name.
// The config field handler selects it. Register it before the server loads config.
func WithRestHandler(name string, handler RestHandler) Option {
	return func(s *settings) {
		if s.handlers == nil {
			s.handlers = map[string]RestHandler{}
		}
		s.handlers[name] = handler
	}
}

// WithRestSpec edits one rest OpenAPI document before it is stored.
// name is the application.api key. doc is that API's document.
// Finish every edit before returning. A nested map kept after return
// can still change the stored document, because a successful hook stores this copy.
// Hooks run in registration order. A later Handler call without this option clears them.
func WithRestSpec(hook func(name string, doc map[string]any) error) Option {
	return func(s *settings) {
		if hook != nil {
			s.specHooks = append(s.specHooks, hook)
		}
	}
}

// WithService registers a background task that runs beside the HTTP server.
// SIGHUP reload applies only to the HTTP server, not to sibling services.
func WithService(run Service) Option {
	return func(s *settings) {
		if run != nil {
			s.services = append(s.services, run)
		}
	}
}

// Handler loads config and returns the HTTP handler Run would serve.
// A later call rebuilds the router and keeps routes from WithRoutes.
func Handler(overlay string, files []string, opts ...Option) (http.Handler, error) {
	cfg := applyOptions(opts...)
	if err := install(cfg, overlay, files); err != nil {
		return nil, err
	}
	handler, err := server.LiveHandler()
	if err != nil {
		return nil, err
	}
	return handler, nil
}

// Serve loads config and runs the HTTP server and every WithService task
// until ctx is canceled. Context cancellation is a clean stop and returns nil.
func Serve(ctx context.Context, overlay string, files []string, opts ...Option) error {
	cfg := applyOptions(opts...)
	if err := install(cfg, overlay, files); err != nil {
		return err
	}
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return server.Serve(gctx)
	})
	for _, svc := range cfg.services {
		svc := svc
		g.Go(func() error {
			return svc(gctx)
		})
	}
	err := g.Wait()
	if err == nil || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// Run loads config and serves it until SIGINT or SIGTERM.
// SIGHUP reloads the same files and overlay and rebuilds routes on the HTTP server.
func Run(overlay string, files []string, opts ...Option) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return Serve(ctx, overlay, files, opts...)
}

func applyOptions(opts ...Option) settings {
	var cfg settings
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

func install(cfg settings, overlay string, files []string) error {
	for name, factory := range cfg.db {
		server.PreservedDbPlugins[name] = factory
	}
	for name, factory := range cfg.query {
		server.PreservedQueryPlugins[name] = factory
	}
	for name, factory := range cfg.auth {
		server.PreservedAuthPlugins[name] = factory
	}
	for name, factory := range cfg.middleware {
		server.PreservedMiddlewarePlugins[name] = factory
	}
	for name, factory := range cfg.content {
		server.PreservedContentPlugins[name] = factory
	}
	for name, factory := range cfg.storage {
		server.PreservedStoragePlugins[name] = factory
	}
	server.SetRoutes(cfg.routes)
	server.SetRestHandlers(cfg.handlers)
	server.SetViews(cfg.views)
	hooks := make([]server.RestSpecHook, len(cfg.specHooks))
	for i, hook := range cfg.specHooks {
		hooks[i] = hook
	}
	server.SetRestSpecHooks(hooks)
	return server.SetupApplication(overlay, files)
}
