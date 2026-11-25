package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// HandlerError is a rest handler failure with an HTTP status.
// A zero Status is reported as 500.
// ContentType, when set, is the response media type. An empty value
// keeps the plain-text error body.
type HandlerError struct {
	Status      int
	Message     string
	ContentType string
}

func (e *HandlerError) Error() string {
	if e == nil || e.Message == "" {
		return "handler error"
	}
	return e.Message
}

// PluginCaller is the in-process internal RPC available to a rest handler or view.
// Calls use the same dispatch path as Internal.TableGet and the other
// Internal methods. They do not open a socket. Begin opens one database
// transaction. Calls on the returned session join it until Commit or Rollback.
// Storage calls reach loaded storage_plugins by name and do not run storage
// auth or forward the caller token.
type PluginCaller interface {
	TableGet(easyrest.HostCall) (easyrest.HostResult, error)
	TableCreate(easyrest.HostCall) (easyrest.HostResult, error)
	TableUpdate(easyrest.HostCall) (easyrest.HostResult, error)
	TableDelete(easyrest.HostCall) (easyrest.HostResult, error)
	CallFunction(easyrest.HostCall) (easyrest.HostResult, error)
	Query(ctx context.Context, db, query string) ([]map[string]any, error)
	CacheGet(name, key string) (string, error)
	CacheSet(name, key, value string, ttl *time.Duration) error
	CacheDelete(name, key string) error
	StoragePut(name, path string, body []byte, ctx map[string]any) (rel string, ctxOut map[string]any, err error)
	StoragePutStream(name, path string, r io.Reader, ctx map[string]any) (rel string, ctxOut map[string]any, err error)
	StorageGetUrl(name string, paths []string, ctx map[string]any) ([]easyrest.StorageURL, error)
	StorageGetMetadata(name, path string, ctx map[string]any) (easyrest.StorageMeta, error)
	StorageGetBin(name, path string, ctx map[string]any) (body []byte, mime string, ctxOut map[string]any, err error)
	StorageGetStream(name, path string, offset int64, ctx map[string]any) (io.ReadCloser, string, map[string]any, error)
	StorageList(name, path string, ctx map[string]any) ([]easyrest.StorageEntry, error)
	StorageDelete(name, path string, ctx map[string]any) error
	Begin(ctx context.Context, db string) (DBSession, error)
}

// DBSession is one shared database transaction.
// Its table and function calls join that transaction. Commit or Rollback ends it.
// Rollback is a no-op after a successful Commit.
type DBSession interface {
	ID() string
	TableGet(easyrest.HostCall) (easyrest.HostResult, error)
	TableCreate(easyrest.HostCall) (easyrest.HostResult, error)
	TableUpdate(easyrest.HostCall) (easyrest.HostResult, error)
	TableDelete(easyrest.HostCall) (easyrest.HostResult, error)
	CallFunction(easyrest.HostCall) (easyrest.HostResult, error)
	Commit(ctx context.Context) (map[string]any, error)
	Rollback(ctx context.Context) error
}

// Call is one invocation of a Go rest handler or view.
// UserID is the authenticated rest user. Internal RPC calls do not receive it.
// Body is the parsed object for a rest handler write. A view leaves Body nil
// and reads Request.Body itself.
type Call struct {
	Context context.Context
	Request *http.Request
	UserID  string
	Params  map[string]string
	Body    map[string]any
	Plugins PluginCaller
}

// Handler replaces a rest table call or function call.
// The returned value is rendered by the endpoint content plugins.
type Handler func(Call) (any, error)

// View writes the HTTP response for one restapi view.
// Authentication and request middleware have already run.
// The function owns ResponseWriter, including status, headers, and streaming.
// Context on Call is canceled when the client disconnects.
// A long-lived stream extends the write deadline with http.NewResponseController.
type View func(http.ResponseWriter, Call)

var restHandlers atomic.Pointer[map[string]Handler]

var restViews atomic.Pointer[map[string]View]

// SetRestHandlers replaces the Go rest handler registry.
// A nil map clears it. SetupApplication rejects a config name that is not registered.
func SetRestHandlers(handlers map[string]Handler) {
	if handlers == nil {
		restHandlers.Store(nil)
		return
	}
	copied := maps.Clone(handlers)
	restHandlers.Store(&copied)
}

func restHandler(name string) (Handler, bool) {
	loaded := restHandlers.Load()
	if loaded == nil || name == "" {
		return nil, false
	}
	handler, ok := (*loaded)[name]
	return handler, ok
}

// SetViews replaces the Go rest view registry.
// A nil map clears it. SetupApplication rejects a config name that is not registered.
func SetViews(views map[string]View) {
	if views == nil {
		restViews.Store(nil)
		return
	}
	copied := maps.Clone(views)
	restViews.Store(&copied)
}

func restView(name string) (View, bool) {
	loaded := restViews.Load()
	if loaded == nil || name == "" {
		return nil, false
	}
	view, ok := (*loaded)[name]
	return view, ok
}

func validateRestHandlers(cfg *config.Config) error {
	if cfg == nil {
		return nil
	}
	for apiName, app := range cfg.RestAPI {
		for epName, ep := range app.Endpoints {
			for actionName, act := range ep.Actions {
				if err := requireRestHandler(apiName, epName, actionName, act.Handler); err != nil {
					return err
				}
			}
			for actionName, call := range ep.DetailActions {
				if err := requireRestHandler(apiName, epName, actionName, call.Handler); err != nil {
					return err
				}
			}
			for actionName, call := range ep.ListActions {
				if err := requireRestHandler(apiName, epName, actionName, call.Handler); err != nil {
					return err
				}
			}
			for actionName, state := range ep.StateActions {
				if err := requireRestHandler(apiName, epName, actionName, state.Handler); err != nil {
					return err
				}
			}
			for viewName, view := range ep.Views {
				if err := requireRestView(apiName, epName, viewName, view.Handler); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func requireRestView(apiName, epName, viewName, name string) error {
	if name == "" {
		return nil
	}
	if _, ok := restView(name); ok {
		return nil
	}
	return fmt.Errorf("restapi %s %s %s handler %q is not registered", apiName, epName, viewName, name)
}

func requireRestHandler(apiName, epName, actionName, name string) error {
	if name == "" {
		return nil
	}
	if _, ok := restHandler(name); ok {
		return nil
	}
	return fmt.Errorf("restapi %s %s %s handler %q is not registered", apiName, epName, actionName, name)
}

func (a restTableAction) serveGo(w http.ResponseWriter, r *http.Request) {
	read := r.Method == http.MethodGet || r.Method == http.MethodHead
	userID, r, ctx, ok := a.openContext(w, r, read, "")
	if !ok {
		return
	}
	var body map[string]any
	switch r.Method {
	case http.MethodPost, http.MethodPatch, http.MethodPut:
		if a.handler == "appendTaskLines" {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			var lines []any
			if err := json.Unmarshal(raw, &lines); err != nil {
				http.Error(w, "lines must be a JSON array", http.StatusBadRequest)
				return
			}
			body = map[string]any{"lines": lines}
			if !a.acceptWrite(w, body) {
				return
			}
			break
		}
		parsed, ready := a.parseWriteObject(w, r)
		if !ready {
			return
		}
		body = parsed
	}
	fn, found := restHandler(a.handler)
	if !found {
		a.finishContext(w, r, ctx, restWrite{err: fmt.Errorf("rest handler %q is not registered", a.handler)})
		return
	}
	params := a.pathValues(r)
	if id := chi.URLParam(r, "id"); id != "" {
		params["id"] = id
	}
	result, err := fn(Call{
		Context: r.Context(),
		Request: r,
		UserID:  userID,
		Params:  params,
		Body:    body,
		Plugins: directPlugins{},
	})
	if err != nil {
		a.finishContext(w, r, ctx, restWrite{err: err})
		return
	}
	status := http.StatusOK
	if r.Method == http.MethodPost && a.successStatus != 0 {
		status = a.successStatus
	}
	a.finishContext(w, r, ctx, restWrite{status: status, body: result})
}

func (a restTableAction) serveView(w http.ResponseWriter, r *http.Request) {
	read := r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == "QUERY"
	userID, r, _, ok := a.openContext(w, r, read, "")
	if !ok {
		return
	}
	fn, found := restView(a.handler)
	if !found {
		http.Error(w, fmt.Sprintf("rest handler %q is not registered", a.handler), http.StatusInternalServerError)
		return
	}
	fn(w, Call{
		Context: r.Context(),
		Request: r,
		UserID:  userID,
		Params:  requestParams(r),
		Plugins: directPlugins{},
	})
}

func requestParams(r *http.Request) map[string]string {
	rctx := chi.RouteContext(r.Context())
	if rctx == nil {
		return map[string]string{}
	}
	params := make(map[string]string, len(rctx.URLParams.Keys))
	for i, key := range rctx.URLParams.Keys {
		if key == "" || key == "*" || i >= len(rctx.URLParams.Values) {
			continue
		}
		params[key] = rctx.URLParams.Values[i]
	}
	return params
}

// directPlugins calls DispatchInternal in this process.
type directPlugins struct{}

var _ PluginCaller = directPlugins{}

// Plugins returns the in-process plugin caller for embed services and tests.
// View and rest handlers use the same implementation on Call.Plugins.
func Plugins() PluginCaller {
	return directPlugins{}
}

func (directPlugins) TableGet(req easyrest.HostCall) (easyrest.HostResult, error) {
	return dispatchHost(http.MethodGet, internalTablePath(req), req)
}

func (directPlugins) TableCreate(req easyrest.HostCall) (easyrest.HostResult, error) {
	return dispatchHost(http.MethodPost, internalTablePath(req), req)
}

func (directPlugins) TableUpdate(req easyrest.HostCall) (easyrest.HostResult, error) {
	return dispatchHost(http.MethodPatch, internalTablePath(req), req)
}

func (directPlugins) TableDelete(req easyrest.HostCall) (easyrest.HostResult, error) {
	return dispatchHost(http.MethodDelete, internalTablePath(req), req)
}

func (directPlugins) CallFunction(req easyrest.HostCall) (easyrest.HostResult, error) {
	return dispatchHost(http.MethodPost, "/api/"+req.DB+"/rpc/"+req.Name+"/", req)
}

func (directPlugins) Query(ctx context.Context, db, query string) ([]map[string]any, error) {
	db = strings.ToLower(strings.TrimSpace(db))
	if db == "" {
		return nil, errors.New("database name is empty")
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, errors.New("query is empty")
	}
	cfg := currentConfig()
	plugCfg, ok := cfg.PluginMap[db]
	if !ok || !plugCfg.UseQuery || !plugCfg.Internal {
		return nil, fmt.Errorf("raw query is not allowed for database %q", db)
	}
	plugins := DbPlugins.Load()
	if plugins == nil {
		return nil, fmt.Errorf("database %q is not loaded", db)
	}
	plug, ok := (*plugins)[db]
	if !ok || plug == nil {
		return nil, fmt.Errorf("database %q is not loaded", db)
	}
	rq, ok := plug.(easyrest.RawQuerier)
	if !ok {
		return nil, fmt.Errorf("database %q does not support raw query", db)
	}
	rows, err := rq.RawQuery(ctx, query)
	if rows == nil && err == nil {
		rows = []map[string]any{}
	}
	return rows, err
}

func (directPlugins) Begin(ctx context.Context, db string) (DBSession, error) {
	txr, err := dbTransactor(db)
	if err != nil {
		return nil, err
	}
	pluginCtx := map[string]any{}
	if ctx != nil {
		if deadline, ok := ctx.Deadline(); ok {
			pluginCtx[easyrest.SharedTxDeadlineKey] = deadline
		}
	}
	id, _, err := txr.BeginTx(pluginCtx)
	if err != nil {
		return nil, err
	}
	return &dbSession{db: strings.ToLower(strings.TrimSpace(db)), id: id}, nil
}

type dbSession struct {
	db   string
	id   string
	done bool
}

func (s *dbSession) ID() string {
	if s == nil {
		return ""
	}
	return s.id
}

func (s *dbSession) TableGet(req easyrest.HostCall) (easyrest.HostResult, error) {
	req, err := s.bind(req)
	if err != nil {
		return easyrest.HostResult{}, err
	}
	return directPlugins{}.TableGet(req)
}

func (s *dbSession) TableCreate(req easyrest.HostCall) (easyrest.HostResult, error) {
	req, err := s.bind(req)
	if err != nil {
		return easyrest.HostResult{}, err
	}
	return directPlugins{}.TableCreate(req)
}

func (s *dbSession) TableUpdate(req easyrest.HostCall) (easyrest.HostResult, error) {
	req, err := s.bind(req)
	if err != nil {
		return easyrest.HostResult{}, err
	}
	return directPlugins{}.TableUpdate(req)
}

func (s *dbSession) TableDelete(req easyrest.HostCall) (easyrest.HostResult, error) {
	req, err := s.bind(req)
	if err != nil {
		return easyrest.HostResult{}, err
	}
	return directPlugins{}.TableDelete(req)
}

func (s *dbSession) CallFunction(req easyrest.HostCall) (easyrest.HostResult, error) {
	req, err := s.bind(req)
	if err != nil {
		return easyrest.HostResult{}, err
	}
	return directPlugins{}.CallFunction(req)
}

func (s *dbSession) Commit(context.Context) (map[string]any, error) {
	if s == nil || s.done {
		return nil, easyrest.ErrSharedTxDone
	}
	txr, err := dbTransactor(s.db)
	if err != nil {
		return nil, err
	}
	out, err := txr.CommitTx(s.id, nil)
	if err != nil {
		return out, err
	}
	s.done = true
	return out, nil
}

func (s *dbSession) Rollback(context.Context) error {
	if s == nil || s.done {
		return nil
	}
	txr, err := dbTransactor(s.db)
	if err != nil {
		return err
	}
	if err := txr.RollbackTx(s.id); err != nil {
		return err
	}
	s.done = true
	return nil
}

func (s *dbSession) bind(req easyrest.HostCall) (easyrest.HostCall, error) {
	if s == nil || s.done {
		return req, easyrest.ErrSharedTxDone
	}
	if req.DB == "" {
		req.DB = s.db
	}
	if strings.ToLower(req.DB) != s.db {
		return req, fmt.Errorf("shared transaction is for database %s", s.db)
	}
	req.TxID = s.id
	return req, nil
}

func (directPlugins) CacheGet(name, key string) (string, error) {
	store, err := cacheStore(name, key)
	if err != nil {
		return "", err
	}
	return store.Get(key)
}

func (directPlugins) CacheSet(name, key, value string, ttl *time.Duration) error {
	store, err := cacheStore(name, key)
	if err != nil {
		return err
	}
	return store.Set(key, value, ttl)
}

func (directPlugins) CacheDelete(name, key string) error {
	store, err := cacheStore(name, key)
	if err != nil {
		return err
	}
	return store.Delete(key)
}

func (directPlugins) StoragePut(name, path string, body []byte, ctx map[string]any) (string, map[string]any, error) {
	plug, err := storagePluginForCaller(name)
	if err != nil {
		return "", ctx, err
	}
	return plug.Put(path, body, ctx)
}

func (directPlugins) StoragePutStream(name, path string, r io.Reader, ctx map[string]any) (string, map[string]any, error) {
	plug, err := storagePluginForCaller(name)
	if err != nil {
		return "", ctx, err
	}
	return plug.PutStream(path, r, ctx)
}

func (directPlugins) StorageGetUrl(name string, paths []string, ctx map[string]any) ([]easyrest.StorageURL, error) {
	plug, err := storagePluginForCaller(name)
	if err != nil {
		return nil, err
	}
	return plug.GetUrl(paths, ctx)
}

func (directPlugins) StorageGetMetadata(name, path string, ctx map[string]any) (easyrest.StorageMeta, error) {
	plug, err := storagePluginForCaller(name)
	if err != nil {
		return easyrest.StorageMeta{}, err
	}
	return plug.GetMetadata(path, ctx)
}

func (directPlugins) StorageGetBin(name, path string, ctx map[string]any) ([]byte, string, map[string]any, error) {
	plug, err := storagePluginForCaller(name)
	if err != nil {
		return nil, "", ctx, err
	}
	return plug.GetBin(path, ctx)
}

func (directPlugins) StorageGetStream(name, path string, offset int64, ctx map[string]any) (io.ReadCloser, string, map[string]any, error) {
	plug, err := storagePluginForCaller(name)
	if err != nil {
		return nil, "", ctx, err
	}
	return plug.GetStream(path, offset, ctx)
}

func (directPlugins) StorageList(name, path string, ctx map[string]any) ([]easyrest.StorageEntry, error) {
	plug, err := storagePluginForCaller(name)
	if err != nil {
		return nil, err
	}
	return plug.List(path, ctx)
}

func (directPlugins) StorageDelete(name, path string, ctx map[string]any) error {
	plug, err := storagePluginForCaller(name)
	if err != nil {
		return err
	}
	return plug.Delete(path, ctx)
}

func storagePluginForCaller(name string) (easyrest.StoragePlugin, error) {
	if name == "" {
		return nil, errors.New("storage plugin name is empty")
	}
	ref, ok := storagePluginByName(name)
	if !ok {
		return nil, fmt.Errorf("storage plugin %q is not loaded", name)
	}
	return ref.Plugin, nil
}

// cacheKeys is the in-process key API on a loaded cache middleware.
// A plugin started from path does not implement it.
type cacheKeys interface {
	Get(key string) (string, error)
	Set(key, value string, ttl *time.Duration) error
	Delete(key string) error
}

func cacheStore(name, key string) (cacheKeys, error) {
	if name == "" {
		return nil, errors.New("cache plugin name is empty")
	}
	if key == "" {
		return nil, errors.New("cache key is empty")
	}
	loaded := MiddlewarePlugins.Load()
	if loaded == nil {
		return nil, fmt.Errorf("cache plugin %q is not loaded", name)
	}
	plug, ok := (*loaded)[name]
	if !ok || plug == nil {
		return nil, fmt.Errorf("cache plugin %q is not loaded", name)
	}
	store, ok := plug.(cacheKeys)
	if !ok {
		return nil, fmt.Errorf("cache plugin %q store is unavailable", name)
	}
	return store, nil
}

func dispatchHost(method, path string, req easyrest.HostCall) (easyrest.HostResult, error) {
	var resp easyrest.HostResult
	err := dispatchNamed(method, path, req, &resp)
	return resp, err
}
