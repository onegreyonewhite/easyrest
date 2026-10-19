package server

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"sync/atomic"

	"github.com/go-chi/chi/v5"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// HandlerError is a rest handler failure with an HTTP status.
// A zero Status is reported as 500.
type HandlerError struct {
	Status  int
	Message string
}

func (e *HandlerError) Error() string {
	if e == nil || e.Message == "" {
		return "handler error"
	}
	return e.Message
}

// PluginCaller is the in-process internal RPC available to a rest handler.
// Calls use the same dispatch path as Internal.TableGet and the other
// Internal methods. They do not open a socket.
type PluginCaller interface {
	TableGet(easyrest.HostCall) (easyrest.HostResult, error)
	TableCreate(easyrest.HostCall) (easyrest.HostResult, error)
	TableUpdate(easyrest.HostCall) (easyrest.HostResult, error)
	TableDelete(easyrest.HostCall) (easyrest.HostResult, error)
	CallFunction(easyrest.HostCall) (easyrest.HostResult, error)
}

// Call is one invocation of a Go rest handler.
// UserID is the authenticated rest user. Internal RPC calls do not receive it.
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

var restHandlers atomic.Pointer[map[string]Handler]

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
		}
	}
	return nil
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

// directPlugins calls DispatchInternal in this process.
type directPlugins struct{}

var _ PluginCaller = directPlugins{}

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

func dispatchHost(method, path string, req easyrest.HostCall) (easyrest.HostResult, error) {
	var resp easyrest.HostResult
	err := dispatchNamed(method, path, req, &resp)
	return resp, err
}
