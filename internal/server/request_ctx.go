package server

import (
	"context"
	"net/http"
	"net/url"
	"sync"

	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

type apiRequestCtxKey struct{}

var apiRequestKey = &apiRequestCtxKey{}

// apiRequestPool reuses bags so the extra Request.WithContext clone stays
// within the BenchmarkTableGet +2 allocs/op budget.
var apiRequestPool = sync.Pool{
	New: func() any { return &apiRequest{} },
}

// apiRequest is the per-request bag shared by host middleware and table
// handlers. One WithContext stores the pointer; later middleware mutate it.
type apiRequest struct {
	dbKey     string
	resource  string
	userID    string
	dbPlug    easyrest.DBPlugin
	cfg       *config.Config
	pluginCfg config.PluginConfig
	pluginCtx map[string]any
	query     url.Values
	respType  string
	isPublic  bool
}

func newAPIRequest(r *http.Request) (*apiRequest, *http.Request) {
	bag := apiRequestPool.Get().(*apiRequest)
	*bag = apiRequest{}
	return bag, r.WithContext(context.WithValue(r.Context(), apiRequestKey, bag))
}

func releaseAPIRequest(bag *apiRequest) {
	if bag == nil {
		return
	}
	*bag = apiRequest{}
	apiRequestPool.Put(bag)
}

func apiRequestFrom(r *http.Request) *apiRequest {
	bag, _ := r.Context().Value(apiRequestKey).(*apiRequest)
	return bag
}
