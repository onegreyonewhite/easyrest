package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/rpc"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// sharedTxHeader carries a shared transaction id on internal requests only.
const sharedTxHeader = "X-Easyrest-Tx"

type internalCallKey struct{}

func markInternal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), internalCallKey{}, true)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func internalCall(r *http.Request) bool {
	flag, _ := r.Context().Value(internalCallKey{}).(bool)
	return flag
}

func buildInternalRouter() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(markInternal)
	tables := r.With(
		sanitizeTableMiddleware,
		requirePluginMiddleware(tableResource),
		tablePreRequestMiddleware,
	)
	const tablePath = "/api/{db}/{table}/"
	tables.HandleFunc(tablePath, tableMethodNotAllowed)
	tables.Get(tablePath, tableGet)
	tables.Post(tablePath, tablePost)
	tables.Patch(tablePath, tablePatch)
	tables.Delete(tablePath, tableDelete)
	r.Post("/api/{db}/rpc/{func}/", rpcHandler)
	return r
}

func DispatchInternal(method, path string, header http.Header, body []byte) (int, http.Header, []byte) {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	for key, values := range header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	buildInternalRouter().ServeHTTP(rec, req)
	return rec.Code, rec.Header().Clone(), append([]byte(nil), rec.Body.Bytes()...)
}

type InternalCall = easyrest.HostCall

type InternalResult = easyrest.HostResult

type Internal struct{}

func (Internal) TableGet(req InternalCall, resp *InternalResult) error {
	return dispatchNamed(http.MethodGet, internalTablePath(req), req, resp)
}

func (Internal) TableCreate(req InternalCall, resp *InternalResult) error {
	return dispatchNamed(http.MethodPost, internalTablePath(req), req, resp)
}

func (Internal) TableUpdate(req InternalCall, resp *InternalResult) error {
	return dispatchNamed(http.MethodPatch, internalTablePath(req), req, resp)
}

func (Internal) TableDelete(req InternalCall, resp *InternalResult) error {
	return dispatchNamed(http.MethodDelete, internalTablePath(req), req, resp)
}

func (Internal) CallFunction(req InternalCall, resp *InternalResult) error {
	path := "/api/" + req.DB + "/rpc/" + req.Name + "/"
	return dispatchNamed(http.MethodPost, path, req, resp)
}

func (Internal) BeginTx(req easyrest.HostTxRequest, resp *easyrest.HostTxResponse) error {
	txr, err := dbTransactor(req.DB)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	pluginCtx := map[string]any{}
	if !req.Deadline.IsZero() {
		pluginCtx[easyrest.SharedTxDeadlineKey] = req.Deadline
	}
	id, _, err := txr.BeginTx(pluginCtx)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	resp.ID = id
	return nil
}

func (Internal) CommitTx(req easyrest.HostTxRequest, resp *easyrest.HostTxResponse) error {
	txr, err := dbTransactor(req.DB)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	if _, err := txr.CommitTx(req.ID, nil); err != nil {
		resp.Error = err.Error()
	}
	return nil
}

func (Internal) RollbackTx(req easyrest.HostTxRequest, resp *easyrest.HostTxResponse) error {
	txr, err := dbTransactor(req.DB)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	if err := txr.RollbackTx(req.ID); err != nil {
		resp.Error = err.Error()
	}
	return nil
}

func dbTransactor(dbKey string) (easyrest.DBTransactor, error) {
	dbKey = strings.ToLower(strings.TrimSpace(dbKey))
	if dbKey == "" {
		return nil, errors.New("database name is empty")
	}
	plugins := DbPlugins.Load()
	if plugins == nil {
		return nil, fmt.Errorf("database %q is not loaded", dbKey)
	}
	plug, ok := (*plugins)[dbKey]
	if !ok || plug == nil {
		return nil, fmt.Errorf("database %q is not loaded", dbKey)
	}
	txr, ok := plug.(easyrest.DBTransactor)
	if !ok {
		return nil, easyrest.ErrSharedTxUnsupported
	}
	return txr, nil
}

func internalTablePath(req InternalCall) string {
	return "/api/" + req.DB + "/" + req.Name + "/"
}

func dispatchNamed(method, path string, req InternalCall, resp *InternalResult) error {
	if req.Query != "" {
		path += "?" + req.Query
	}
	header := make(http.Header, len(req.Header)+1)
	for key, value := range req.Header {
		header.Set(key, value)
	}
	if req.TxID != "" {
		header.Set(sharedTxHeader, req.TxID)
	}
	status, hdr, body := DispatchInternal(method, path, header, req.Body)
	resp.Status = status
	resp.Header = hdr
	resp.Body = body
	return nil
}

func serveInternalRPC(lis net.Listener) {
	srv := rpc.NewServer()
	if err := srv.RegisterName("Internal", Internal{}); err != nil {
		stdlog.Printf("internal rpc: %v", err)
		return
	}
	srv.Accept(lis)
}

func currentHostRPC() easyrest.HostRPC {
	cfg := currentConfig().InternalRPC
	return easyrest.HostRPC{Network: cfg.Network, Address: cfg.Address, FD: cfg.FD}
}

func listenInternalRPC(cfg config.InternalRPCConfig) (net.Listener, error) {
	if cfg.FD != 0 {
		file := os.NewFile(uintptr(cfg.FD), "internal-rpc")
		lis, err := net.FileListener(file)
		file.Close()
		return lis, err
	}
	if cfg.Address == "" {
		return nil, nil
	}
	return net.Listen(cfg.Network, cfg.Address)
}
