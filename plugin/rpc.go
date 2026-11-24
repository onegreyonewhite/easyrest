package plugin

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"math"
	"net/rpc"
	"slices"
	"time"

	"github.com/hashicorp/go-plugin"
)

// DBPluginRPC is the client wrapper.
type DBPluginRPC struct{ client *rpc.Client }

var _ DBTransactor = (*DBPluginRPC)(nil)

func (g *DBPluginRPC) InitConnection(uri string) error {
	req := InitConnectionRequest{URI: uri}
	var resp InitConnectionResponse
	err := g.client.Call("Plugin.InitConnection", req, &resp)
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	return nil
}

func (g *DBPluginRPC) TableGet(userID, table string, selectFields []string, where map[string]any,
	ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, map[string]any, error) {
	req := TableGetRequest{
		UserID:       userID,
		Table:        table,
		SelectFields: selectFields,
		Where:        where,
		Ordering:     ordering,
		GroupBy:      groupBy,
		Limit:        limit,
		Offset:       offset,
		Ctx:          ctx,
	}

	var resp TableGetResponse
	err := g.client.Call("Plugin.TableGet", req, &resp)

	if err != nil {
		return nil, nil, err
	}
	outCtx := resp.Ctx
	resp.Ctx = nil
	if resp.Error != "" {
		return nil, outCtx, errors.New(resp.Error)
	}
	result := resp.Rows
	resp.Rows = nil
	return result, outCtx, nil
}

func (g *DBPluginRPC) TableCreate(userID, table string, data []map[string]any, ctx map[string]any) ([]map[string]any, map[string]any, error) {
	req := TableCreateRequest{
		UserID: userID,
		Table:  table,
		Data:   data,
		Ctx:    ctx,
	}
	var resp TableCreateResponse
	err := g.client.Call("Plugin.TableCreate", req, &resp)
	if err != nil {
		return nil, nil, err
	}
	outCtx := resp.Ctx
	resp.Ctx = nil
	if resp.Error != "" {
		return nil, outCtx, errors.New(resp.Error)
	}
	rows := resp.Rows
	resp.Rows = nil
	return rows, outCtx, nil
}

func (g *DBPluginRPC) TableUpdate(userID, table string, data map[string]any, where map[string]any, ctx map[string]any) (int, map[string]any, error) {
	req := TableUpdateRequest{
		UserID: userID,
		Table:  table,
		Data:   data,
		Where:  where,
		Ctx:    ctx,
	}
	var resp TableUpdateResponse
	err := g.client.Call("Plugin.TableUpdate", req, &resp)
	if err != nil {
		return 0, nil, err
	}
	outCtx := resp.Ctx
	resp.Ctx = nil
	if resp.Error != "" {
		return 0, outCtx, errors.New(resp.Error)
	}
	return resp.Updated, outCtx, nil
}

func (g *DBPluginRPC) TableDelete(userID, table string, where map[string]any, ctx map[string]any) (int, map[string]any, error) {
	req := TableDeleteRequest{
		UserID: userID,
		Table:  table,
		Where:  where,
		Ctx:    ctx,
	}
	var resp TableDeleteResponse
	err := g.client.Call("Plugin.TableDelete", req, &resp)
	if err != nil {
		return 0, nil, err
	}
	outCtx := resp.Ctx
	resp.Ctx = nil
	if resp.Error != "" {
		return 0, outCtx, errors.New(resp.Error)
	}
	return resp.Deleted, outCtx, nil
}

func (g *DBPluginRPC) CallFunction(userID, funcName string, data map[string]any, ctx map[string]any) (any, map[string]any, error) {
	req := CallFunctionRequest{
		UserID:   userID,
		FuncName: funcName,
		Data:     data,
		Ctx:      ctx,
	}
	var resp CallFunctionResponse
	err := g.client.Call("Plugin.CallFunction", req, &resp)
	if err != nil {
		return nil, nil, err
	}
	outCtx := resp.Ctx
	resp.Ctx = nil
	if resp.Error != "" {
		return nil, outCtx, errors.New(resp.Error)
	}
	return resp.Result, outCtx, nil
}

// New GetSchema method.
func (g *DBPluginRPC) GetSchema(ctx map[string]any) (any, map[string]any, error) {
	req := GetSchemaRequest{Ctx: ctx}
	var resp GetSchemaResponse
	err := g.client.Call("Plugin.GetSchema", req, &resp)
	if err != nil {
		return nil, nil, err
	}
	outCtx := resp.Ctx
	resp.Ctx = nil
	if resp.Error != "" {
		return nil, outCtx, errors.New(resp.Error)
	}
	return resp.Schema, outCtx, nil
}

func (g *DBPluginRPC) BeginTx(ctx map[string]any) (string, map[string]any, error) {
	var resp BeginTxResponse
	if err := g.client.Call("Plugin.BeginTx", BeginTxRequest{Ctx: ctx}, &resp); err != nil {
		return "", nil, err
	}
	outCtx := resp.Ctx
	resp.Ctx = nil
	if resp.Error != "" {
		return "", outCtx, errors.New(resp.Error)
	}
	return resp.ID, outCtx, nil
}

func (g *DBPluginRPC) CommitTx(id string, ctx map[string]any) (map[string]any, error) {
	var resp CommitTxResponse
	if err := g.client.Call("Plugin.CommitTx", CommitTxRequest{ID: id, Ctx: ctx}, &resp); err != nil {
		return nil, err
	}
	outCtx := resp.Ctx
	resp.Ctx = nil
	if resp.Error != "" {
		return outCtx, errors.New(resp.Error)
	}
	return outCtx, nil
}

func (g *DBPluginRPC) RollbackTx(id string) error {
	var resp RollbackTxResponse
	if err := g.client.Call("Plugin.RollbackTx", RollbackTxRequest{ID: id}, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	return nil
}

// DBPluginRPCServer is the server-side RPC implementation.
type DBPluginRPCServer struct {
	Impl DBPlugin
}

func (s *DBPluginRPCServer) InitConnection(req InitConnectionRequest, resp *InitConnectionResponse) error {
	err := s.Impl.InitConnection(req.URI)
	if err != nil {
		resp.Error = err.Error()
	}
	return nil
}

func (s *DBPluginRPCServer) TableGet(req TableGetRequest, resp *TableGetResponse) error {
	rows, outCtx, err := s.Impl.TableGet(req.UserID, req.Table, req.SelectFields, req.Where, req.Ordering, req.GroupBy, req.Limit, req.Offset, req.Ctx)
	resp.Ctx = outCtx
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	resp.Rows = rows
	return nil
}

func (s *DBPluginRPCServer) TableCreate(req TableCreateRequest, resp *TableCreateResponse) error {
	rows, outCtx, err := s.Impl.TableCreate(req.UserID, req.Table, req.Data, req.Ctx)
	resp.Ctx = outCtx
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	resp.Rows = rows
	return nil
}

func (s *DBPluginRPCServer) TableUpdate(req TableUpdateRequest, resp *TableUpdateResponse) error {
	updated, outCtx, err := s.Impl.TableUpdate(req.UserID, req.Table, req.Data, req.Where, req.Ctx)
	resp.Ctx = outCtx
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	resp.Updated = updated
	return nil
}

func (s *DBPluginRPCServer) TableDelete(req TableDeleteRequest, resp *TableDeleteResponse) error {
	deleted, outCtx, err := s.Impl.TableDelete(req.UserID, req.Table, req.Where, req.Ctx)
	resp.Ctx = outCtx
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	resp.Deleted = deleted
	return nil
}

func (s *DBPluginRPCServer) CallFunction(req CallFunctionRequest, resp *CallFunctionResponse) error {
	result, outCtx, err := s.Impl.CallFunction(req.UserID, req.FuncName, req.Data, req.Ctx)
	resp.Ctx = outCtx
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	resp.Result = result
	return nil
}

// New GetSchema server method.
func (s *DBPluginRPCServer) GetSchema(req GetSchemaRequest, resp *GetSchemaResponse) error {
	schema, outCtx, err := s.Impl.GetSchema(req.Ctx)
	resp.Ctx = outCtx
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	resp.Schema = schema
	return nil
}

func (s *DBPluginRPCServer) BeginTx(req BeginTxRequest, resp *BeginTxResponse) error {
	txr, ok := s.Impl.(DBTransactor)
	if !ok {
		resp.Error = ErrSharedTxUnsupported.Error()
		return nil
	}
	id, outCtx, err := txr.BeginTx(req.Ctx)
	resp.ID = id
	resp.Ctx = outCtx
	if err != nil {
		resp.Error = err.Error()
	}
	return nil
}

func (s *DBPluginRPCServer) CommitTx(req CommitTxRequest, resp *CommitTxResponse) error {
	txr, ok := s.Impl.(DBTransactor)
	if !ok {
		resp.Error = ErrSharedTxUnsupported.Error()
		return nil
	}
	outCtx, err := txr.CommitTx(req.ID, req.Ctx)
	resp.Ctx = outCtx
	if err != nil {
		resp.Error = err.Error()
	}
	return nil
}

func (s *DBPluginRPCServer) RollbackTx(req RollbackTxRequest, resp *RollbackTxResponse) error {
	txr, ok := s.Impl.(DBTransactor)
	if !ok {
		resp.Error = ErrSharedTxUnsupported.Error()
		return nil
	}
	if err := txr.RollbackTx(req.ID); err != nil {
		resp.Error = err.Error()
	}
	return nil
}

// DBPluginPlugin wraps the DBPlugin implementation for go-plugin.
type DBPluginPlugin struct {
	Impl DBPlugin
}

func (p *DBPluginPlugin) Server(broker *plugin.MuxBroker) (any, error) {
	return &DBPluginRPCServer{Impl: p.Impl}, nil
}

func (p *DBPluginPlugin) Client(broker *plugin.MuxBroker, c *rpc.Client) (any, error) {
	return &DBPluginRPC{client: c}, nil
}

// --- DBQueryPlugin ---

// DBQueryPluginRPC is the client wrapper for DBQueryPlugin.
type DBQueryPluginRPC struct{ client *rpc.Client }

func (q *DBQueryPluginRPC) InitConnection(uri string) error {
	req := InitConnectionRequest{URI: uri}
	var resp InitConnectionResponse
	err := q.client.Call("Plugin.InitConnection", req, &resp)
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	return nil
}

func (q *DBQueryPluginRPC) QueryCall(query string, ctx map[string]any) ([]map[string]any, error) {
	req := QueryCallRequest{Query: query, Ctx: ctx}
	var resp QueryCallResponse
	err := q.client.Call("Plugin.QueryCall", req, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, errors.New(resp.Error)
	}
	result := resp.Rows
	resp.Rows = nil
	return result, nil
}

// DBQueryPluginRPCServer is the server-side RPC implementation for DBQueryPlugin.
type DBQueryPluginRPCServer struct {
	Impl DBQueryPlugin
}

func (s *DBQueryPluginRPCServer) InitConnection(req InitConnectionRequest, resp *InitConnectionResponse) error {
	err := s.Impl.InitConnection(req.URI)
	if err != nil {
		resp.Error = err.Error()
	}
	return nil
}

func (s *DBQueryPluginRPCServer) QueryCall(req QueryCallRequest, resp *QueryCallResponse) error {
	rows, err := s.Impl.QueryCall(req.Query, req.Ctx)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	resp.Rows = rows
	return nil
}

// DBQueryPluginPlugin wraps the DBQueryPlugin implementation for go-plugin.
type DBQueryPluginPlugin struct {
	Impl DBQueryPlugin
}

func (p *DBQueryPluginPlugin) Server(broker *plugin.MuxBroker) (any, error) {
	return &DBQueryPluginRPCServer{Impl: p.Impl}, nil
}

func (p *DBQueryPluginPlugin) Client(broker *plugin.MuxBroker, c *rpc.Client) (any, error) {
	return &DBQueryPluginRPC{client: c}, nil
}

// --- End DBQueryPlugin ---

// AuthPluginRPC is the client wrapper for AuthPlugin.
type AuthPluginRPC struct{ client *rpc.Client }

func (a *AuthPluginRPC) Init(settings map[string]any, host HostRPC) (AuthInfo, error) {
	req := AuthInitRequest{Settings: settings, Host: host}
	var resp AuthInitResponse
	err := a.client.Call("Plugin.Init", req, &resp)
	if err != nil {
		return AuthInfo{}, err
	}
	if resp.Error != "" {
		return resp.Info, errors.New(resp.Error)
	}
	return resp.Info, nil
}

func (a *AuthPluginRPC) Authenticate(headers map[string]string, method string, path string, query string) (map[string]any, error) {
	req := AuthAuthenticateRequest{Headers: headers, Method: method, Path: path, Query: query}
	var resp AuthAuthenticateResponse
	err := a.client.Call("Plugin.Authenticate", req, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, errors.New(resp.Error)
	}
	return resp.Claims, nil
}

// AuthPluginRPCServer is the server-side RPC implementation for AuthPlugin.
type AuthPluginRPCServer struct {
	Impl AuthPlugin
}

func (s *AuthPluginRPCServer) Init(req AuthInitRequest, resp *AuthInitResponse) error {
	info, err := s.Impl.Init(req.Settings, req.Host)
	resp.Info = info
	if err != nil {
		resp.Error = err.Error()
	}
	return nil
}

func (s *AuthPluginRPCServer) Authenticate(req AuthAuthenticateRequest, resp *AuthAuthenticateResponse) error {
	claims, err := s.Impl.Authenticate(req.Headers, req.Method, req.Path, req.Query)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	resp.Claims = claims
	return nil
}

// AuthPluginPlugin wraps the AuthPlugin implementation for go-plugin.
type AuthPluginPlugin struct {
	Impl AuthPlugin
}

func (p *AuthPluginPlugin) Server(broker *plugin.MuxBroker) (any, error) {
	return &AuthPluginRPCServer{Impl: p.Impl}, nil
}

func (p *AuthPluginPlugin) Client(broker *plugin.MuxBroker, c *rpc.Client) (any, error) {
	return &AuthPluginRPC{client: c}, nil
}

// --- End AuthPlugin ---

// MiddlewarePluginRPC is the client wrapper for MiddlewarePlugin.
type MiddlewarePluginRPC struct{ client *rpc.Client }

func (m *MiddlewarePluginRPC) Init(settings map[string]any, host HostRPC) (MiddlewareInfo, error) {
	req := MiddlewareInitRequest{Settings: settings, Host: host}
	var resp MiddlewareInitResponse
	err := m.client.Call("Plugin.Init", req, &resp)
	if err != nil {
		return MiddlewareInfo{}, err
	}
	if resp.Error != "" {
		return resp.Info, errors.New(resp.Error)
	}
	return resp.Info, nil
}

func (m *MiddlewarePluginRPC) PreRequest(dbKey string, ctx map[string]any) (map[string]any, *int, error) {
	req := MiddlewarePreRequestRequest{DbKey: dbKey, Ctx: ctx}
	var resp MiddlewarePreRequestResponse
	err := m.client.Call("Plugin.PreRequest", req, &resp)
	if err != nil {
		return nil, nil, err
	}
	if resp.Error != "" {
		if resp.Status != nil {
			return resp.Ctx, resp.Status, errors.New(resp.Error)
		}
		return resp.Ctx, nil, errors.New(resp.Error)
	}
	return resp.Ctx, resp.Status, nil
}

func (m *MiddlewarePluginRPC) PostRequest(dbKey string, ctx map[string]any) (map[string]string, error) {
	req := MiddlewarePostRequestRequest{DbKey: dbKey, Ctx: ctx}
	var resp MiddlewarePostRequestResponse
	err := m.client.Call("Plugin.PostRequest", req, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return resp.Headers, errors.New(resp.Error)
	}
	return resp.Headers, nil
}

// MiddlewarePluginRPCServer is the server-side RPC implementation for MiddlewarePlugin.
type MiddlewarePluginRPCServer struct {
	Impl MiddlewarePlugin
}

func (s *MiddlewarePluginRPCServer) Init(req MiddlewareInitRequest, resp *MiddlewareInitResponse) error {
	info, err := s.Impl.Init(req.Settings, req.Host)
	resp.Info = info
	if err != nil {
		resp.Error = err.Error()
	}
	return nil
}

func (s *MiddlewarePluginRPCServer) PreRequest(req MiddlewarePreRequestRequest, resp *MiddlewarePreRequestResponse) error {
	ctx, status, err := s.Impl.PreRequest(req.DbKey, req.Ctx)
	resp.Ctx = ctx
	resp.Status = status
	if err != nil {
		resp.Error = err.Error()
	}
	return nil
}

func (s *MiddlewarePluginRPCServer) PostRequest(req MiddlewarePostRequestRequest, resp *MiddlewarePostRequestResponse) error {
	headers, err := s.Impl.PostRequest(req.DbKey, req.Ctx)
	resp.Headers = headers
	if err != nil {
		resp.Error = err.Error()
	}
	return nil
}

// MiddlewarePluginPlugin wraps the MiddlewarePlugin implementation for go-plugin.
type MiddlewarePluginPlugin struct {
	Impl MiddlewarePlugin
}

func (p *MiddlewarePluginPlugin) Server(broker *plugin.MuxBroker) (any, error) {
	return &MiddlewarePluginRPCServer{Impl: p.Impl}, nil
}

func (p *MiddlewarePluginPlugin) Client(broker *plugin.MuxBroker, c *rpc.Client) (any, error) {
	return &MiddlewarePluginRPC{client: c}, nil
}

// --- End MiddlewarePlugin ---

// ContentInitRequest holds settings for a content plugin.
type ContentInitRequest struct {
	Settings map[string]any
}

// ContentInitResponse is the Init result or an error string.
type ContentInitResponse struct {
	Info  ContentInfo
	Error string
}

// ContentParseRequest is a raw body plus the plugin context.
type ContentParseRequest struct {
	Body []byte
	Ctx  map[string]any
}

// ContentParseResponse is the parsed value. Value is a map or a slice.
type ContentParseResponse struct {
	Value any
	Ctx   map[string]any
	Error string
}

// ContentRenderRequest is the value to render and the plugin context.
type ContentRenderRequest struct {
	Data any
	Ctx  map[string]any
}

// ContentRenderResponse is the rendered body bytes.
type ContentRenderResponse struct {
	Body  []byte
	Ctx   map[string]any
	Error string
}

// ContentPrepareGetRequest is the limit, offset, and page size for the next fetch.
type ContentPrepareGetRequest struct {
	Limit  int
	Offset int
	Page   int
}

// ContentPrepareGetResponse is the next TableGet windows.
type ContentPrepareGetResponse struct {
	Windows []ContentWindow
	Repeat  bool
}

// ContentPrepareCreateRequest is the parsed body and the page size.
type ContentPrepareCreateRequest struct {
	Body any
	Page int
}

// ContentPrepareCreateResponse is the body split into TableCreate chunks.
type ContentPrepareCreateResponse struct {
	Chunks []any
	Error  string
}

// ContentPluginRPC is the client wrapper for ContentPlugin.
type ContentPluginRPC struct{ client *rpc.Client }

func (c *ContentPluginRPC) Init(settings map[string]any) (ContentInfo, error) {
	req := ContentInitRequest{Settings: settings}
	var resp ContentInitResponse
	if err := c.client.Call("Plugin.Init", req, &resp); err != nil {
		return ContentInfo{}, err
	}
	if resp.Error != "" {
		return resp.Info, errors.New(resp.Error)
	}
	return resp.Info, nil
}

func (c *ContentPluginRPC) Parse(body []byte, ctx map[string]any) (any, map[string]any, error) {
	req := ContentParseRequest{Body: body, Ctx: ctx}
	var resp ContentParseResponse
	if err := c.client.Call("Plugin.Parse", req, &resp); err != nil {
		return nil, nil, err
	}
	if resp.Error != "" {
		return resp.Value, resp.Ctx, errors.New(resp.Error)
	}
	return resp.Value, resp.Ctx, nil
}

func (c *ContentPluginRPC) Render(data any, ctx map[string]any) (any, map[string]any, error) {
	req := ContentRenderRequest{Data: data, Ctx: ctx}
	var resp ContentRenderResponse
	if err := c.client.Call("Plugin.Render", req, &resp); err != nil {
		return nil, nil, err
	}
	if resp.Error != "" {
		return resp.Body, resp.Ctx, errors.New(resp.Error)
	}
	return resp.Body, resp.Ctx, nil
}

func (c *ContentPluginRPC) PrepareGet(limit, offset, page int) ([]ContentWindow, bool) {
	req := ContentPrepareGetRequest{Limit: limit, Offset: offset, Page: page}
	var resp ContentPrepareGetResponse
	if err := c.client.Call("Plugin.PrepareGet", req, &resp); err != nil {
		return nil, false
	}
	return resp.Windows, resp.Repeat
}

func (c *ContentPluginRPC) PrepareCreate(body any, page int) []any {
	req := ContentPrepareCreateRequest{Body: body, Page: page}
	var resp ContentPrepareCreateResponse
	if err := c.client.Call("Plugin.PrepareCreate", req, &resp); err != nil {
		return nil
	}
	if resp.Error != "" {
		return nil
	}
	return resp.Chunks
}

// ContentPluginRPCServer is the server-side RPC implementation for ContentPlugin.
type ContentPluginRPCServer struct {
	Impl ContentPlugin
}

func (s *ContentPluginRPCServer) Init(req ContentInitRequest, resp *ContentInitResponse) error {
	info, err := s.Impl.Init(req.Settings)
	resp.Info = info
	if err != nil {
		resp.Error = err.Error()
	}
	return nil
}

func (s *ContentPluginRPCServer) Parse(req ContentParseRequest, resp *ContentParseResponse) error {
	value, ctx, err := s.Impl.Parse(req.Body, req.Ctx)
	if err != nil {
		resp.Error = err.Error()
	}
	if hasNonFinite(value) || hasNonFinite(ctx) {
		resp.Error = "non-finite float"
		return nil
	}
	resp.Value = value
	resp.Ctx = ctx
	return nil
}

func (s *ContentPluginRPCServer) Render(req ContentRenderRequest, resp *ContentRenderResponse) error {
	value, ctx, err := s.Impl.Render(req.Data, req.Ctx)
	if hasNonFinite(value) || hasNonFinite(ctx) {
		resp.Error = "non-finite float"
		return nil
	}
	resp.Ctx = ctx
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	body, err := RenderedBytes(value)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	resp.Body = body
	return nil
}

func (s *ContentPluginRPCServer) PrepareGet(req ContentPrepareGetRequest, resp *ContentPrepareGetResponse) error {
	windows, repeat := s.Impl.PrepareGet(req.Limit, req.Offset, req.Page)
	resp.Windows = windows
	resp.Repeat = repeat
	return nil
}

func (s *ContentPluginRPCServer) PrepareCreate(req ContentPrepareCreateRequest, resp *ContentPrepareCreateResponse) error {
	chunks := s.Impl.PrepareCreate(req.Body, req.Page)
	if hasNonFinite(chunks) {
		resp.Error = "non-finite float"
		return nil
	}
	resp.Chunks = chunks
	return nil
}

func hasNonFinite(v any) bool {
	switch n := v.(type) {
	case float32:
		return math.IsNaN(float64(n)) || math.IsInf(float64(n), 0)
	case float64:
		return math.IsNaN(n) || math.IsInf(n, 0)
	case map[string]any:
		for _, item := range n {
			if hasNonFinite(item) {
				return true
			}
		}
	case []any:
		if slices.ContainsFunc(n, hasNonFinite) {
			return true
		}
	case []map[string]any:
		for i := range n {
			if hasNonFinite(n[i]) {
				return true
			}
		}
	}
	return false
}

// ContentPluginPlugin wraps a ContentPlugin for go-plugin.
type ContentPluginPlugin struct {
	Impl ContentPlugin
}

func (p *ContentPluginPlugin) Server(broker *plugin.MuxBroker) (any, error) {
	return &ContentPluginRPCServer{Impl: p.Impl}, nil
}

func (p *ContentPluginPlugin) Client(broker *plugin.MuxBroker, c *rpc.Client) (any, error) {
	return &ContentPluginRPC{client: c}, nil
}

// --- End ContentPlugin ---

// StorageInitRequest holds settings for a storage plugin.
type StorageInitRequest struct {
	Settings map[string]any
	Host     HostRPC
}

// StorageInitResponse is the storage Init result.
type StorageInitResponse struct {
	Info  StorageInfo
	Error string
}

// StoragePutRequest is a relative path, file bytes, and plugin context.
type StoragePutRequest struct {
	Path string
	Body []byte
	Ctx  map[string]any
}

// StoragePutResponse is the stored relative path.
type StoragePutResponse struct {
	Path  string
	Ctx   map[string]any
	Error string
}

// StoragePathRequest is a relative path and plugin context.
type StoragePathRequest struct {
	Path string
	Ctx  map[string]any
}

// StorageGetURLRequest is a batch of relative paths and the plugin context.
type StorageGetURLRequest struct {
	Paths []string
	Ctx   map[string]any
}

// StorageGetURLResponse is one URL and MIME type per requested path.
type StorageGetURLResponse struct {
	URLs  []StorageURL
	Error string
}

// StorageMetadataResponse is file metadata.
type StorageMetadataResponse struct {
	Meta  StorageMeta
	Error string
}

// StorageGetBinResponse is the file bytes and MIME type.
type StorageGetBinResponse struct {
	Body  []byte
	Mime  string
	Ctx   map[string]any
	Error string
}

// StorageListResponse is one directory listing.
type StorageListResponse struct {
	Entries []StorageEntry
	Error   string
}

// StorageDeleteResponse reports a delete error.
type StorageDeleteResponse struct {
	Error string
}

// StoragePluginRPC is the client wrapper for StoragePlugin.
type StoragePluginRPC struct{ client *rpc.Client }

func (c *StoragePluginRPC) Init(settings map[string]any, host HostRPC) (StorageInfo, error) {
	var resp StorageInitResponse
	if err := c.client.Call("Plugin.Init", StorageInitRequest{Settings: settings, Host: host}, &resp); err != nil {
		return StorageInfo{}, err
	}
	if resp.Error != "" {
		return resp.Info, errors.New(resp.Error)
	}
	return resp.Info, nil
}

func (c *StoragePluginRPC) Put(path string, body []byte, ctx map[string]any) (string, map[string]any, error) {
	var resp StoragePutResponse
	if err := c.client.Call("Plugin.Put", StoragePutRequest{Path: path, Body: body, Ctx: ctx}, &resp); err != nil {
		return "", nil, err
	}
	if resp.Error != "" {
		return resp.Path, resp.Ctx, errors.New(resp.Error)
	}
	return resp.Path, resp.Ctx, nil
}

func (c *StoragePluginRPC) PutStream(path string, r io.Reader, ctx map[string]any) (string, map[string]any, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return "", ctx, err
	}
	return c.Put(path, body, ctx)
}

func (c *StoragePluginRPC) GetUrl(paths []string, ctx map[string]any) ([]StorageURL, error) {
	var resp StorageGetURLResponse
	if err := c.client.Call("Plugin.GetUrl", StorageGetURLRequest{Paths: paths, Ctx: ctx}, &resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return resp.URLs, errors.New(resp.Error)
	}
	return resp.URLs, nil
}

func (c *StoragePluginRPC) GetMetadata(path string, ctx map[string]any) (StorageMeta, error) {
	var resp StorageMetadataResponse
	if err := c.client.Call("Plugin.GetMetadata", StoragePathRequest{Path: path, Ctx: ctx}, &resp); err != nil {
		return StorageMeta{}, err
	}
	if resp.Error != "" {
		return resp.Meta, errors.New(resp.Error)
	}
	return resp.Meta, nil
}

func (c *StoragePluginRPC) GetBin(path string, ctx map[string]any) ([]byte, string, map[string]any, error) {
	var resp StorageGetBinResponse
	if err := c.client.Call("Plugin.GetBin", StoragePathRequest{Path: path, Ctx: ctx}, &resp); err != nil {
		return nil, "", nil, err
	}
	if resp.Error != "" {
		return resp.Body, resp.Mime, resp.Ctx, errors.New(resp.Error)
	}
	return resp.Body, resp.Mime, resp.Ctx, nil
}

func (c *StoragePluginRPC) GetStream(path string, offset int64, ctx map[string]any) (io.ReadCloser, string, map[string]any, error) {
	if offset < 0 {
		return nil, "", ctx, fmt.Errorf("storage: negative offset")
	}
	body, mimeType, ctxOut, err := c.GetBin(path, ctx)
	if err != nil {
		return nil, "", ctxOut, err
	}
	if offset > int64(len(body)) {
		offset = int64(len(body))
	}
	return io.NopCloser(bytes.NewReader(body[offset:])), mimeType, ctxOut, nil
}

func (c *StoragePluginRPC) List(path string, ctx map[string]any) ([]StorageEntry, error) {
	var resp StorageListResponse
	if err := c.client.Call("Plugin.List", StoragePathRequest{Path: path, Ctx: ctx}, &resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return resp.Entries, errors.New(resp.Error)
	}
	return resp.Entries, nil
}

func (c *StoragePluginRPC) Delete(path string, ctx map[string]any) error {
	var resp StorageDeleteResponse
	if err := c.client.Call("Plugin.Delete", StoragePathRequest{Path: path, Ctx: ctx}, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	return nil
}

// StoragePluginRPCServer is the server-side RPC implementation for StoragePlugin.
type StoragePluginRPCServer struct {
	Impl StoragePlugin
}

func (s *StoragePluginRPCServer) Init(req StorageInitRequest, resp *StorageInitResponse) error {
	info, err := s.Impl.Init(req.Settings, req.Host)
	resp.Info = info
	if err != nil {
		resp.Error = err.Error()
	}
	return nil
}

func (s *StoragePluginRPCServer) Put(req StoragePutRequest, resp *StoragePutResponse) error {
	rel, ctx, err := s.Impl.Put(req.Path, req.Body, req.Ctx)
	resp.Path = rel
	resp.Ctx = ctx
	if err != nil {
		resp.Error = err.Error()
	}
	return nil
}

func (s *StoragePluginRPCServer) GetUrl(req StorageGetURLRequest, resp *StorageGetURLResponse) error {
	urls, err := s.Impl.GetUrl(req.Paths, req.Ctx)
	resp.URLs = urls
	if err != nil {
		resp.Error = err.Error()
	}
	return nil
}

func (s *StoragePluginRPCServer) GetMetadata(req StoragePathRequest, resp *StorageMetadataResponse) error {
	meta, err := s.Impl.GetMetadata(req.Path, req.Ctx)
	resp.Meta = meta
	if err != nil {
		resp.Error = err.Error()
	}
	return nil
}

func (s *StoragePluginRPCServer) GetBin(req StoragePathRequest, resp *StorageGetBinResponse) error {
	body, mimeType, ctx, err := s.Impl.GetBin(req.Path, req.Ctx)
	resp.Body = body
	resp.Mime = mimeType
	resp.Ctx = ctx
	if err != nil {
		resp.Error = err.Error()
	}
	return nil
}

func (s *StoragePluginRPCServer) List(req StoragePathRequest, resp *StorageListResponse) error {
	entries, err := s.Impl.List(req.Path, req.Ctx)
	resp.Entries = entries
	if err != nil {
		resp.Error = err.Error()
	}
	return nil
}

func (s *StoragePluginRPCServer) Delete(req StoragePathRequest, resp *StorageDeleteResponse) error {
	if err := s.Impl.Delete(req.Path, req.Ctx); err != nil {
		resp.Error = err.Error()
	}
	return nil
}

// StoragePluginPlugin wraps a StoragePlugin for go-plugin.
type StoragePluginPlugin struct {
	Impl StoragePlugin
}

func (p *StoragePluginPlugin) Server(broker *plugin.MuxBroker) (any, error) {
	return &StoragePluginRPCServer{Impl: p.Impl}, nil
}

func (p *StoragePluginPlugin) Client(broker *plugin.MuxBroker, c *rpc.Client) (any, error) {
	return &StoragePluginRPC{client: c}, nil
}

// --- End StoragePlugin ---

func init() {
	gob.Register(map[string]any(nil))
	gob.Register(map[string]string{})
	gob.Register([]map[string]any{})
	gob.Register(time.Time{})
	gob.Register([]any{})
	gob.Register(time.Duration(0))
	gob.Register(StorageMeta{})
	gob.Register(StorageEntry{})
	gob.Register([]StorageEntry{})
	gob.Register(StorageURL{})
	gob.Register([]StorageURL{})
}
