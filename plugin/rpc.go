package plugin

import (
	"encoding/gob"
	"errors"
	"net/rpc"
	"time"

	"github.com/hashicorp/go-plugin"
)

// DBPluginRPC is the client wrapper.
type DBPluginRPC struct{ client *rpc.Client }

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

func (a *AuthPluginRPC) Init(settings map[string]any) (map[string]any, error) {
	req := AuthInitRequest{Settings: settings}
	var resp AuthInitResponse
	err := a.client.Call("Plugin.Init", req, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return resp.Schema, errors.New(resp.Error)
	}
	return resp.Schema, nil
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
	schema, err := s.Impl.Init(req.Settings)
	resp.Schema = schema
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

func (m *MiddlewarePluginRPC) Init(settings map[string]any) error {
	req := MiddlewareInitRequest{Settings: settings}
	var resp MiddlewareInitResponse
	err := m.client.Call("Plugin.Init", req, &resp)
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	return nil
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
	err := s.Impl.Init(req.Settings)
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

func init() {
	gob.Register(map[string]any(nil))
	gob.Register(map[string]string{})
	gob.Register([]map[string]any{})
	gob.Register(time.Time{})
	gob.Register([]any{})
	gob.Register(time.Duration(0))
}
