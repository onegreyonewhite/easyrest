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
	ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, error) {
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
		return nil, err
	}
	if resp.Error != "" {
		return nil, errors.New(resp.Error)
	}
	result := resp.Rows
	resp.Rows = nil
	return result, nil
}

func (g *DBPluginRPC) TableCreate(userID, table string, data []map[string]any, ctx map[string]any) ([]map[string]any, error) {
	req := TableCreateRequest{
		UserID: userID,
		Table:  table,
		Data:   data,
		Ctx:    ctx,
	}
	var resp TableCreateResponse
	err := g.client.Call("Plugin.TableCreate", req, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, errors.New(resp.Error)
	}
	return resp.Rows, nil
}

func (g *DBPluginRPC) TableUpdate(userID, table string, data map[string]any, where map[string]any, ctx map[string]any) (int, error) {
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
		return 0, err
	}
	if resp.Error != "" {
		return 0, errors.New(resp.Error)
	}
	return resp.Updated, nil
}

func (g *DBPluginRPC) TableDelete(userID, table string, where map[string]any, ctx map[string]any) (int, error) {
	req := TableDeleteRequest{
		UserID: userID,
		Table:  table,
		Where:  where,
		Ctx:    ctx,
	}
	var resp TableDeleteResponse
	err := g.client.Call("Plugin.TableDelete", req, &resp)
	if err != nil {
		return 0, err
	}
	if resp.Error != "" {
		return 0, errors.New(resp.Error)
	}
	return resp.Deleted, nil
}

func (g *DBPluginRPC) CallFunction(userID, funcName string, data map[string]any, ctx map[string]any) (any, error) {
	req := CallFunctionRequest{
		UserID:   userID,
		FuncName: funcName,
		Data:     data,
		Ctx:      ctx,
	}
	var resp CallFunctionResponse
	err := g.client.Call("Plugin.CallFunction", req, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, errors.New(resp.Error)
	}
	return resp.Result, nil
}

// New GetSchema method.
func (g *DBPluginRPC) GetSchema(ctx map[string]any) (any, error) {
	req := GetSchemaRequest{Ctx: ctx}
	var resp GetSchemaResponse
	err := g.client.Call("Plugin.GetSchema", req, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, errors.New(resp.Error)
	}
	return resp.Schema, nil
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
	rows, err := s.Impl.TableGet(req.UserID, req.Table, req.SelectFields, req.Where, req.Ordering, req.GroupBy, req.Limit, req.Offset, req.Ctx)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	resp.Rows = rows
	return nil
}

func (s *DBPluginRPCServer) TableCreate(req TableCreateRequest, resp *TableCreateResponse) error {
	rows, err := s.Impl.TableCreate(req.UserID, req.Table, req.Data, req.Ctx)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	resp.Rows = rows
	return nil
}

func (s *DBPluginRPCServer) TableUpdate(req TableUpdateRequest, resp *TableUpdateResponse) error {
	updated, err := s.Impl.TableUpdate(req.UserID, req.Table, req.Data, req.Where, req.Ctx)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	resp.Updated = updated
	return nil
}

func (s *DBPluginRPCServer) TableDelete(req TableDeleteRequest, resp *TableDeleteResponse) error {
	deleted, err := s.Impl.TableDelete(req.UserID, req.Table, req.Where, req.Ctx)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	resp.Deleted = deleted
	return nil
}

func (s *DBPluginRPCServer) CallFunction(req CallFunctionRequest, resp *CallFunctionResponse) error {
	result, err := s.Impl.CallFunction(req.UserID, req.FuncName, req.Data, req.Ctx)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	resp.Result = result
	return nil
}

// New GetSchema server method.
func (s *DBPluginRPCServer) GetSchema(req GetSchemaRequest, resp *GetSchemaResponse) error {
	schema, err := s.Impl.GetSchema(req.Ctx)
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

// CachePluginRPC is the client wrapper for CachePlugin.
type CachePluginRPC struct{ client *rpc.Client }

func (c *CachePluginRPC) InitConnection(uri string) error {
	req := CacheInitConnectionRequest{URI: uri}
	var resp CacheInitConnectionResponse
	err := c.client.Call("Plugin.InitConnection", req, &resp)
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	return nil
}

func (c *CachePluginRPC) Set(key string, value string, ttl time.Duration) error {
	req := CacheSetRequest{Key: key, Value: value, TTL: ttl}
	var resp CacheSetResponse
	err := c.client.Call("Plugin.Set", req, &resp)
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	return nil
}

func (c *CachePluginRPC) Get(key string) (string, error) {
	req := CacheGetRequest{Key: key}
	var resp CacheGetResponse
	err := c.client.Call("Plugin.Get", req, &resp)
	if err != nil {
		return "", err
	}
	if resp.Error != "" {
		return "", errors.New(resp.Error)
	}
	return resp.Value, nil
}

// CachePluginRPCServer is the server-side RPC implementation for CachePlugin.
type CachePluginRPCServer struct {
	Impl CachePlugin
}

func (s *CachePluginRPCServer) InitConnection(req CacheInitConnectionRequest, resp *CacheInitConnectionResponse) error {
	err := s.Impl.InitConnection(req.URI)
	if err != nil {
		resp.Error = err.Error()
	}
	return nil
}

func (s *CachePluginRPCServer) Set(req CacheSetRequest, resp *CacheSetResponse) error {
	err := s.Impl.Set(req.Key, req.Value, req.TTL)
	if err != nil {
		resp.Error = err.Error()
	}
	return nil
}

func (s *CachePluginRPCServer) Get(req CacheGetRequest, resp *CacheGetResponse) error {
	value, err := s.Impl.Get(req.Key)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}
	resp.Value = value
	return nil
}

// CachePluginPlugin wraps the CachePlugin implementation for go-plugin.
type CachePluginPlugin struct {
	Impl CachePlugin
}

func (p *CachePluginPlugin) Server(broker *plugin.MuxBroker) (any, error) {
	return &CachePluginRPCServer{Impl: p.Impl}, nil
}

func (p *CachePluginPlugin) Client(broker *plugin.MuxBroker, c *rpc.Client) (any, error) {
	return &CachePluginRPC{client: c}, nil
}

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

func init() {
	gob.Register(map[string]any(nil))
	gob.Register(map[string]string{})
	gob.Register([]map[string]any{})
	gob.Register(time.Time{})
	gob.Register([]any{})
	gob.Register(time.Duration(0))
}
