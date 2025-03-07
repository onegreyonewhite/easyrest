package plugin

import (
	"encoding/gob"
	"errors"
	"net/rpc"
	"sync"
	"time"

	"github.com/hashicorp/go-plugin"
)

var Version = "v0.1.0"

// DBPlugin – interface for DB access plugins.
type DBPlugin interface {
	InitConnection(uri string) error
	TableGet(userID, table string, selectFields []string, where map[string]interface{},
		ordering []string, groupBy []string, limit, offset int, ctx map[string]interface{}) ([]map[string]interface{}, error)
	TableCreate(userID, table string, data []map[string]interface{}, ctx map[string]interface{}) ([]map[string]interface{}, error)
	TableUpdate(userID, table string, data map[string]interface{}, where map[string]interface{}, ctx map[string]interface{}) (int, error)
	TableDelete(userID, table string, where map[string]interface{}, ctx map[string]interface{}) (int, error)
	CallFunction(userID, funcName string, data map[string]interface{}, ctx map[string]interface{}) (interface{}, error)
}

// RPC request/response structures.
type InitConnectionRequest struct {
	URI string
}

type InitConnectionResponse struct {
	Error string
}

type TableGetRequest struct {
	UserID       string
	Table        string
	SelectFields []string
	Where        map[string]interface{}
	Ordering     []string
	GroupBy      []string
	Limit        int
	Offset       int
	Ctx          map[string]interface{}
}

type TableGetResponse struct {
	Rows  []map[string]interface{}
	Error string
}

type TableCreateRequest struct {
	UserID string
	Table  string
	Data   []map[string]interface{}
	Ctx    map[string]interface{}
}

type TableCreateResponse struct {
	Rows  []map[string]interface{}
	Error string
}

type TableUpdateRequest struct {
	UserID string
	Table  string
	Data   map[string]interface{}
	Where  map[string]interface{}
	Ctx    map[string]interface{}
}

type TableUpdateResponse struct {
	Updated int
	Error   string
}

type TableDeleteRequest struct {
	UserID string
	Table  string
	Where  map[string]interface{}
	Ctx    map[string]interface{}
}

type TableDeleteResponse struct {
	Deleted int
	Error   string
}

type CallFunctionRequest struct {
	UserID   string
	FuncName string
	Data     map[string]interface{}
	Ctx      map[string]interface{}
}

type CallFunctionResponse struct {
	Result interface{}
	Error  string
}

// Pools.
var tableGetRequestPool = sync.Pool{
	New: func() interface{} {
		return &TableGetRequest{}
	},
}

var tableGetResponsePool = sync.Pool{
	New: func() interface{} {
		return &TableGetResponse{}
	},
}

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

func (g *DBPluginRPC) TableGet(userID, table string, selectFields []string, where map[string]interface{},
	ordering []string, groupBy []string, limit, offset int, ctx map[string]interface{}) ([]map[string]interface{}, error) {
	req := tableGetRequestPool.Get().(*TableGetRequest)
	req.UserID = userID
	req.Table = table
	req.SelectFields = selectFields
	req.Where = where
	req.Ordering = ordering
	req.GroupBy = groupBy
	req.Limit = limit
	req.Offset = offset
	req.Ctx = ctx

	resp := tableGetResponsePool.Get().(*TableGetResponse)
	err := g.client.Call("Plugin.TableGet", req, resp)

	req.UserID = ""
	req.Table = ""
	req.SelectFields = nil
	req.Where = nil
	req.Ordering = nil
	req.GroupBy = nil
	req.Limit = 0
	req.Offset = 0
	req.Ctx = nil
	tableGetRequestPool.Put(req)

	if err != nil {
		tableGetResponsePool.Put(resp)
		return nil, err
	}
	if resp.Error != "" {
		tableGetResponsePool.Put(resp)
		return nil, errors.New(resp.Error)
	}
	result := resp.Rows
	resp.Rows = nil
	tableGetResponsePool.Put(resp)
	return result, nil
}

func (g *DBPluginRPC) TableCreate(userID, table string, data []map[string]interface{}, ctx map[string]interface{}) ([]map[string]interface{}, error) {
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

func (g *DBPluginRPC) TableUpdate(userID, table string, data map[string]interface{}, where map[string]interface{}, ctx map[string]interface{}) (int, error) {
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

func (g *DBPluginRPC) TableDelete(userID, table string, where map[string]interface{}, ctx map[string]interface{}) (int, error) {
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

func (g *DBPluginRPC) CallFunction(userID, funcName string, data map[string]interface{}, ctx map[string]interface{}) (interface{}, error) {
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

// DBPluginRPCServer implements the server side RPC.
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

// DBPluginPlugin wraps the DBPlugin implementation for go-plugin.
type DBPluginPlugin struct {
	Impl DBPlugin
}

func (p *DBPluginPlugin) Server(broker *plugin.MuxBroker) (interface{}, error) {
	return &DBPluginRPCServer{Impl: p.Impl}, nil
}

func (p *DBPluginPlugin) Client(broker *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &DBPluginRPC{client: c}, nil
}

func init() {
	gob.Register(map[string]interface{}(nil))
	gob.Register([]map[string]interface{}{})
	gob.Register(time.Time{})
}

// Handshake configuration for plugin security.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "EASYREST_PLUGIN",
	MagicCookieValue: "easyrest",
}
