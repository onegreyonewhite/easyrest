package plugin

import (
	"sync"

	"github.com/hashicorp/go-plugin"
)

// Version is the plugin version.
var Version = "v0.4.3"

// DBPlugin – interface for DB access plugins.
type DBPlugin interface {
	InitConnection(uri string) error
	TableGet(userID string, table string, selectFields []string, where map[string]any,
		ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, error)
	TableCreate(userID string, table string, data []map[string]any, ctx map[string]any) ([]map[string]any, error)
	TableUpdate(userID string, table string, data map[string]any, where map[string]any, ctx map[string]any) (int, error)
	TableDelete(userID string, table string, where map[string]any, ctx map[string]any) (int, error)
	CallFunction(userID string, funcName string, data map[string]any, ctx map[string]any) (any, error)
	GetSchema(ctx map[string]any) (any, error)
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
	Where        map[string]any
	Ordering     []string
	GroupBy      []string
	Limit        int
	Offset       int
	Ctx          map[string]any
}

type TableGetResponse struct {
	Rows  []map[string]any
	Error string
}

type TableCreateRequest struct {
	UserID string
	Table  string
	Data   []map[string]any
	Ctx    map[string]any
}

type TableCreateResponse struct {
	Rows  []map[string]any
	Error string
}

type TableUpdateRequest struct {
	UserID string
	Table  string
	Data   map[string]any
	Where  map[string]any
	Ctx    map[string]any
}

type TableUpdateResponse struct {
	Updated int
	Error   string
}

type TableDeleteRequest struct {
	UserID string
	Table  string
	Where  map[string]any
	Ctx    map[string]any
}

type TableDeleteResponse struct {
	Deleted int
	Error   string
}

type CallFunctionRequest struct {
	UserID   string
	FuncName string
	Data     map[string]any
	Ctx      map[string]any
}

type CallFunctionResponse struct {
	Result any
	Error  string
}

// New structures for GetSchema.
type GetSchemaRequest struct {
	Ctx map[string]any
}

type GetSchemaResponse struct {
	Schema any
	Error  string
}

// Pools.
var tableGetRequestPool = sync.Pool{
	New: func() any {
		return &TableGetRequest{}
	},
}

var tableGetResponsePool = sync.Pool{
	New: func() any {
		return &TableGetResponse{}
	},
}

// Handshake configuration for plugin security.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "EASYREST_PLUGIN",
	MagicCookieValue: "easyrest",
}
