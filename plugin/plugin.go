package plugin

import (
	"time"

	"github.com/hashicorp/go-plugin"
)

// Version is the plugin version.
var Version = "v0.13.2"

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

// --- CachePlugin ---

// CachePlugin defines the interface for cache operations.
type CachePlugin interface {
	InitConnection(uri string) error
	Set(key string, value string, ttl time.Duration) error
	Get(key string) (string, error)
}

// CacheInitConnectionRequest holds the URI for cache connection initialization.
type CacheInitConnectionRequest struct {
	URI string
}

// CacheInitConnectionResponse indicates success or error during cache connection initialization.
type CacheInitConnectionResponse struct {
	Error string
}

// CacheSetRequest holds the key, value, and TTL for setting a cache entry.
type CacheSetRequest struct {
	Key   string
	Value string
	TTL   time.Duration
}

// CacheSetResponse indicates success or error during cache set operation.
type CacheSetResponse struct {
	Error string
}

// CacheGetRequest holds the key for retrieving a cache entry.
type CacheGetRequest struct {
	Key string
}

// CacheGetResponse holds the retrieved value or an error.
type CacheGetResponse struct {
	Value string
	Error string
}

// --- AuthPlugin ---
// AuthPlugin defines the interface for authentication plugins.
type AuthPlugin interface {
	Init(settings map[string]any) (map[string]any, error) // Returns Swagger 2.0 security definition and error
	Authenticate(headers map[string]string, method string, path string, query string) (map[string]any, error)
}

// AuthInitRequest holds the settings for authentication plugin initialization.
type AuthInitRequest struct {
	Settings map[string]any
}

// AuthInitResponse indicates success or error during authentication plugin initialization.
type AuthInitResponse struct {
	Schema map[string]any // Swagger 2.0 security definition
	Error  string
}

// AuthAuthenticateRequest holds the data for authentication.
type AuthAuthenticateRequest struct {
	Headers map[string]string
	Method  string
	Path    string
	Query   string
}

// AuthAuthenticateResponse holds the claims or an error.
type AuthAuthenticateResponse struct {
	Claims map[string]any
	Error  string
}

// Handshake configuration for plugin security.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "EASYREST_PLUGIN",
	MagicCookieValue: "easyrest",
}
