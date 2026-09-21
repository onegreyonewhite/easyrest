package plugin

import (
	"github.com/hashicorp/go-plugin"
)

// VersionMajor and VersionMinor are the plugin API version. They are encoded
// into HTTP ETags; the patch component of Version is not.
const (
	VersionMajor = 0
	VersionMinor = 20
)

// Version is the plugin version.
var Version = "v0.20.0"

// DBPlugin – interface for DB access plugins.
// Methods that take ctx may return an updated context map. A nil returned ctx
// means the caller should keep its existing context. A non-nil map replaces it.
type DBPlugin interface {
	InitConnection(uri string) error
	TableGet(userID string, table string, selectFields []string, where map[string]any,
		ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, map[string]any, error)
	TableCreate(userID string, table string, data []map[string]any, ctx map[string]any) ([]map[string]any, map[string]any, error)
	TableUpdate(userID string, table string, data map[string]any, where map[string]any, ctx map[string]any) (int, map[string]any, error)
	TableDelete(userID string, table string, where map[string]any, ctx map[string]any) (int, map[string]any, error)
	CallFunction(userID string, funcName string, data map[string]any, ctx map[string]any) (any, map[string]any, error)
	GetSchema(ctx map[string]any) (any, map[string]any, error)
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
	Ctx   map[string]any
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
	Ctx   map[string]any
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
	Ctx     map[string]any
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
	Ctx     map[string]any
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
	Ctx    map[string]any
	Error  string
}

// New structures for GetSchema.
type GetSchemaRequest struct {
	Ctx map[string]any
}

type GetSchemaResponse struct {
	Schema any
	Ctx    map[string]any
	Error  string
}

// --- DBQueryPlugin ---

// DBQueryPlugin defines the interface for read-only SQL query plugins.
type DBQueryPlugin interface {
	InitConnection(uri string) error
	QueryCall(query string, ctx map[string]any) ([]map[string]any, error)
}

// QueryCallRequest holds the SQL query and context for QueryCall.
type QueryCallRequest struct {
	Query string
	Ctx   map[string]any
}

// QueryCallResponse holds the query result rows or an error.
type QueryCallResponse struct {
	Rows  []map[string]any
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

// --- MiddlewarePlugin ---

// MiddlewarePlugin defines the interface for request middleware plugins.
type MiddlewarePlugin interface {
	Init(settings map[string]any) error
	PreRequest(dbKey string, ctx map[string]any) (map[string]any, *int, error)
	PostRequest(dbKey string, ctx map[string]any) (map[string]string, error)
}

// MiddlewareInitRequest holds the settings for middleware plugin initialization.
type MiddlewareInitRequest struct {
	Settings map[string]any
}

// MiddlewareInitResponse indicates success or error during middleware plugin initialization.
type MiddlewareInitResponse struct {
	Error string
}

// MiddlewarePreRequestRequest holds the dbKey and context for PreRequest.
type MiddlewarePreRequestRequest struct {
	DbKey string
	Ctx   map[string]any
}

// MiddlewarePreRequestResponse holds the updated context, optional HTTP status, or an error.
type MiddlewarePreRequestResponse struct {
	Ctx    map[string]any
	Status *int
	Error  string
}

// MiddlewarePostRequestRequest holds the dbKey and context for PostRequest.
type MiddlewarePostRequestRequest struct {
	DbKey string
	Ctx   map[string]any
}

// MiddlewarePostRequestResponse holds response headers or an error.
type MiddlewarePostRequestResponse struct {
	Headers map[string]string
	Error   string
}

// Handshake configuration for plugin security.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "EASYREST_PLUGIN",
	MagicCookieValue: "easyrest",
}
