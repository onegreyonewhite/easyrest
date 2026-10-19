package plugin

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/rpc"
	"time"
)

// PluginMeta holds values any plugin may return from Init.
// Metadata and Ctx are empty maps when the plugin has nothing extra to report.
type PluginMeta struct {
	Metadata map[string]any
	Ctx      map[string]any
}

// EmptyPluginMeta returns Metadata and Ctx as non-nil empty maps.
func EmptyPluginMeta() PluginMeta {
	return PluginMeta{
		Metadata: map[string]any{},
		Ctx:      map[string]any{},
	}
}

// NewAuthInfo returns an auth Init result with empty Metadata and Ctx.
func NewAuthInfo(schema map[string]any) AuthInfo {
	return AuthInfo{
		PluginMeta: EmptyPluginMeta(),
		Schema:     schema,
		Key:        "Authorization",
	}
}

// NewMiddlewareInfo returns a middleware Init result with empty Metadata and Ctx.
func NewMiddlewareInfo() MiddlewareInfo {
	return MiddlewareInfo{PluginMeta: EmptyPluginMeta()}
}

// NewStorageInfo returns a storage Init result with empty Metadata and Ctx.
func NewStorageInfo(root string, inline bool) StorageInfo {
	return StorageInfo{PluginMeta: EmptyPluginMeta(), Root: root, Inline: inline}
}

// NewContentInfo returns a content Init result with empty Metadata and Ctx.
// An empty RenderMedia means the plugin cannot render. An empty ParserMedia means it cannot parse.
func NewContentInfo(renderMedia, parserMedia, format string) ContentInfo {
	return ContentInfo{
		PluginMeta:  EmptyPluginMeta(),
		RenderMedia: renderMedia,
		ParserMedia: parserMedia,
		Format:      format,
	}
}

// AuthInfo is the Init result for an auth plugin.
// Key is the header or cookie name to read. An empty Key means Authorization.
// IsCookie reads Key from the request cookies instead of the headers.
type AuthInfo struct {
	PluginMeta
	Schema   map[string]any
	Key      string
	IsCookie bool
}

// MiddlewareInfo is the Init result for a middleware plugin.
type MiddlewareInfo struct {
	PluginMeta
}

// StorageInfo is the Init result for a storage plugin.
type StorageInfo struct {
	PluginMeta
	Root   string
	Inline bool
}

// ContentInfo is the Init result for a content plugin.
// RenderMedia is the response media type. ParserMedia is the request body media type.
// An empty media field means that direction is unsupported. Format is the ?format= value.
type ContentInfo struct {
	PluginMeta
	RenderMedia string
	ParserMedia string
	Format      string
}

// HostRPC is the dial target for the internal RPC server.
// Network and Address are what a later call dials. FD is the server's
// listening descriptor and is not a client dial target.
type HostRPC struct {
	Network string
	Address string
	FD      int
}

// HostCall is one table or function call on the internal RPC server.
type HostCall struct {
	DB     string
	Name   string
	Query  string
	Header map[string]string
	Body   []byte
}

// HostResult is the HTTP status, headers, and body from an internal call.
type HostResult struct {
	Status int
	Header http.Header
	Body   []byte
}

// Host is a client for the internal RPC server.
type Host struct {
	client *rpc.Client
}

// DialHost connects to the internal RPC server.
// A zero HostRPC returns a client that does not dial. Its calls fail with
// "host rpc is not configured".
func DialHost(cfg HostRPC) (*Host, error) {
	if cfg.Address == "" {
		return &Host{}, nil
	}
	network := cfg.Network
	if network == "" {
		network = "unix"
	}
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.Dial(network, cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("dial host rpc: %w", err)
	}
	return &Host{client: rpc.NewClient(conn)}, nil
}

// Close releases the RPC client. It is safe on a client that did not dial.
func (h *Host) Close() error {
	if h == nil || h.client == nil {
		return nil
	}
	return h.client.Close()
}

// TableGet calls Internal.TableGet.
func (h *Host) TableGet(req HostCall) (HostResult, error) {
	return h.call("Internal.TableGet", req)
}

// TableCreate calls Internal.TableCreate.
func (h *Host) TableCreate(req HostCall) (HostResult, error) {
	return h.call("Internal.TableCreate", req)
}

// TableUpdate calls Internal.TableUpdate.
func (h *Host) TableUpdate(req HostCall) (HostResult, error) {
	return h.call("Internal.TableUpdate", req)
}

// TableDelete calls Internal.TableDelete.
func (h *Host) TableDelete(req HostCall) (HostResult, error) {
	return h.call("Internal.TableDelete", req)
}

// CallFunction calls Internal.CallFunction.
func (h *Host) CallFunction(req HostCall) (HostResult, error) {
	return h.call("Internal.CallFunction", req)
}

func (h *Host) call(method string, req HostCall) (HostResult, error) {
	if h == nil || h.client == nil {
		return HostResult{}, errors.New("host rpc is not configured")
	}
	var resp HostResult
	if err := h.client.Call(method, req, &resp); err != nil {
		return HostResult{}, fmt.Errorf("host rpc %s: %w", method, err)
	}
	return resp, nil
}
