package plugin

import (
	"context"
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
	// TxID joins the call to a shared transaction started with Host.Begin.
	TxID string
}

// HostTxRequest starts, commits, or rolls back a shared transaction.
type HostTxRequest struct {
	DB       string
	ID       string
	Deadline time.Time
}

// HostTxResponse is the id from Begin or an error string.
type HostTxResponse struct {
	ID    string
	Error string
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

// Begin starts a shared transaction on db and returns its id.
// A deadline on ctx becomes the session deadline. Otherwise the plugin default applies.
func (h *Host) Begin(ctx context.Context, db string) (string, error) {
	req := HostTxRequest{DB: db}
	if ctx != nil {
		if deadline, ok := ctx.Deadline(); ok {
			req.Deadline = deadline
		}
	}
	resp, err := h.callTx("Internal.BeginTx", req)
	if err != nil {
		return "", err
	}
	return resp.ID, nil
}

// Commit commits a shared transaction.
func (h *Host) Commit(ctx context.Context, db, id string) error {
	_, err := h.callTx("Internal.CommitTx", HostTxRequest{DB: db, ID: id})
	return err
}

// Rollback rolls back a shared transaction.
func (h *Host) Rollback(ctx context.Context, db, id string) error {
	_, err := h.callTx("Internal.RollbackTx", HostTxRequest{DB: db, ID: id})
	return err
}

// BeginSession starts a shared transaction and returns a caller that stamps TxID.
func (h *Host) BeginSession(ctx context.Context, db string) (*HostSession, error) {
	id, err := h.Begin(ctx, db)
	if err != nil {
		return nil, err
	}
	return &HostSession{host: h, db: db, id: id}, nil
}

// HostSession is one shared transaction on a single database key.
type HostSession struct {
	host *Host
	db   string
	id   string
	done bool
}

// ID is the opaque transaction id.
func (s *HostSession) ID() string {
	if s == nil {
		return ""
	}
	return s.id
}

// TableGet calls Internal.TableGet inside the session.
func (s *HostSession) TableGet(req HostCall) (HostResult, error) {
	req, err := s.bind(req)
	if err != nil {
		return HostResult{}, err
	}
	return s.host.TableGet(req)
}

// TableCreate calls Internal.TableCreate inside the session.
func (s *HostSession) TableCreate(req HostCall) (HostResult, error) {
	req, err := s.bind(req)
	if err != nil {
		return HostResult{}, err
	}
	return s.host.TableCreate(req)
}

// TableUpdate calls Internal.TableUpdate inside the session.
func (s *HostSession) TableUpdate(req HostCall) (HostResult, error) {
	req, err := s.bind(req)
	if err != nil {
		return HostResult{}, err
	}
	return s.host.TableUpdate(req)
}

// TableDelete calls Internal.TableDelete inside the session.
func (s *HostSession) TableDelete(req HostCall) (HostResult, error) {
	req, err := s.bind(req)
	if err != nil {
		return HostResult{}, err
	}
	return s.host.TableDelete(req)
}

// CallFunction calls Internal.CallFunction inside the session.
func (s *HostSession) CallFunction(req HostCall) (HostResult, error) {
	req, err := s.bind(req)
	if err != nil {
		return HostResult{}, err
	}
	return s.host.CallFunction(req)
}

// Commit commits the session. A second call returns ErrSharedTxDone.
func (s *HostSession) Commit(ctx context.Context) error {
	if s == nil || s.host == nil {
		return ErrSharedTxNotFound
	}
	if s.done {
		return ErrSharedTxDone
	}
	if err := s.host.Commit(ctx, s.db, s.id); err != nil {
		return err
	}
	s.done = true
	return nil
}

// Rollback rolls back the session.
// It returns nil when the session was already committed or rolled back.
func (s *HostSession) Rollback(ctx context.Context) error {
	if s == nil || s.host == nil || s.done {
		return nil
	}
	if err := s.host.Rollback(ctx, s.db, s.id); err != nil {
		return err
	}
	s.done = true
	return nil
}

func (s *HostSession) bind(req HostCall) (HostCall, error) {
	if s == nil || s.done {
		return req, ErrSharedTxDone
	}
	if req.DB == "" {
		req.DB = s.db
	}
	if req.DB != s.db {
		return req, fmt.Errorf("shared transaction is for database %s", s.db)
	}
	req.TxID = s.id
	return req, nil
}

func (h *Host) callTx(method string, req HostTxRequest) (HostTxResponse, error) {
	if h == nil || h.client == nil {
		return HostTxResponse{}, errors.New("host rpc is not configured")
	}
	var resp HostTxResponse
	if err := h.client.Call(method, req, &resp); err != nil {
		return HostTxResponse{}, fmt.Errorf("host rpc %s: %w", method, err)
	}
	if resp.Error != "" {
		return HostTxResponse{}, errors.New(resp.Error)
	}
	return resp, nil
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
