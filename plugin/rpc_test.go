package plugin

import (
	"errors"
	"math"
	"net"
	"net/rpc"
	"strings"
	"sync"
	"testing"
	"time"

	goplugin "github.com/hashicorp/go-plugin"
)

// --- stubs ---

type stubDBPlugin struct {
	fail      bool
	returnCtx map[string]any
}

func (s *stubDBPlugin) InitConnection(uri string) error {
	if s.fail {
		return errors.New("init failed")
	}
	return nil
}

func (s *stubDBPlugin) TableGet(userID, table string, selectFields []string, where map[string]any,
	ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, map[string]any, error) {
	if s.fail {
		return nil, s.returnCtx, errors.New("get failed")
	}
	return []map[string]any{{"id": 1, "user": userID, "table": table}}, s.returnCtx, nil
}

func (s *stubDBPlugin) TableCreate(userID, table string, data []map[string]any, ctx map[string]any) ([]map[string]any, map[string]any, error) {
	if s.fail {
		return nil, s.returnCtx, errors.New("create failed")
	}
	return data, s.returnCtx, nil
}

func (s *stubDBPlugin) TableUpdate(userID, table string, data map[string]any, where map[string]any, ctx map[string]any) (int, map[string]any, error) {
	if s.fail {
		return 0, s.returnCtx, errors.New("update failed")
	}
	return 2, s.returnCtx, nil
}

func (s *stubDBPlugin) TableDelete(userID, table string, where map[string]any, ctx map[string]any) (int, map[string]any, error) {
	if s.fail {
		return 0, s.returnCtx, errors.New("delete failed")
	}
	return 3, s.returnCtx, nil
}

func (s *stubDBPlugin) CallFunction(userID, funcName string, data map[string]any, ctx map[string]any) (any, map[string]any, error) {
	if s.fail {
		return nil, s.returnCtx, errors.New("call failed")
	}
	return map[string]any{"func": funcName, "data": data}, s.returnCtx, nil
}

func (s *stubDBPlugin) GetSchema(ctx map[string]any) (any, map[string]any, error) {
	if s.fail {
		return nil, s.returnCtx, errors.New("schema failed")
	}
	return map[string]any{"tables": []string{"users"}}, s.returnCtx, nil
}

type stubQueryPlugin struct {
	fail bool
}

func (s *stubQueryPlugin) InitConnection(uri string) error {
	if s.fail {
		return errors.New("query init failed")
	}
	return nil
}

func (s *stubQueryPlugin) QueryCall(query string, ctx map[string]any) ([]map[string]any, error) {
	if s.fail {
		return nil, errors.New("query failed")
	}
	return []map[string]any{{"q": query}}, nil
}

type stubMiddlewarePlugin struct {
	failInit         bool
	failPreRequest   bool
	failPostRequest  bool
	preRequestStatus *int
	postHeaders      map[string]string
}

func (s *stubMiddlewarePlugin) Init(map[string]any, HostRPC) (MiddlewareInfo, error) {
	if s.failInit {
		return MiddlewareInfo{}, errors.New("middleware init failed")
	}
	return NewMiddlewareInfo(), nil
}

func (s *stubMiddlewarePlugin) PreRequest(dbKey string, ctx map[string]any) (map[string]any, *int, error) {
	if s.failPreRequest {
		return ctx, s.preRequestStatus, errors.New("pre-request failed")
	}
	return ctx, nil, nil
}

func (s *stubMiddlewarePlugin) PostRequest(dbKey string, ctx map[string]any) (map[string]string, error) {
	if s.failPostRequest {
		return s.postHeaders, errors.New("post-request failed")
	}
	if s.postHeaders != nil {
		return s.postHeaders, nil
	}
	return map[string]string{"X-MW-Post": dbKey}, nil
}

type stubAuthPlugin struct {
	failInit bool
	failAuth bool
}

func (s *stubAuthPlugin) Init(map[string]any, HostRPC) (AuthInfo, error) {
	schema := map[string]any{"type": "apiKey", "name": "Authorization"}
	if s.failInit {
		return NewAuthInfo(schema), errors.New("auth init failed")
	}
	return NewAuthInfo(schema), nil
}

func (s *stubAuthPlugin) Authenticate(headers map[string]string, method, path, query string) (map[string]any, error) {
	if s.failAuth {
		return nil, errors.New("auth failed")
	}
	return map[string]any{"sub": "user1", "method": method}, nil
}

type stubContentPlugin struct {
	ContentBase
	failInit   bool
	failParse  bool
	failRender bool
	badRender  bool
}

func (s *stubContentPlugin) Init(map[string]any) (ContentInfo, error) {
	if s.failInit {
		return ContentInfo{}, errors.New("content init failed")
	}
	return NewContentInfo(MediaTypeJSON, MediaTypeJSON, "json"), nil
}

func (s *stubContentPlugin) Parse(body []byte, ctx map[string]any) (any, map[string]any, error) {
	if s.failParse {
		return nil, ctx, errors.New("parse failed")
	}
	return map[string]any{"body": string(body)}, ctx, nil
}

func (s *stubContentPlugin) Render(data any, ctx map[string]any) (any, map[string]any, error) {
	if s.failRender {
		return nil, ctx, errors.New("render failed")
	}
	if s.badRender {
		return 1, ctx, nil
	}
	return []byte("ok"), ctx, nil
}

func startRPCServer(t *testing.T, rcvr any) (*rpc.Client, func()) {
	t.Helper()
	srv := rpc.NewServer()
	if err := srv.RegisterName("Plugin", rcvr); err != nil {
		t.Fatalf("RegisterName: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.ServeConn(conn)
		}
	})
	client, err := rpc.Dial("tcp", ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatalf("Dial: %v", err)
	}
	cleanup := func() {
		client.Close()
		ln.Close()
		wg.Wait()
	}
	return client, cleanup
}

func TestDBPluginRPC_SuccessAndError(t *testing.T) {
	impl := &stubDBPlugin{}
	client, cleanup := startRPCServer(t, &DBPluginRPCServer{Impl: impl})
	defer cleanup()
	db := &DBPluginRPC{client: client}

	if err := db.InitConnection("sqlite://mem"); err != nil {
		t.Fatalf("InitConnection: %v", err)
	}
	rows, _, err := db.TableGet("u1", "users", []string{"id"}, nil, nil, nil, 10, 0, nil)
	if err != nil || len(rows) != 1 {
		t.Fatalf("TableGet: rows=%v err=%v", rows, err)
	}
	created, _, err := db.TableCreate("u1", "users", []map[string]any{{"name": "a"}}, nil)
	if err != nil || len(created) != 1 {
		t.Fatalf("TableCreate: %v %v", created, err)
	}
	updated, _, err := db.TableUpdate("u1", "users", map[string]any{"name": "b"}, map[string]any{"id": "eq.1"}, nil)
	if err != nil || updated != 2 {
		t.Fatalf("TableUpdate: %d %v", updated, err)
	}
	deleted, _, err := db.TableDelete("u1", "users", map[string]any{"id": "eq.1"}, nil)
	if err != nil || deleted != 3 {
		t.Fatalf("TableDelete: %d %v", deleted, err)
	}
	result, _, err := db.CallFunction("u1", "myFunc", map[string]any{"x": 1}, nil)
	if err != nil {
		t.Fatalf("CallFunction: %v", err)
	}
	if m, ok := result.(map[string]any); !ok || m["func"] != "myFunc" {
		t.Fatalf("CallFunction result: %v", result)
	}
	schema, _, err := db.GetSchema(nil)
	if err != nil {
		t.Fatalf("GetSchema: %v", err)
	}
	if schema == nil {
		t.Fatal("expected schema")
	}

	impl.fail = true
	if err := db.InitConnection("x"); err == nil || err.Error() != "init failed" {
		t.Fatalf("expected init failed, got %v", err)
	}
	if _, _, err := db.TableGet("u", "t", nil, nil, nil, nil, 0, 0, nil); err == nil {
		t.Fatal("expected TableGet error")
	}
	if _, _, err := db.TableCreate("u", "t", nil, nil); err == nil {
		t.Fatal("expected TableCreate error")
	}
	if _, _, err := db.TableUpdate("u", "t", nil, nil, nil); err == nil {
		t.Fatal("expected TableUpdate error")
	}
	if _, _, err := db.TableDelete("u", "t", nil, nil); err == nil {
		t.Fatal("expected TableDelete error")
	}
	if _, _, err := db.CallFunction("u", "f", nil, nil); err == nil {
		t.Fatal("expected CallFunction error")
	}
	if _, _, err := db.GetSchema(nil); err == nil {
		t.Fatal("expected GetSchema error")
	}
}

func TestDBPluginRPC_ReturnsCtx(t *testing.T) {
	outCtx := map[string]any{"from": "plugin"}
	impl := &stubDBPlugin{returnCtx: outCtx}
	client, cleanup := startRPCServer(t, &DBPluginRPCServer{Impl: impl})
	defer cleanup()
	db := &DBPluginRPC{client: client}

	_, got, err := db.TableGet("u1", "users", nil, nil, nil, nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("TableGet: %v", err)
	}
	if got["from"] != "plugin" {
		t.Fatalf("TableGet ctx: %#v", got)
	}
	_, got, err = db.TableCreate("u1", "users", nil, nil)
	if err != nil || got["from"] != "plugin" {
		t.Fatalf("TableCreate ctx=%#v err=%v", got, err)
	}
	_, got, err = db.TableUpdate("u1", "users", nil, nil, nil)
	if err != nil || got["from"] != "plugin" {
		t.Fatalf("TableUpdate ctx=%#v err=%v", got, err)
	}
	_, got, err = db.TableDelete("u1", "users", nil, nil)
	if err != nil || got["from"] != "plugin" {
		t.Fatalf("TableDelete ctx=%#v err=%v", got, err)
	}
	_, got, err = db.CallFunction("u1", "f", nil, nil)
	if err != nil || got["from"] != "plugin" {
		t.Fatalf("CallFunction ctx=%#v err=%v", got, err)
	}
	_, got, err = db.GetSchema(nil)
	if err != nil || got["from"] != "plugin" {
		t.Fatalf("GetSchema ctx=%#v err=%v", got, err)
	}

	impl.fail = true
	_, got, err = db.TableGet("u", "t", nil, nil, nil, nil, 0, 0, nil)
	if err == nil || err.Error() != "get failed" {
		t.Fatalf("expected get failed, got %v", err)
	}
	if got["from"] != "plugin" {
		t.Fatalf("error path ctx: %#v", got)
	}
}

func TestDBPluginRPC_ClientCallFailure(t *testing.T) {
	client, cleanup := startRPCServer(t, &DBPluginRPCServer{Impl: &stubDBPlugin{}})
	cleanup() // close connection so subsequent Calls fail at RPC layer

	db := &DBPluginRPC{client: client}
	if err := db.InitConnection("x"); err == nil {
		t.Fatal("expected RPC error after close")
	}
	if _, _, err := db.TableGet("u", "t", nil, nil, nil, nil, 0, 0, nil); err == nil {
		t.Fatal("expected TableGet RPC error")
	}
	if _, _, err := db.TableCreate("u", "t", nil, nil); err == nil {
		t.Fatal("expected TableCreate RPC error")
	}
	if _, _, err := db.TableUpdate("u", "t", nil, nil, nil); err == nil {
		t.Fatal("expected TableUpdate RPC error")
	}
	if _, _, err := db.TableDelete("u", "t", nil, nil); err == nil {
		t.Fatal("expected TableDelete RPC error")
	}
	if _, _, err := db.CallFunction("u", "f", nil, nil); err == nil {
		t.Fatal("expected CallFunction RPC error")
	}
	if _, _, err := db.GetSchema(nil); err == nil {
		t.Fatal("expected GetSchema RPC error")
	}
}

func TestDBQueryPluginRPC_SuccessAndError(t *testing.T) {
	impl := &stubQueryPlugin{}
	client, cleanup := startRPCServer(t, &DBQueryPluginRPCServer{Impl: impl})
	defer cleanup()
	q := &DBQueryPluginRPC{client: client}

	if err := q.InitConnection("sqlite://mem"); err != nil {
		t.Fatalf("InitConnection: %v", err)
	}
	rows, err := q.QueryCall("SELECT 1", nil)
	if err != nil || len(rows) != 1 || rows[0]["q"] != "SELECT 1" {
		t.Fatalf("QueryCall: %v %v", rows, err)
	}

	impl.fail = true
	if err := q.InitConnection("x"); err == nil {
		t.Fatal("expected InitConnection error")
	}
	if _, err := q.QueryCall("SELECT 1", nil); err == nil {
		t.Fatal("expected QueryCall error")
	}
}

func TestDBQueryPluginRPC_ClientCallFailure(t *testing.T) {
	client, cleanup := startRPCServer(t, &DBQueryPluginRPCServer{Impl: &stubQueryPlugin{}})
	cleanup()
	q := &DBQueryPluginRPC{client: client}
	if err := q.InitConnection("x"); err == nil {
		t.Fatal("expected RPC error")
	}
	if _, err := q.QueryCall("SELECT 1", nil); err == nil {
		t.Fatal("expected QueryCall RPC error")
	}
}

func TestMiddlewarePluginRPC_SuccessAndError(t *testing.T) {
	impl := &stubMiddlewarePlugin{}
	client, cleanup := startRPCServer(t, &MiddlewarePluginRPCServer{Impl: impl})
	defer cleanup()
	mw := &MiddlewarePluginRPC{client: client}

	if _, err := mw.Init(map[string]any{"k": "v"}, HostRPC{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ctx, status, err := mw.PreRequest("test", map[string]any{"method": "GET"})
	if err != nil || status != nil || ctx["method"] != "GET" {
		t.Fatalf("PreRequest: ctx=%v status=%v err=%v", ctx, status, err)
	}

	impl.failInit = true
	if _, err := mw.Init(nil, HostRPC{}); err == nil {
		t.Fatal("expected Init error")
	}
	impl.failInit = false
	impl.failPreRequest = true
	_, status, err = mw.PreRequest("test", nil)
	if err == nil {
		t.Fatal("expected PreRequest error")
	}
	status403 := 403
	impl.preRequestStatus = &status403
	_, status, err = mw.PreRequest("test", nil)
	if err == nil || status == nil || *status != 403 {
		t.Fatalf("expected PreRequest error with status 403: status=%v err=%v", status, err)
	}

	impl.failPreRequest = false
	impl.preRequestStatus = nil
	headers, err := mw.PostRequest("test", map[string]any{"method": "GET"})
	if err != nil || headers["X-MW-Post"] != "test" {
		t.Fatalf("PostRequest: headers=%v err=%v", headers, err)
	}
	impl.failPostRequest = true
	impl.postHeaders = map[string]string{"X-MW-Post": "partial"}
	headers, err = mw.PostRequest("test", nil)
	if err == nil || headers["X-MW-Post"] != "partial" {
		t.Fatalf("expected PostRequest error with headers: headers=%v err=%v", headers, err)
	}
}

func TestMiddlewarePluginRPC_ClientCallFailure(t *testing.T) {
	client, cleanup := startRPCServer(t, &MiddlewarePluginRPCServer{Impl: &stubMiddlewarePlugin{}})
	cleanup()
	mw := &MiddlewarePluginRPC{client: client}
	if _, err := mw.Init(nil, HostRPC{}); err == nil {
		t.Fatal("expected Init RPC error")
	}
	if _, _, err := mw.PreRequest("test", nil); err == nil {
		t.Fatal("expected PreRequest RPC error")
	}
	if _, err := mw.PostRequest("test", nil); err == nil {
		t.Fatal("expected PostRequest RPC error")
	}
}

func TestAuthPluginRPC_SuccessAndError(t *testing.T) {
	impl := &stubAuthPlugin{}
	client, cleanup := startRPCServer(t, &AuthPluginRPCServer{Impl: impl})
	defer cleanup()
	auth := &AuthPluginRPC{client: client}

	info, err := auth.Init(map[string]any{"k": "v"}, HostRPC{})
	schema := info.Schema
	if err != nil || schema["type"] != "apiKey" {
		t.Fatalf("Init: %v %v", schema, err)
	}
	claims, err := auth.Authenticate(map[string]string{"Authorization": "Bearer x"}, "GET", "/api", "")
	if err != nil || claims["sub"] != "user1" {
		t.Fatalf("Authenticate: %v %v", claims, err)
	}

	impl.failInit = true
	info, err = auth.Init(nil, HostRPC{})
	schema = info.Schema
	if err == nil || schema["type"] != "apiKey" {
		t.Fatalf("Init with error should still return schema: %v %v", schema, err)
	}
	impl.failInit = false
	impl.failAuth = true
	if _, err := auth.Authenticate(nil, "GET", "/", ""); err == nil {
		t.Fatal("expected Authenticate error")
	}
}

func TestAuthPluginRPC_ClientCallFailure(t *testing.T) {
	client, cleanup := startRPCServer(t, &AuthPluginRPCServer{Impl: &stubAuthPlugin{}})
	cleanup()
	auth := &AuthPluginRPC{client: client}
	if _, err := auth.Init(nil, HostRPC{}); err == nil {
		t.Fatal("expected Init RPC error")
	}
	if _, err := auth.Authenticate(nil, "GET", "/", ""); err == nil {
		t.Fatal("expected Authenticate RPC error")
	}
}

func TestPluginBrokerConstructors(t *testing.T) {
	var broker *goplugin.MuxBroker

	dbP := &DBPluginPlugin{Impl: &stubDBPlugin{}}
	srv, err := dbP.Server(broker)
	if err != nil || srv == nil {
		t.Fatalf("DBPluginPlugin.Server: %v %v", srv, err)
	}
	cli, cleanup := startRPCServer(t, srv)
	defer cleanup()
	clientObj, err := dbP.Client(broker, cli)
	if err != nil || clientObj == nil {
		t.Fatalf("DBPluginPlugin.Client: %v %v", clientObj, err)
	}

	queryP := &DBQueryPluginPlugin{Impl: &stubQueryPlugin{}}
	srv, err = queryP.Server(broker)
	if err != nil || srv == nil {
		t.Fatalf("DBQueryPluginPlugin.Server: %v %v", srv, err)
	}
	clientObj, err = queryP.Client(broker, cli)
	if err != nil || clientObj == nil {
		t.Fatalf("DBQueryPluginPlugin.Client: %v %v", clientObj, err)
	}

	authP := &AuthPluginPlugin{Impl: &stubAuthPlugin{}}
	srv, err = authP.Server(broker)
	if err != nil || srv == nil {
		t.Fatalf("AuthPluginPlugin.Server: %v %v", srv, err)
	}
	clientObj, err = authP.Client(broker, cli)
	if err != nil || clientObj == nil {
		t.Fatalf("AuthPluginPlugin.Client: %v %v", clientObj, err)
	}

	mwP := &MiddlewarePluginPlugin{Impl: &stubMiddlewarePlugin{}}
	srv, err = mwP.Server(broker)
	if err != nil || srv == nil {
		t.Fatalf("MiddlewarePluginPlugin.Server: %v %v", srv, err)
	}
	clientObj, err = mwP.Client(broker, cli)
	if err != nil || clientObj == nil {
		t.Fatalf("MiddlewarePluginPlugin.Client: %v %v", clientObj, err)
	}

	contentP := &ContentPluginPlugin{Impl: &stubContentPlugin{}}
	srv, err = contentP.Server(broker)
	if err != nil || srv == nil {
		t.Fatalf("ContentPluginPlugin.Server: %v %v", srv, err)
	}
	clientObj, err = contentP.Client(broker, cli)
	if err != nil || clientObj == nil {
		t.Fatalf("ContentPluginPlugin.Client: %v %v", clientObj, err)
	}
}

func TestContentPluginRPC_RoundTrip(t *testing.T) {
	impl := &stubContentPlugin{}
	client, cleanup := startRPCServer(t, &ContentPluginRPCServer{Impl: impl})
	defer cleanup()
	plug := &ContentPluginRPC{client: client}

	info, err := plug.Init(map[string]any{"k": "v"})
	if err != nil || info.RenderMedia != MediaTypeJSON || info.ParserMedia != MediaTypeJSON || info.Format != "json" {
		t.Fatalf("Init %+v %v", info, err)
	}
	if info.Metadata == nil || info.Ctx == nil {
		t.Fatalf("meta %#v ctx %#v", info.Metadata, info.Ctx)
	}
	value, ctx, err := plug.Parse([]byte(`{"a":1}`), map[string]any{"n": "1"})
	row, _ := value.(map[string]any)
	if err != nil || row["body"] != `{"a":1}` || ctx["n"] != "1" {
		t.Fatalf("Parse %#v %#v %v", value, ctx, err)
	}
	rendered, ctx, err := plug.Render(map[string]any{"a": "1"}, map[string]any{"n": "1"})
	body, _ := rendered.([]byte)
	if err != nil || string(body) != "ok" || ctx["n"] != "1" {
		t.Fatalf("Render %#v %#v %v", rendered, ctx, err)
	}
	windows, repeat := plug.PrepareGet(0, 3, 10)
	if repeat || len(windows) != 1 || windows[0].Limit != 10 || windows[0].Offset != 3 {
		t.Fatalf("PrepareGet %+v %v", windows, repeat)
	}
	chunks := plug.PrepareCreate(map[string]any{"a": "1"}, 2)
	if len(chunks) != 1 {
		t.Fatalf("PrepareCreate %#v", chunks)
	}

	impl.failInit = true
	if _, err = plug.Init(nil); err == nil {
		t.Fatal("expected Init error")
	}
	impl.failInit = false
	impl.failParse = true
	if _, _, err = plug.Parse(nil, nil); err == nil {
		t.Fatal("expected Parse error")
	}
	impl.failParse = false
	impl.failRender = true
	if _, _, err = plug.Render(nil, nil); err == nil {
		t.Fatal("expected Render error")
	}
	impl.failRender = false
	impl.badRender = true
	if _, _, err = plug.Render(nil, nil); err == nil {
		t.Fatal("expected Render type error")
	}
}

type fixedParsePlugin struct {
	ContentBase
	value any
}

func (p *fixedParsePlugin) Init(map[string]any) (ContentInfo, error) {
	return NewContentInfo(MediaTypeJSON, MediaTypeJSON, "json"), nil
}

func (p *fixedParsePlugin) Parse([]byte, map[string]any) (any, map[string]any, error) {
	return p.value, map[string]any{}, nil
}

func TestContentPluginRPC_GobScalars(t *testing.T) {
	when := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	impl := &fixedParsePlugin{value: map[string]any{
		"u":    uint64(9),
		"i":    int64(-3),
		"f":    1.5,
		"b":    true,
		"s":    "ada",
		"n":    nil,
		"nest": map[string]any{"k": "v"},
		"list": []any{"x", int64(2)},
		"when": when,
		"raw":  []byte("hi"),
	}}
	client, cleanup := startRPCServer(t, &ContentPluginRPCServer{Impl: impl})
	defer cleanup()
	plug := &ContentPluginRPC{client: client}

	value, _, err := plug.Parse(nil, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	row, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("value %#v", value)
	}
	if row["u"] != uint64(9) || row["i"] != int64(-3) || row["f"] != 1.5 || row["b"] != true || row["s"] != "ada" || row["n"] != nil {
		t.Fatalf("scalars %#v", row)
	}
	nest, _ := row["nest"].(map[string]any)
	if nest["k"] != "v" {
		t.Fatalf("nest %#v", row["nest"])
	}
	list, _ := row["list"].([]any)
	if len(list) != 2 || list[0] != "x" || list[1] != int64(2) {
		t.Fatalf("list %#v", row["list"])
	}
	gotWhen, _ := row["when"].(time.Time)
	if !gotWhen.Equal(when) {
		t.Fatalf("time %v", row["when"])
	}
	raw, _ := row["raw"].([]byte)
	if string(raw) != "hi" {
		t.Fatalf("bytes %#v", row["raw"])
	}

	nanClient, nanCleanup := startRPCServer(t, &ContentPluginRPCServer{Impl: &fixedParsePlugin{value: math.NaN()}})
	defer nanCleanup()
	nanPlug := &ContentPluginRPC{client: nanClient}
	if _, _, err = nanPlug.Parse(nil, nil); err == nil || !strings.Contains(err.Error(), "non-finite") {
		t.Fatalf("NaN error: %v", err)
	}
	if _, _, err = nanPlug.Parse([]byte("again"), nil); err == nil || !strings.Contains(err.Error(), "non-finite") {
		t.Fatalf("NaN must not break the RPC connection: %v", err)
	}
}

func TestContentPluginRPC_ClientCallFailure(t *testing.T) {
	client, cleanup := startRPCServer(t, &ContentPluginRPCServer{Impl: &stubContentPlugin{}})
	cleanup()
	plug := &ContentPluginRPC{client: client}
	if _, err := plug.Init(nil); err == nil {
		t.Fatal("expected Init RPC error")
	}
	if _, _, err := plug.Parse(nil, nil); err == nil {
		t.Fatal("expected Parse RPC error")
	}
	if _, _, err := plug.Render(nil, nil); err == nil {
		t.Fatal("expected Render RPC error")
	}
	if windows, repeat := plug.PrepareGet(1, 0, 1); windows != nil || repeat {
		t.Fatalf("PrepareGet after close %+v %v", windows, repeat)
	}
	if chunks := plug.PrepareCreate(nil, 1); chunks != nil {
		t.Fatalf("PrepareCreate after close %#v", chunks)
	}
}

func TestGetTxPreference(t *testing.T) {
	tx, err := GetTxPreference(nil)
	if err != nil || tx != "commit" {
		t.Fatalf("nil ctx: %q %v", tx, err)
	}
	tx, err = GetTxPreference(map[string]any{})
	if err != nil || tx != "commit" {
		t.Fatalf("empty: %q %v", tx, err)
	}
	tx, err = GetTxPreference(map[string]any{"prefer": "bad"})
	if err == nil {
		t.Fatal("expected prefer type error")
	}
	tx, err = GetTxPreference(map[string]any{"prefer": map[string]any{"tx": 1}})
	if err == nil {
		t.Fatal("expected prefer.tx type error")
	}
	tx, err = GetTxPreference(map[string]any{"prefer": map[string]any{"tx": "nope"}})
	if err == nil {
		t.Fatal("expected invalid prefer.tx value")
	}
	tx, err = GetTxPreference(map[string]any{"prefer": map[string]any{"tx": "rollback"}})
	if err != nil || tx != "rollback" {
		t.Fatalf("rollback: %q %v", tx, err)
	}
	tx, err = GetTxPreference(map[string]any{"prefer": map[string]any{}})
	if err != nil || tx != "commit" {
		t.Fatalf("empty prefer: %q %v", tx, err)
	}
}

type recordingTx struct {
	stubDBPlugin
	seen    []string
	commits int
}

func (r *recordingTx) BeginTx(ctx map[string]any) (string, map[string]any, error) {
	return "sess-1", map[string]any{"begun": true}, nil
}

func (r *recordingTx) CommitTx(id string, ctx map[string]any) (map[string]any, error) {
	if id != "sess-1" {
		return nil, ErrSharedTxNotFound
	}
	r.commits++
	return map[string]any{"committed": true}, nil
}

func (r *recordingTx) RollbackTx(id string) error { return nil }

func (r *recordingTx) TableGet(userID, table string, selectFields []string, where map[string]any,
	ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, map[string]any, error) {
	id, _ := SharedTxID(ctx)
	r.seen = append(r.seen, id)
	return r.stubDBPlugin.TableGet(userID, table, selectFields, where, ordering, groupBy, limit, offset, ctx)
}

func TestDBTransactorRPC(t *testing.T) {
	plain, cleanup := startRPCServer(t, &DBPluginRPCServer{Impl: &stubDBPlugin{}})
	defer cleanup()
	unsupported := &DBPluginRPC{client: plain}
	if _, _, err := unsupported.BeginTx(nil); err == nil || !strings.Contains(err.Error(), ErrSharedTxUnsupported.Error()) {
		t.Fatalf("unsupported: %v", err)
	}

	rec := &recordingTx{}
	client, cleanupRec := startRPCServer(t, &DBPluginRPCServer{Impl: rec})
	defer cleanupRec()
	db := &DBPluginRPC{client: client}
	id, begun, err := db.BeginTx(nil)
	if err != nil || id != "sess-1" || begun["begun"] != true {
		t.Fatalf("begin: id=%q ctx=%v err=%v", id, begun, err)
	}
	ctx := map[string]any{SharedTxKey: id}
	if _, _, err := db.TableGet("u", "users", nil, nil, nil, nil, 0, 0, ctx); err != nil {
		t.Fatal(err)
	}
	if len(rec.seen) != 1 || rec.seen[0] != id {
		t.Fatalf("joined id: %#v", rec.seen)
	}
	out, err := db.CommitTx(id, nil)
	if err != nil || out["committed"] != true || rec.commits != 1 {
		t.Fatalf("commit: %#v %v commits=%d", out, err, rec.commits)
	}
	if err := db.RollbackTx(id); err != nil {
		t.Fatal(err)
	}
}
