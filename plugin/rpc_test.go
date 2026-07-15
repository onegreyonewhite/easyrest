package plugin

import (
	"errors"
	"net"
	"net/rpc"
	"sync"
	"testing"
	"time"

	goplugin "github.com/hashicorp/go-plugin"
)

// --- stubs ---

type stubDBPlugin struct {
	fail bool
}

func (s *stubDBPlugin) InitConnection(uri string) error {
	if s.fail {
		return errors.New("init failed")
	}
	return nil
}

func (s *stubDBPlugin) TableGet(userID, table string, selectFields []string, where map[string]any,
	ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, error) {
	if s.fail {
		return nil, errors.New("get failed")
	}
	return []map[string]any{{"id": 1, "user": userID, "table": table}}, nil
}

func (s *stubDBPlugin) TableCreate(userID, table string, data []map[string]any, ctx map[string]any) ([]map[string]any, error) {
	if s.fail {
		return nil, errors.New("create failed")
	}
	return data, nil
}

func (s *stubDBPlugin) TableUpdate(userID, table string, data map[string]any, where map[string]any, ctx map[string]any) (int, error) {
	if s.fail {
		return 0, errors.New("update failed")
	}
	return 2, nil
}

func (s *stubDBPlugin) TableDelete(userID, table string, where map[string]any, ctx map[string]any) (int, error) {
	if s.fail {
		return 0, errors.New("delete failed")
	}
	return 3, nil
}

func (s *stubDBPlugin) CallFunction(userID, funcName string, data map[string]any, ctx map[string]any) (any, error) {
	if s.fail {
		return nil, errors.New("call failed")
	}
	return map[string]any{"func": funcName, "data": data}, nil
}

func (s *stubDBPlugin) GetSchema(ctx map[string]any) (any, error) {
	if s.fail {
		return nil, errors.New("schema failed")
	}
	return map[string]any{"tables": []string{"users"}}, nil
}

type stubCachePlugin struct {
	fail  bool
	store map[string]string
	mu    sync.Mutex
}

func (s *stubCachePlugin) InitConnection(uri string) error {
	if s.fail {
		return errors.New("cache init failed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == nil {
		s.store = make(map[string]string)
	}
	return nil
}

func (s *stubCachePlugin) Set(key, value string, ttl time.Duration) error {
	if s.fail {
		return errors.New("set failed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == nil {
		s.store = make(map[string]string)
	}
	s.store[key] = value
	return nil
}

func (s *stubCachePlugin) Get(key string) (string, error) {
	if s.fail {
		return "", errors.New("get failed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.store[key]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
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

type stubAuthPlugin struct {
	failInit bool
	failAuth bool
}

func (s *stubAuthPlugin) Init(settings map[string]any) (map[string]any, error) {
	schema := map[string]any{"type": "apiKey", "name": "Authorization"}
	if s.failInit {
		return schema, errors.New("auth init failed")
	}
	return schema, nil
}

func (s *stubAuthPlugin) Authenticate(headers map[string]string, method, path, query string) (map[string]any, error) {
	if s.failAuth {
		return nil, errors.New("auth failed")
	}
	return map[string]any{"sub": "user1", "method": method}, nil
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
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.ServeConn(conn)
		}
	}()
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
	rows, err := db.TableGet("u1", "users", []string{"id"}, nil, nil, nil, 10, 0, nil)
	if err != nil || len(rows) != 1 {
		t.Fatalf("TableGet: rows=%v err=%v", rows, err)
	}
	created, err := db.TableCreate("u1", "users", []map[string]any{{"name": "a"}}, nil)
	if err != nil || len(created) != 1 {
		t.Fatalf("TableCreate: %v %v", created, err)
	}
	updated, err := db.TableUpdate("u1", "users", map[string]any{"name": "b"}, map[string]any{"id": "eq.1"}, nil)
	if err != nil || updated != 2 {
		t.Fatalf("TableUpdate: %d %v", updated, err)
	}
	deleted, err := db.TableDelete("u1", "users", map[string]any{"id": "eq.1"}, nil)
	if err != nil || deleted != 3 {
		t.Fatalf("TableDelete: %d %v", deleted, err)
	}
	result, err := db.CallFunction("u1", "myFunc", map[string]any{"x": 1}, nil)
	if err != nil {
		t.Fatalf("CallFunction: %v", err)
	}
	if m, ok := result.(map[string]any); !ok || m["func"] != "myFunc" {
		t.Fatalf("CallFunction result: %v", result)
	}
	schema, err := db.GetSchema(nil)
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
	if _, err := db.TableGet("u", "t", nil, nil, nil, nil, 0, 0, nil); err == nil {
		t.Fatal("expected TableGet error")
	}
	if _, err := db.TableCreate("u", "t", nil, nil); err == nil {
		t.Fatal("expected TableCreate error")
	}
	if _, err := db.TableUpdate("u", "t", nil, nil, nil); err == nil {
		t.Fatal("expected TableUpdate error")
	}
	if _, err := db.TableDelete("u", "t", nil, nil); err == nil {
		t.Fatal("expected TableDelete error")
	}
	if _, err := db.CallFunction("u", "f", nil, nil); err == nil {
		t.Fatal("expected CallFunction error")
	}
	if _, err := db.GetSchema(nil); err == nil {
		t.Fatal("expected GetSchema error")
	}
}

func TestDBPluginRPC_ClientCallFailure(t *testing.T) {
	client, cleanup := startRPCServer(t, &DBPluginRPCServer{Impl: &stubDBPlugin{}})
	cleanup() // close connection so subsequent Calls fail at RPC layer

	db := &DBPluginRPC{client: client}
	if err := db.InitConnection("x"); err == nil {
		t.Fatal("expected RPC error after close")
	}
	if _, err := db.TableGet("u", "t", nil, nil, nil, nil, 0, 0, nil); err == nil {
		t.Fatal("expected TableGet RPC error")
	}
	if _, err := db.TableCreate("u", "t", nil, nil); err == nil {
		t.Fatal("expected TableCreate RPC error")
	}
	if _, err := db.TableUpdate("u", "t", nil, nil, nil); err == nil {
		t.Fatal("expected TableUpdate RPC error")
	}
	if _, err := db.TableDelete("u", "t", nil, nil); err == nil {
		t.Fatal("expected TableDelete RPC error")
	}
	if _, err := db.CallFunction("u", "f", nil, nil); err == nil {
		t.Fatal("expected CallFunction RPC error")
	}
	if _, err := db.GetSchema(nil); err == nil {
		t.Fatal("expected GetSchema RPC error")
	}
}

func TestCachePluginRPC_SuccessAndError(t *testing.T) {
	impl := &stubCachePlugin{}
	client, cleanup := startRPCServer(t, &CachePluginRPCServer{Impl: impl})
	defer cleanup()
	cache := &CachePluginRPC{client: client}

	if err := cache.InitConnection("mem"); err != nil {
		t.Fatalf("InitConnection: %v", err)
	}
	if err := cache.Set("k", "v", time.Second); err != nil {
		t.Fatalf("Set: %v", err)
	}
	val, err := cache.Get("k")
	if err != nil || val != "v" {
		t.Fatalf("Get: %q %v", val, err)
	}

	impl.fail = true
	if err := cache.InitConnection("x"); err == nil {
		t.Fatal("expected InitConnection error")
	}
	if err := cache.Set("k", "v", 0); err == nil {
		t.Fatal("expected Set error")
	}
	if _, err := cache.Get("k"); err == nil {
		t.Fatal("expected Get error")
	}
}

func TestCachePluginRPC_ClientCallFailure(t *testing.T) {
	client, cleanup := startRPCServer(t, &CachePluginRPCServer{Impl: &stubCachePlugin{}})
	cleanup()
	cache := &CachePluginRPC{client: client}
	if err := cache.InitConnection("x"); err == nil {
		t.Fatal("expected RPC error")
	}
	if err := cache.Set("k", "v", 0); err == nil {
		t.Fatal("expected Set RPC error")
	}
	if _, err := cache.Get("k"); err == nil {
		t.Fatal("expected Get RPC error")
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

func TestAuthPluginRPC_SuccessAndError(t *testing.T) {
	impl := &stubAuthPlugin{}
	client, cleanup := startRPCServer(t, &AuthPluginRPCServer{Impl: impl})
	defer cleanup()
	auth := &AuthPluginRPC{client: client}

	schema, err := auth.Init(map[string]any{"k": "v"})
	if err != nil || schema["type"] != "apiKey" {
		t.Fatalf("Init: %v %v", schema, err)
	}
	claims, err := auth.Authenticate(map[string]string{"Authorization": "Bearer x"}, "GET", "/api", "")
	if err != nil || claims["sub"] != "user1" {
		t.Fatalf("Authenticate: %v %v", claims, err)
	}

	impl.failInit = true
	schema, err = auth.Init(nil)
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
	if _, err := auth.Init(nil); err == nil {
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

	cacheP := &CachePluginPlugin{Impl: &stubCachePlugin{}}
	srv, err = cacheP.Server(broker)
	if err != nil || srv == nil {
		t.Fatalf("CachePluginPlugin.Server: %v %v", srv, err)
	}
	clientObj, err = cacheP.Client(broker, cli)
	if err != nil || clientObj == nil {
		t.Fatalf("CachePluginPlugin.Client: %v %v", clientObj, err)
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
