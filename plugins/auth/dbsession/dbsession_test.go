package dbsession

import (
	"encoding/json"
	"net"
	"net/http"
	"net/rpc"
	"net/url"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestDBSessionInit(t *testing.T) {
	plug := New()
	info, err := plug.Init(map[string]any{
		"plugin": "app",
		"table":  "sessions",
	}, easyrest.HostRPC{
		Network: "unix",
		Address: filepath.Join(t.TempDir(), "missing.sock"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.Key != "session" || !info.IsCookie {
		t.Fatalf("key %q cookie %v", info.Key, info.IsCookie)
	}
	if info.Schema["type"] != "apiKey" || info.Schema["in"] != "cookie" || info.Schema["name"] != "session" {
		t.Fatalf("schema %#v", info.Schema)
	}
	if plug.idCol != "id" || plug.claimsCol != "claims" || plug.expCol != "exp" || plug.cookie != "session" {
		t.Fatalf("columns %#v", plug)
	}

	custom := New()
	info, err = custom.Init(map[string]any{
		"plugin": "app",
		"table":  "sessions",
		"id":     "sid",
		"claims": "payload",
		"exp":    "until",
		"cookie": "auth",
	}, easyrest.HostRPC{})
	if err != nil {
		t.Fatal(err)
	}
	if custom.idCol != "sid" || custom.claimsCol != "payload" || custom.expCol != "until" || custom.cookie != "auth" {
		t.Fatalf("custom %#v", custom)
	}
	if info.Key != "auth" || info.Schema["name"] != "auth" {
		t.Fatalf("custom schema %#v key %q", info.Schema, info.Key)
	}

	if _, err := New().Init(map[string]any{"plugin": "app"}, easyrest.HostRPC{}); err == nil {
		t.Fatal("expected plugin without table to fail")
	}
	if _, err := New().Init(map[string]any{"table": "sessions"}, easyrest.HostRPC{}); err == nil {
		t.Fatal("expected table without plugin to fail")
	}
}

type sessionRPC struct {
	mu   sync.Mutex
	gets []easyrest.HostCall
	rows []map[string]any
}

func (s *sessionRPC) TableGet(req easyrest.HostCall, resp *easyrest.HostResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets = append(s.gets, req)
	raw, err := json.Marshal(s.rows)
	if err != nil {
		return err
	}
	resp.Status = http.StatusOK
	resp.Body = raw
	return nil
}

type acceptCounter struct {
	net.Listener
	n atomic.Int32
}

func (l *acceptCounter) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.n.Add(1)
	return conn, nil
}

func startSessionRPC(t *testing.T, api *sessionRPC) easyrest.HostRPC {
	t.Helper()
	host, _ := startCountedSessionRPC(t, api)
	return host
}

func startCountedSessionRPC(t *testing.T, api *sessionRPC) (easyrest.HostRPC, *acceptCounter) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "dbsession.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	counted := &acceptCounter{Listener: lis}
	srv := rpc.NewServer()
	if err := srv.RegisterName("Internal", api); err != nil {
		t.Fatal(err)
	}
	go srv.Accept(counted)
	t.Cleanup(func() { lis.Close() })
	return easyrest.HostRPC{Network: "unix", Address: sock}, counted
}

func initSession(t *testing.T, host easyrest.HostRPC) *Plugin {
	t.Helper()
	plug := New()
	if _, err := plug.Init(map[string]any{"plugin": "app", "table": "sessions"}, host); err != nil {
		t.Fatal(err)
	}
	return plug
}

func TestDBSessionAuthenticate(t *testing.T) {
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	api := &sessionRPC{rows: []map[string]any{{
		"claims": map[string]any{"sub": "ada"},
		"exp":    future,
	}}}
	plug := initSession(t, startSessionRPC(t, api))
	claims, err := plug.Authenticate(map[string]string{"session": "sess-1"}, http.MethodGet, "/", "")
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "ada" {
		t.Fatalf("claims %#v", claims)
	}

	text := &sessionRPC{rows: []map[string]any{{
		"claims": `{"sub":"ada","scope":"read write"}`,
		"exp":    future,
	}}}
	plug = initSession(t, startSessionRPC(t, text))
	claims, err = plug.Authenticate(map[string]string{"session": "sess-1"}, http.MethodGet, "/", "")
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "ada" || claims["scope"] != "read write" {
		t.Fatalf("text claims %#v", claims)
	}
	if len(api.gets) != 1 || api.gets[0].DB != "app" || api.gets[0].Name != "sessions" {
		t.Fatalf("get %#v", api.gets)
	}
	query, err := url.ParseQuery(api.gets[0].Query)
	if err != nil {
		t.Fatal(err)
	}
	if query.Get("where.eq.id") != "sess-1" || query.Get("select") != "claims,exp" {
		t.Fatalf("query %q", api.gets[0].Query)
	}

	missing := &sessionRPC{rows: []map[string]any{}}
	plug = initSession(t, startSessionRPC(t, missing))
	if _, err := plug.Authenticate(map[string]string{"session": "gone"}, http.MethodGet, "/", ""); err == nil {
		t.Fatal("expected a missing row to fail")
	}
}

func TestDBSessionDialOnce(t *testing.T) {
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	api := &sessionRPC{rows: []map[string]any{{
		"claims": map[string]any{"sub": "ada"},
		"exp":    future,
	}}}
	host, counted := startCountedSessionRPC(t, api)
	plug := initSession(t, host)

	var wg sync.WaitGroup
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			claims, err := plug.Authenticate(map[string]string{"session": "sess-1"}, http.MethodGet, "/", "")
			if err != nil || claims["sub"] != "ada" {
				t.Errorf("claims %#v err %v", claims, err)
			}
		}()
	}
	wg.Wait()
	if counted.n.Load() != 1 {
		t.Fatalf("dials %d", counted.n.Load())
	}

	if _, err := plug.Init(map[string]any{"plugin": "app", "table": "sessions"}, host); err != nil {
		t.Fatal(err)
	}
	if _, err := plug.Authenticate(map[string]string{"session": "sess-1"}, http.MethodGet, "/", ""); err != nil {
		t.Fatal(err)
	}
	if counted.n.Load() != 2 {
		t.Fatalf("dials after init %d", counted.n.Load())
	}

	other, otherCounted := startCountedSessionRPC(t, api)
	if _, err := plug.Init(map[string]any{"plugin": "app", "table": "sessions"}, other); err != nil {
		t.Fatal(err)
	}
	claims, err := plug.Authenticate(map[string]string{"session": "sess-1"}, http.MethodGet, "/", "")
	if err != nil || claims["sub"] != "ada" {
		t.Fatalf("claims %#v err %v", claims, err)
	}
	if otherCounted.n.Load() != 1 || counted.n.Load() != 2 {
		t.Fatalf("old dials %d new dials %d", counted.n.Load(), otherCounted.n.Load())
	}
}

func TestDBSessionExpired(t *testing.T) {
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	api := &sessionRPC{rows: []map[string]any{{
		"claims": map[string]any{"sub": "ada"},
		"exp":    past,
	}}}
	plug := initSession(t, startSessionRPC(t, api))
	if _, err := plug.Authenticate(map[string]string{"session": "old"}, http.MethodGet, "/", ""); err == nil {
		t.Fatal("expected an expired row to fail")
	}
}
