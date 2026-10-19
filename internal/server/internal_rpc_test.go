package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/rpc"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

type internalRowsPlugin struct {
	fakeDBPlugin
	userID string
	rows   []map[string]any
}

func (p *internalRowsPlugin) TableGet(userID string, _ string, _ []string, _ map[string]any, _ []string, _ []string, _, _ int, _ map[string]any) ([]map[string]any, map[string]any, error) {
	p.userID = userID
	return p.rows, nil, nil
}

func TestInternalRPC_TableGetSkipsAuth(t *testing.T) {
	origCfg := GetConfig()
	origDB := DbPlugins.Load()
	t.Cleanup(func() {
		SetConfig(origCfg)
		DbPlugins.Store(origDB)
	})
	plugin := &internalRowsPlugin{rows: []map[string]any{{"id": float64(1)}}}
	SetConfig(config.Config{
		CheckScope: true,
		AnonClaims: map[string]any{},
		PluginMap:  map[string]config.PluginConfig{"db": {Uri: "sqlite://memory"}},
	})
	DbPlugins.Store(&map[string]easyrest.DBPlugin{"db": plugin})

	httpW := httptest.NewRecorder()
	buildRouter().ServeHTTP(httpW, httptest.NewRequest(http.MethodGet, "/api/db/users/?select=id", nil))
	if httpW.Code != http.StatusUnauthorized {
		t.Fatalf("http status %d body %q", httpW.Code, httpW.Body.String())
	}

	status, _, body := DispatchInternal(http.MethodGet, "/api/db/users/?select=id", nil, nil)
	if status != http.StatusOK || plugin.userID != "" || !strings.Contains(string(body), `"id"`) {
		t.Fatalf("status %d user %q body %q", status, plugin.userID, body)
	}
}

type internalWritePlugin struct {
	fakeDBPlugin
	created []map[string]any
	updated map[string]any
	deleted map[string]any
}

func (p *internalWritePlugin) TableCreate(_ string, _ string, data []map[string]any, _ map[string]any) ([]map[string]any, map[string]any, error) {
	p.created = data
	return data, nil, nil
}

func (p *internalWritePlugin) TableUpdate(_ string, _ string, data map[string]any, _ map[string]any, _ map[string]any) (int, map[string]any, error) {
	p.updated = data
	return 1, nil, nil
}

func (p *internalWritePlugin) TableDelete(_ string, _ string, where map[string]any, _ map[string]any) (int, map[string]any, error) {
	p.deleted = where
	return 1, nil, nil
}

func TestInternalRPC_InternalDBStillReachable(t *testing.T) {
	origCfg := GetConfig()
	origDB := DbPlugins.Load()
	t.Cleanup(func() {
		SetConfig(origCfg)
		DbPlugins.Store(origDB)
	})
	plugin := &internalRowsPlugin{rows: []map[string]any{{"id": "ada"}}}
	SetConfig(config.Config{
		PluginMap: map[string]config.PluginConfig{"db": {Uri: "sqlite://memory", Internal: true}},
	})
	DbPlugins.Store(&map[string]easyrest.DBPlugin{"db": plugin})

	httpW := httptest.NewRecorder()
	buildRouter().ServeHTTP(httpW, httptest.NewRequest(http.MethodGet, "/api/db/sessions/", nil))
	if httpW.Code != http.StatusNotFound || !strings.Contains(httpW.Body.String(), "DB plugin not found") {
		t.Fatalf("public status %d body %q", httpW.Code, httpW.Body.String())
	}

	status, _, body := DispatchInternal(http.MethodGet, "/api/db/sessions/?select=id", nil, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"ada"`) {
		t.Fatalf("internal status %d body %q", status, body)
	}
}

func TestInternalRPC_TableWrite(t *testing.T) {
	origCfg := GetConfig()
	origDB := DbPlugins.Load()
	t.Cleanup(func() {
		SetConfig(origCfg)
		DbPlugins.Store(origDB)
	})
	plugin := &internalWritePlugin{}
	SetConfig(config.Config{
		CheckScope: true,
		AnonClaims: map[string]any{},
		PluginMap:  map[string]config.PluginConfig{"db": {Uri: "sqlite://memory"}},
	})
	DbPlugins.Store(&map[string]easyrest.DBPlugin{"db": plugin})

	postStatus, _, _ := DispatchInternal(http.MethodPost, "/api/db/users/", http.Header{
		"Content-Type": {"application/json"},
	}, []byte(`[{"name":"ada"}]`))
	if postStatus != http.StatusCreated || len(plugin.created) != 1 || plugin.created[0]["name"] != "ada" {
		t.Fatalf("post status %d created %#v", postStatus, plugin.created)
	}

	patchStatus, _, _ := DispatchInternal(http.MethodPatch, "/api/db/users/?where.eq.id=1", http.Header{
		"Content-Type": {"application/json"},
	}, []byte(`{"name":"bea"}`))
	if patchStatus != http.StatusOK || plugin.updated["name"] != "bea" {
		t.Fatalf("patch status %d updated %#v", patchStatus, plugin.updated)
	}

	deleteStatus, _, _ := DispatchInternal(http.MethodDelete, "/api/db/users/?where.eq.id=1", nil, nil)
	if deleteStatus != http.StatusNoContent || plugin.deleted == nil {
		t.Fatalf("delete status %d where %#v", deleteStatus, plugin.deleted)
	}
}

type internalCallPlugin struct {
	fakeDBPlugin
	name string
	data map[string]any
}

func (p *internalCallPlugin) CallFunction(_ string, name string, data map[string]any, _ map[string]any) (any, map[string]any, error) {
	p.name = name
	p.data = data
	return map[string]any{"ok": true}, nil, nil
}

func TestInternalRPC_CallFunction(t *testing.T) {
	origCfg := GetConfig()
	origDB := DbPlugins.Load()
	t.Cleanup(func() {
		SetConfig(origCfg)
		DbPlugins.Store(origDB)
	})
	plugin := &internalCallPlugin{}
	SetConfig(config.Config{
		CheckScope: true,
		AnonClaims: map[string]any{},
		PluginMap:  map[string]config.PluginConfig{"db": {Uri: "sqlite://memory"}},
	})
	DbPlugins.Store(&map[string]easyrest.DBPlugin{"db": plugin})

	httpW := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/api/db/rpc/echo/", strings.NewReader(`{"name":"ada"}`))
	httpReq.Header.Set("Content-Type", "application/json")
	buildRouter().ServeHTTP(httpW, httpReq)
	if httpW.Code != http.StatusUnauthorized || plugin.name != "" {
		t.Fatalf("http status %d func %q body %q", httpW.Code, plugin.name, httpW.Body.String())
	}

	status, _, body := DispatchInternal(http.MethodPost, "/api/db/rpc/echo/", http.Header{
		"Content-Type": {"application/json"},
	}, []byte(`{"name":"ada"}`))
	if status != http.StatusOK || plugin.name != "echo" || plugin.data["name"] != "ada" || !strings.Contains(string(body), `"ok"`) {
		t.Fatalf("status %d func %q data %#v body %q", status, plugin.name, plugin.data, body)
	}
}

func TestInternalRPC_UnixDial(t *testing.T) {
	origCfg := GetConfig()
	origDB := DbPlugins.Load()
	t.Cleanup(func() {
		SetConfig(origCfg)
		DbPlugins.Store(origDB)
	})
	plugin := &internalRowsPlugin{rows: []map[string]any{{"id": float64(1)}}}
	SetConfig(config.Config{
		CheckScope: true,
		AnonClaims: map[string]any{},
		PluginMap:  map[string]config.PluginConfig{"db": {Uri: "sqlite://memory"}},
	})
	DbPlugins.Store(&map[string]easyrest.DBPlugin{"db": plugin})

	sock := filepath.Join(t.TempDir(), "easyrest.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lis.Close() })
	go serveInternalRPC(lis)

	client, err := rpc.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	var got InternalResult
	err = client.Call("Internal.TableGet", InternalCall{
		DB:    "db",
		Name:  "users",
		Query: "select=id",
	}, &got)
	if err != nil {
		t.Fatal(err)
	}
	wantStatus, _, wantBody := DispatchInternal(http.MethodGet, "/api/db/users/?select=id", nil, nil)
	if got.Status != wantStatus || string(got.Body) != string(wantBody) {
		t.Fatalf("rpc status %d body %q, dispatch status %d body %q", got.Status, got.Body, wantStatus, wantBody)
	}
}

func TestInternalRPC_ListenFD(t *testing.T) {
	origCfg := GetConfig()
	origDB := DbPlugins.Load()
	t.Cleanup(func() {
		SetConfig(origCfg)
		DbPlugins.Store(origDB)
	})
	plugin := &internalRowsPlugin{rows: []map[string]any{{"id": float64(1)}}}
	SetConfig(config.Config{
		CheckScope: true,
		AnonClaims: map[string]any{},
		PluginMap:  map[string]config.PluginConfig{"db": {Uri: "sqlite://memory"}},
	})
	DbPlugins.Store(&map[string]easyrest.DBPlugin{"db": plugin})

	sock := filepath.Join(t.TempDir(), "easyrest.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	unixLn, ok := ln.(*net.UnixListener)
	if !ok {
		t.Fatal("listener is not a unix socket")
	}
	file, err := unixLn.File()
	if err != nil {
		t.Fatal(err)
	}
	lis, err := listenInternalRPC(config.InternalRPCConfig{FD: int(file.Fd())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		lis.Close()
		ln.Close()
	})
	go serveInternalRPC(lis)

	client, err := rpc.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	var got InternalResult
	err = client.Call("Internal.TableGet", InternalCall{DB: "db", Name: "users", Query: "select=id"}, &got)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != http.StatusOK || !strings.Contains(string(got.Body), `"id"`) {
		t.Fatalf("status %d body %q", got.Status, got.Body)
	}
}
