package server

import (
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

type dummyAuthPlugin struct {
	host easyrest.HostRPC
}

func (d *dummyAuthPlugin) Init(_ map[string]any, host easyrest.HostRPC) (easyrest.AuthInfo, error) {
	d.host = host
	return easyrest.AuthInfo{
		PluginMeta: easyrest.EmptyPluginMeta(),
		Schema:     map[string]any{"type": "apiKey"},
	}, nil
}

func (d *dummyAuthPlugin) Authenticate(map[string]string, string, string, string) (map[string]any, error) {
	return map[string]any{"sub": "dummy"}, nil
}

func (d *dummyAuthPlugin) FetchUsers() (easyrest.HostResult, error) {
	client, err := easyrest.DialHost(d.host)
	if err != nil {
		return easyrest.HostResult{}, err
	}
	defer client.Close()
	return client.TableGet(easyrest.HostCall{DB: "db", Name: "users", Query: "select=id"})
}

func TestHostRPC_AuthDummy(t *testing.T) {
	origCfg := GetConfig()
	origDB := DbPlugins.Load()
	t.Cleanup(func() {
		SetConfig(origCfg)
		DbPlugins.Store(origDB)
	})
	rows := &internalRowsPlugin{rows: []map[string]any{{"id": float64(1)}}}
	SetConfig(config.Config{
		CheckScope: true,
		AnonClaims: map[string]any{},
		PluginMap:  map[string]config.PluginConfig{"db": {Uri: "sqlite://memory"}},
	})
	DbPlugins.Store(&map[string]easyrest.DBPlugin{"db": rows})

	sock := filepath.Join(t.TempDir(), "easyrest.sock")
	dummy := &dummyAuthPlugin{}
	info, err := dummy.Init(map[string]any{}, easyrest.HostRPC{Network: "unix", Address: sock})
	if err != nil {
		t.Fatal(err)
	}
	if info.Schema["type"] != "apiKey" || info.Metadata == nil || info.Ctx == nil {
		t.Fatalf("info %#v", info)
	}

	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lis.Close() })
	go serveInternalRPC(lis)

	got, err := dummy.FetchUsers()
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != http.StatusOK || !strings.Contains(string(got.Body), `"id"`) {
		t.Fatalf("status %d body %q", got.Status, got.Body)
	}
}

type dummyMiddlewarePlugin struct {
	host easyrest.HostRPC
}

func (d *dummyMiddlewarePlugin) Init(_ map[string]any, host easyrest.HostRPC) (easyrest.MiddlewareInfo, error) {
	d.host = host
	return easyrest.MiddlewareInfo{PluginMeta: easyrest.EmptyPluginMeta()}, nil
}

func (d *dummyMiddlewarePlugin) PreRequest(string, map[string]any) (map[string]any, *int, error) {
	return map[string]any{}, nil, nil
}

func (d *dummyMiddlewarePlugin) PostRequest(string, map[string]any) (map[string]string, error) {
	return map[string]string{}, nil
}

func (d *dummyMiddlewarePlugin) CallEcho() (easyrest.HostResult, error) {
	client, err := easyrest.DialHost(d.host)
	if err != nil {
		return easyrest.HostResult{}, err
	}
	defer client.Close()
	return client.CallFunction(easyrest.HostCall{
		DB:     "db",
		Name:   "echo",
		Header: map[string]string{"Content-Type": "application/json"},
		Body:   []byte(`{"name":"ada"}`),
	})
}

func TestHostRPC_MiddlewareDummy(t *testing.T) {
	origCfg := GetConfig()
	origDB := DbPlugins.Load()
	t.Cleanup(func() {
		SetConfig(origCfg)
		DbPlugins.Store(origDB)
	})
	rows := &internalCallPlugin{}
	SetConfig(config.Config{
		CheckScope: true,
		AnonClaims: map[string]any{},
		PluginMap:  map[string]config.PluginConfig{"db": {Uri: "sqlite://memory"}},
	})
	DbPlugins.Store(&map[string]easyrest.DBPlugin{"db": rows})

	sock := filepath.Join(t.TempDir(), "easyrest.sock")
	dummy := &dummyMiddlewarePlugin{}
	info, err := dummy.Init(map[string]any{}, easyrest.HostRPC{Network: "unix", Address: sock})
	if err != nil {
		t.Fatal(err)
	}
	if info.Metadata == nil || info.Ctx == nil {
		t.Fatalf("info %#v", info)
	}

	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lis.Close() })
	go serveInternalRPC(lis)

	got, err := dummy.CallEcho()
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != http.StatusOK || rows.name != "echo" || rows.data["name"] != "ada" {
		t.Fatalf("status %d func %q data %#v body %q", got.Status, rows.name, rows.data, got.Body)
	}
}

type dummyStoragePlugin struct {
	host easyrest.HostRPC
}

func (d *dummyStoragePlugin) Init(_ map[string]any, host easyrest.HostRPC) (easyrest.StorageInfo, error) {
	d.host = host
	return easyrest.StorageInfo{
		PluginMeta: easyrest.EmptyPluginMeta(),
		Root:       "files",
		Inline:     true,
	}, nil
}

func (d *dummyStoragePlugin) Put(string, []byte, map[string]any) (string, map[string]any, error) {
	return "", nil, nil
}

func (d *dummyStoragePlugin) GetUrl([]string, map[string]any) ([]easyrest.StorageURL, error) {
	return []easyrest.StorageURL{}, nil
}

func (d *dummyStoragePlugin) GetMetadata(string, map[string]any) (easyrest.StorageMeta, error) {
	return easyrest.StorageMeta{}, nil
}

func (d *dummyStoragePlugin) GetBin(string, map[string]any) ([]byte, string, map[string]any, error) {
	return []byte{}, "", nil, nil
}

func (d *dummyStoragePlugin) List(string, map[string]any) ([]easyrest.StorageEntry, error) {
	return []easyrest.StorageEntry{}, nil
}

func (d *dummyStoragePlugin) Delete(string, map[string]any) error { return nil }

func (d *dummyStoragePlugin) StoreRow() (easyrest.HostResult, error) {
	client, err := easyrest.DialHost(d.host)
	if err != nil {
		return easyrest.HostResult{}, err
	}
	defer client.Close()
	return client.TableCreate(easyrest.HostCall{
		DB:     "db",
		Name:   "users",
		Header: map[string]string{"Content-Type": "application/json"},
		Body:   []byte(`[{"name":"ada"}]`),
	})
}

func TestHostRPC_StorageDummy(t *testing.T) {
	origCfg := GetConfig()
	origDB := DbPlugins.Load()
	t.Cleanup(func() {
		SetConfig(origCfg)
		DbPlugins.Store(origDB)
	})
	rows := &internalWritePlugin{}
	SetConfig(config.Config{
		CheckScope: true,
		AnonClaims: map[string]any{},
		PluginMap:  map[string]config.PluginConfig{"db": {Uri: "sqlite://memory"}},
	})
	DbPlugins.Store(&map[string]easyrest.DBPlugin{"db": rows})

	sock := filepath.Join(t.TempDir(), "easyrest.sock")
	dummy := &dummyStoragePlugin{}
	info, err := dummy.Init(map[string]any{}, easyrest.HostRPC{Network: "unix", Address: sock})
	if err != nil {
		t.Fatal(err)
	}
	if info.Root != "files" || !info.Inline || info.Metadata == nil || info.Ctx == nil {
		t.Fatalf("info %#v", info)
	}

	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lis.Close() })
	go serveInternalRPC(lis)

	got, err := dummy.StoreRow()
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != http.StatusCreated || len(rows.created) != 1 || rows.created[0]["name"] != "ada" {
		t.Fatalf("status %d created %#v body %q", got.Status, rows.created, got.Body)
	}
}
