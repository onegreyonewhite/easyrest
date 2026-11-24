package plugin

import (
	"io"
	"strings"
	"testing"
)

type rpcMem struct {
	path string
	body []byte
	ctx  map[string]any
}

func (m *rpcMem) Init(map[string]any, HostRPC) (StorageInfo, error) {
	return NewStorageInfo(".", false), nil
}
func (m *rpcMem) Put(path string, body []byte, ctx map[string]any) (string, map[string]any, error) {
	m.path = path
	m.body = append([]byte(nil), body...)
	m.ctx = ctx
	return path, ctx, nil
}
func (m *rpcMem) GetUrl(paths []string, ctx map[string]any) ([]StorageURL, error) {
	return []StorageURL{}, nil
}
func (m *rpcMem) GetMetadata(path string, ctx map[string]any) (StorageMeta, error) {
	return StorageMeta{}, nil
}
func (m *rpcMem) GetBin(path string, ctx map[string]any) ([]byte, string, map[string]any, error) {
	return append([]byte(nil), m.body...), "text/plain", m.ctx, nil
}
func (m *rpcMem) PutStream(path string, r io.Reader, ctx map[string]any) (string, map[string]any, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return "", ctx, err
	}
	return m.Put(path, body, ctx)
}
func (m *rpcMem) GetStream(path string, offset int64, ctx map[string]any) (io.ReadCloser, string, map[string]any, error) {
	body, mimeType, ctxOut, err := m.GetBin(path, ctx)
	if err != nil {
		return nil, "", ctxOut, err
	}
	if offset < 0 {
		return nil, "", ctx, io.ErrUnexpectedEOF
	}
	if offset > int64(len(body)) {
		offset = int64(len(body))
	}
	return io.NopCloser(strings.NewReader(string(body[offset:]))), mimeType, ctxOut, nil
}
func (m *rpcMem) List(path string, ctx map[string]any) ([]StorageEntry, error) {
	return []StorageEntry{}, nil
}
func (m *rpcMem) Delete(path string, ctx map[string]any) error { return nil }

func TestStorageRPC(t *testing.T) {
	srv := &StoragePluginRPCServer{Impl: &rpcMem{}}
	var initResp StorageInitResponse
	if err := srv.Init(StorageInitRequest{Settings: map[string]any{"name": "memory"}}, &initResp); err != nil {
		t.Fatal(err)
	}
	if initResp.Error != "" || initResp.Info.Root != "." || initResp.Info.Inline {
		t.Fatalf("init %#v", initResp)
	}

	var put StoragePutResponse
	err := srv.Put(StoragePutRequest{
		Path: "docs/note.txt",
		Body: []byte("hello"),
		Ctx:  map[string]any{"k": "v"},
	}, &put)
	if err != nil {
		t.Fatal(err)
	}
	if put.Error != "" || put.Path != "docs/note.txt" || put.Ctx["k"] != "v" {
		t.Fatalf("put %#v", put)
	}

	var got StorageGetBinResponse
	if err := srv.GetBin(StoragePathRequest{Path: "docs/note.txt"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Error != "" || string(got.Body) != "hello" || got.Mime != "text/plain" || got.Ctx["k"] != "v" {
		t.Fatalf("get %#v", got)
	}
}

func TestStorageRPCStream(t *testing.T) {
	mem := &rpcMem{}
	client, cleanup := startRPCServer(t, &StoragePluginRPCServer{Impl: mem})
	defer cleanup()
	plug := &StoragePluginRPC{client: client}

	rel, ctx, err := plug.PutStream("docs/note.txt", strings.NewReader("hello"), map[string]any{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	if rel != "docs/note.txt" || ctx["k"] != "v" {
		t.Fatalf("put rel %q ctx %#v", rel, ctx)
	}
	if string(mem.body) != "hello" {
		t.Fatalf("wire body %q", mem.body)
	}
	rc, mimeType, _, err := plug.GetStream("docs/note.txt", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" || mimeType != "text/plain" {
		t.Fatalf("body %q mime %q", body, mimeType)
	}
	rc, _, _, err = plug.GetStream("docs/note.txt", 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	body, err = io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "o" {
		t.Fatalf("suffix %q", body)
	}
}
