package dbglob

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/rpc"
	"path/filepath"
	"strings"
	"testing"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestPutGetBin(t *testing.T) {
	plug := New()
	info, err := plug.Init(nil, easyrest.HostRPC{})
	root, inline := info.Root, info.Inline
	if err != nil {
		t.Fatal(err)
	}
	if root != "" || !inline {
		t.Fatalf("root %q inline %v", root, inline)
	}
	stored, _, err := plug.Put("ignored", []byte("hello"), nil)
	want := easyrest.FormatDataURL("", []byte("hello"))
	if err != nil || stored != want {
		t.Fatalf("stored %q err %v", stored, err)
	}
	body, mime, _, err := plug.GetBin(stored, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, []byte("hello")) || mime != "text/plain; charset=utf-8" {
		t.Fatalf("body %q mime %q", body, mime)
	}
	typed, _, err := plug.Put("ignored", []byte("hello"), map[string]any{easyrest.CtxStorageMIME: "image/png"})
	if err != nil || typed != easyrest.FormatDataURL("image/png", []byte("hello")) {
		t.Fatalf("typed %q err %v", typed, err)
	}
	body, mime, _, err = plug.GetBin(typed, nil)
	if err != nil || !bytes.Equal(body, []byte("hello")) || mime != "image/png" {
		t.Fatalf("body %q mime %q err %v", body, mime, err)
	}
	if _, _, _, err := plug.GetBin("aGVsbG8=", nil); err == nil {
		t.Fatal("expected plain base64 to fail")
	}
	if _, err := plug.List("", nil); err == nil {
		t.Fatal("expected list to fail")
	}
	if err := plug.Delete("aGVsbG8=", nil); err == nil {
		t.Fatal("expected delete to fail")
	}
}

func TestInitTableMode(t *testing.T) {
	plug := New()
	info, err := plug.Init(map[string]any{
		"name":   "blobs",
		"plugin": "app",
		"table":  "files",
	}, easyrest.HostRPC{
		Network: "unix",
		Address: filepath.Join(t.TempDir(), "missing.sock"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.Inline || info.Root != "." {
		t.Fatalf("root %q inline %v", info.Root, info.Inline)
	}
	if plug.db != "app" || plug.table != "files" || plug.pathCol != "path" || plug.dataCol != "data" || plug.metaCol != "metadata" {
		t.Fatalf("stored %#v", plug)
	}

	custom := New()
	if _, err := custom.Init(map[string]any{
		"plugin":   "app",
		"table":    "files",
		"path":     "object_path",
		"data":     "blob",
		"metadata": "meta",
	}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	if custom.pathCol != "object_path" || custom.dataCol != "blob" || custom.metaCol != "meta" {
		t.Fatalf("columns path %q data %q metadata %q", custom.pathCol, custom.dataCol, custom.metaCol)
	}

	if _, err := New().Init(map[string]any{"plugin": "app"}, easyrest.HostRPC{}); err == nil {
		t.Fatal("expected plugin without table to fail")
	}
	if _, err := New().Init(map[string]any{"table": "files"}, easyrest.HostRPC{}); err == nil {
		t.Fatal("expected table without plugin to fail")
	}
}

type tableRPC struct {
	gets    []easyrest.HostCall
	creates []easyrest.HostCall
	updates []easyrest.HostCall
	deletes []easyrest.HostCall
	rows    []map[string]any
}

func (t *tableRPC) TableGet(req easyrest.HostCall, resp *easyrest.HostResult) error {
	t.gets = append(t.gets, req)
	raw, err := json.Marshal(t.rows)
	if err != nil {
		return err
	}
	resp.Status = http.StatusOK
	resp.Body = raw
	return nil
}

func (t *tableRPC) TableCreate(req easyrest.HostCall, resp *easyrest.HostResult) error {
	t.creates = append(t.creates, req)
	resp.Status = http.StatusCreated
	resp.Body = []byte(`[]`)
	return nil
}

func (t *tableRPC) TableUpdate(req easyrest.HostCall, resp *easyrest.HostResult) error {
	t.updates = append(t.updates, req)
	resp.Status = http.StatusOK
	resp.Body = []byte(`{"updated":1}`)
	return nil
}

func (t *tableRPC) TableDelete(req easyrest.HostCall, resp *easyrest.HostResult) error {
	t.deletes = append(t.deletes, req)
	resp.Status = http.StatusNoContent
	return nil
}

func startTableRPC(t *testing.T, api *tableRPC) easyrest.HostRPC {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "dbglob.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := rpc.NewServer()
	if err := srv.RegisterName("Internal", api); err != nil {
		t.Fatal(err)
	}
	go srv.Accept(lis)
	t.Cleanup(func() { lis.Close() })
	return easyrest.HostRPC{Network: "unix", Address: sock}
}

func TestTablePutCreatesRow(t *testing.T) {
	api := &tableRPC{rows: []map[string]any{}}
	host := startTableRPC(t, api)
	plug := New()
	if _, err := plug.Init(map[string]any{
		"name":   "blobs",
		"plugin": "app",
		"table":  "files",
	}, host); err != nil {
		t.Fatal(err)
	}
	stored, _, err := plug.Put("docs/note.txt", []byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if stored != "docs/note.txt" {
		t.Fatalf("stored %q", stored)
	}
	if len(api.creates) != 1 || api.creates[0].DB != "app" || api.creates[0].Name != "files" {
		t.Fatalf("create %#v", api.creates)
	}
	if api.creates[0].Header["Content-Type"] != "application/json" {
		t.Fatalf("header %#v", api.creates[0].Header)
	}
	var rows []map[string]any
	if err := json.Unmarshal(api.creates[0].Body, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["path"] != "docs/note.txt" || rows[0]["data"] != "aGVsbG8=" {
		t.Fatalf("row %#v", rows)
	}
	meta, _ := rows[0]["metadata"].(map[string]any)
	if meta["mime"] == "" || meta["created"] == "" || meta["mod_time"] != meta["created"] {
		t.Fatalf("metadata %#v", meta)
	}
}

func TestTablePutUpdatesRow(t *testing.T) {
	api := &tableRPC{rows: []map[string]any{{
		"metadata": map[string]any{"created": "2020-01-02T03:04:05Z", "mod_time": "2020-01-02T03:04:05Z"},
	}}}
	host := startTableRPC(t, api)
	plug := New()
	if _, err := plug.Init(map[string]any{"plugin": "app", "table": "files"}, host); err != nil {
		t.Fatal(err)
	}
	stored, _, err := plug.Put("docs/note.txt", []byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if stored != "docs/note.txt" || len(api.creates) != 0 || len(api.updates) != 1 {
		t.Fatalf("stored %q creates %d updates %#v", stored, len(api.creates), api.updates)
	}
	if api.updates[0].DB != "app" || api.updates[0].Name != "files" || api.updates[0].Query == "" {
		t.Fatalf("update %#v", api.updates[0])
	}
	var row map[string]any
	if err := json.Unmarshal(api.updates[0].Body, &row); err != nil {
		t.Fatal(err)
	}
	if row["data"] != "aGVsbG8=" {
		t.Fatalf("row %#v", row)
	}
	meta, _ := row["metadata"].(map[string]any)
	if meta["created"] != "2020-01-02T03:04:05Z" || meta["mod_time"] == meta["created"] {
		t.Fatalf("metadata %#v", meta)
	}
}

func TestTableGetBin(t *testing.T) {
	api := &tableRPC{rows: []map[string]any{{"data": "aGVsbG8="}}}
	host := startTableRPC(t, api)
	plug := New()
	if _, err := plug.Init(map[string]any{"plugin": "app", "table": "files"}, host); err != nil {
		t.Fatal(err)
	}
	body, mime, _, err := plug.GetBin("docs/note.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, []byte("hello")) || mime == "" {
		t.Fatalf("body %q mime %q", body, mime)
	}
	if len(api.gets) != 1 || !strings.Contains(api.gets[0].Query, "select=data") || strings.Contains(api.gets[0].Query, "metadata") {
		t.Fatalf("query %q", api.gets[0].Query)
	}
}

func TestTableGetMetadata(t *testing.T) {
	api := &tableRPC{rows: []map[string]any{{
		"metadata": map[string]any{
			"size":     float64(5),
			"mime":     "text/plain; charset=utf-8",
			"created":  "2020-01-02T03:04:05Z",
			"mod_time": "2021-06-07T08:09:10Z",
		},
	}}}
	host := startTableRPC(t, api)
	plug := New()
	if _, err := plug.Init(map[string]any{"plugin": "app", "table": "files"}, host); err != nil {
		t.Fatal(err)
	}
	meta, err := plug.GetMetadata("docs/note.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Size != 5 || meta.Mime != "text/plain; charset=utf-8" || meta.Created.IsZero() || meta.ModTime.IsZero() {
		t.Fatalf("meta %#v", meta)
	}
	if len(api.gets) != 1 || !strings.Contains(api.gets[0].Query, "select=metadata") || strings.Contains(api.gets[0].Query, "select=data") {
		t.Fatalf("query %q", api.gets[0].Query)
	}
}

func TestTableDelete(t *testing.T) {
	api := &tableRPC{rows: []map[string]any{}}
	host := startTableRPC(t, api)
	plug := New()
	if _, err := plug.Init(map[string]any{"plugin": "app", "table": "files"}, host); err != nil {
		t.Fatal(err)
	}
	if err := plug.Delete("docs/note.txt", nil); err != nil {
		t.Fatal(err)
	}
	if len(api.deletes) != 1 || api.deletes[0].DB != "app" || api.deletes[0].Name != "files" {
		t.Fatalf("delete %#v", api.deletes)
	}
	if !strings.Contains(api.deletes[0].Query, "where.eq.path=") {
		t.Fatalf("query %q", api.deletes[0].Query)
	}
	inline := New()
	if _, err := inline.Init(nil, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	if err := inline.Delete("aGVsbG8=", nil); err == nil {
		t.Fatal("expected inline delete to fail")
	}
}

func TestTableGetURL(t *testing.T) {
	plug := New()
	if _, err := plug.Init(map[string]any{
		"name":   "blobs",
		"plugin": "app",
		"table":  "files",
	}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	urls, err := plug.GetUrl([]string{"docs/note.txt"}, map[string]any{
		"request": map[string]any{"scheme": "http", "host": "example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 1 || urls[0].URL != "http://example.test/media/blobs/docs/note.txt" {
		t.Fatalf("urls %#v", urls)
	}
}
