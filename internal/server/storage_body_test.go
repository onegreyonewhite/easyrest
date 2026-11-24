package server

import (
	"bytes"
	"io"
	"net/http/httptest"
	"testing"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

type streamOnlyPlugin struct {
	body []byte
}

func (p *streamOnlyPlugin) Init(map[string]any, easyrest.HostRPC) (easyrest.StorageInfo, error) {
	return easyrest.StorageInfo{}, nil
}

func (p *streamOnlyPlugin) Put(string, []byte, map[string]any) (string, map[string]any, error) {
	return "", nil, io.ErrClosedPipe
}

func (p *streamOnlyPlugin) PutStream(string, io.Reader, map[string]any) (string, map[string]any, error) {
	return "", nil, io.ErrClosedPipe
}

func (p *streamOnlyPlugin) GetUrl([]string, map[string]any) ([]easyrest.StorageURL, error) {
	return nil, nil
}

func (p *streamOnlyPlugin) GetMetadata(string, map[string]any) (easyrest.StorageMeta, error) {
	return easyrest.StorageMeta{}, nil
}

func (p *streamOnlyPlugin) GetBin(string, map[string]any) ([]byte, string, map[string]any, error) {
	return nil, "", nil, io.ErrClosedPipe
}

func (p *streamOnlyPlugin) GetStream(_ string, offset int64, ctx map[string]any) (io.ReadCloser, string, map[string]any, error) {
	if offset < 0 {
		offset = 0
	}
	if offset > int64(len(p.body)) {
		offset = int64(len(p.body))
	}
	return io.NopCloser(bytes.NewReader(p.body[offset:])), "text/plain", ctx, nil
}

func (p *streamOnlyPlugin) List(string, map[string]any) ([]easyrest.StorageEntry, error) {
	return nil, nil
}

func (p *streamOnlyPlugin) Delete(string, map[string]any) error { return nil }

func TestLazyStorageBodyUsesGetStream(t *testing.T) {
	plug := &streamOnlyPlugin{body: []byte("hello")}
	body := &lazyStorageBody{
		plug: plug,
		rel:  "a.txt",
		size: 5,
		req:  httptest.NewRequest("GET", "/media/x/a.txt", nil),
	}
	buf := make([]byte, 8)
	n, err := body.Read(buf[:2])
	if err != nil || string(buf[:n]) != "he" {
		t.Fatalf("read %q err %v", buf[:n], err)
	}
	if _, err := body.Seek(4, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	n, err = body.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(buf[:n]) != "o" {
		t.Fatalf("suffix %q", buf[:n])
	}
}
