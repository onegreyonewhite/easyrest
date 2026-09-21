package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/onegreyonewhite/easyrest/internal/config"
)

type pagingDBPlugin struct {
	fakeDBPlugin
	mu        sync.Mutex
	calls     int
	rows      []map[string]any
	errAt     int
	lastOff   int
	lastLimit int
}

func (p *pagingDBPlugin) TableGet(_ string, _ string, _ []string, _ map[string]any, _ []string, _ []string, limit, offset int, _ map[string]any) ([]map[string]any, map[string]any, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	p.lastOff = offset
	p.lastLimit = limit
	if p.errAt > 0 && p.calls == p.errAt {
		return nil, nil, errors.New("page fail")
	}
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || offset >= len(p.rows) {
		return []map[string]any{}, nil, nil
	}
	end := offset + limit
	if end > len(p.rows) {
		end = len(p.rows)
	}
	out := make([]map[string]any, end-offset)
	copy(out, p.rows[offset:end])
	return out, nil, nil
}

func TestNegotiateResponseTypeNDJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", contentTypeNDJSON)
	got, varyCT := negotiateResponseType(req, url.Values{})
	if got != contentTypeNDJSON || varyCT {
		t.Fatalf("accept ndjson: got %q varyCT=%v", got, varyCT)
	}

	req = httptest.NewRequest(http.MethodGet, "/?format=ndjson", nil)
	got, _ = negotiateResponseType(req, req.URL.Query())
	if got != contentTypeNDJSON {
		t.Fatalf("format=ndjson: %q", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/?format=json", nil)
	req.Header.Set("Accept", contentTypeNDJSON)
	got, _ = negotiateResponseType(req, req.URL.Query())
	if got != "application/json" {
		t.Fatalf("format=json wins: %q", got)
	}
}

func TestStreamTableGetNDJSONPagesAndCancel(t *testing.T) {
	orig := GetConfig()
	t.Cleanup(func() { SetConfig(orig) })
	SetConfig(config.Config{Server: config.ServerConfig{WriteTimeout: 0}})

	plug := &pagingDBPlugin{
		rows: []map[string]any{
			{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5},
		},
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test/users/", nil)
	streamTableGetNDJSON(w, req, "test", map[string]any{}, plug, url.Values{}, "u", "users", nil, nil, nil, nil, 2, 0, 0)
	if plug.calls != 3 {
		t.Fatalf("expected 3 TableGet calls, got %d", plug.calls)
	}
	if plug.lastOff != 4 {
		t.Fatalf("last offset: %d", plug.lastOff)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), contentTypeNDJSON) {
		t.Fatalf("content-type %s", w.Header().Get("Content-Type"))
	}
	if cr := w.Header().Get("Content-Range"); cr != "" {
		t.Fatalf("auto-stream must omit Content-Range, got %q", cr)
	}
	var rows []map[string]any
	dec := json.NewDecoder(strings.NewReader(w.Body.String()))
	for {
		var row map[string]any
		if err := dec.Decode(&row); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("decode: %v body=%q", err, w.Body.String())
		}
		rows = append(rows, row)
	}
	if len(rows) != 5 {
		t.Fatalf("rows %d body=%q", len(rows), w.Body.String())
	}
	assertNDJSONTrailers(t, w, "0-4/*")

	canceled := &pagingDBPlugin{rows: plug.rows}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req = httptest.NewRequest(http.MethodGet, "/api/test/users/", nil).WithContext(ctx)
	streamTableGetNDJSON(httptest.NewRecorder(), req, "test", map[string]any{}, canceled, url.Values{}, "u", "users", nil, nil, nil, nil, 2, 0, 0)
	if canceled.calls != 0 {
		t.Fatalf("canceled request still called TableGet %d times", canceled.calls)
	}
}

func TestNdjsonFetchSize(t *testing.T) {
	t.Parallel()
	if got := ndjsonFetchSize(100, 0, 0); got != 100 {
		t.Fatalf("unlimited: %d", got)
	}
	if got := ndjsonFetchSize(100, 50, 0); got != 50 {
		t.Fatalf("cap smaller than page: %d", got)
	}
	if got := ndjsonFetchSize(100, 250, 200); got != 50 {
		t.Fatalf("remaining: %d", got)
	}
	if got := ndjsonFetchSize(100, 10, 10); got != 0 {
		t.Fatalf("exhausted: %d", got)
	}
}

func TestStreamTableGetNDJSONMaxRows(t *testing.T) {
	orig := GetConfig()
	t.Cleanup(func() { SetConfig(orig) })
	SetConfig(config.Config{Server: config.ServerConfig{WriteTimeout: 0}})

	plug := &pagingDBPlugin{
		rows: []map[string]any{
			{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5},
		},
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test/users/", nil)
	streamTableGetNDJSON(w, req, "test", map[string]any{}, plug, url.Values{}, "u", "users", nil, nil, nil, nil, 2, 0, 3)
	if plug.calls != 2 {
		t.Fatalf("expected 2 TableGet calls, got %d", plug.calls)
	}
	if plug.lastOff != 2 {
		t.Fatalf("last offset: %d", plug.lastOff)
	}
	if plug.lastLimit != 1 {
		t.Fatalf("last limit: %d", plug.lastLimit)
	}
	if cr := w.Header().Get("Content-Range"); cr != "" {
		t.Fatalf("capped stream must omit Content-Range, got %q", cr)
	}
	var rows []map[string]any
	dec := json.NewDecoder(strings.NewReader(w.Body.String()))
	for {
		var row map[string]any
		if err := dec.Decode(&row); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("decode: %v body=%q", err, w.Body.String())
		}
		rows = append(rows, row)
	}
	if len(rows) != 3 {
		t.Fatalf("rows %d body=%q", len(rows), w.Body.String())
	}
	assertNDJSONTrailers(t, w, "0-2/*")
}

func TestNdjsonContentRange(t *testing.T) {
	t.Parallel()
	if got := ndjsonContentRange(0, 5); got != "0-4/*" {
		t.Fatalf("got %q", got)
	}
	if got := ndjsonContentRange(3, 2); got != "3-4/*" {
		t.Fatalf("offset: %q", got)
	}
	if got := ndjsonContentRange(0, 0); got != "0--1/*" {
		t.Fatalf("empty: %q", got)
	}
}

func TestStreamTableGetNDJSONOffsetTrailers(t *testing.T) {
	orig := GetConfig()
	t.Cleanup(func() { SetConfig(orig) })
	SetConfig(config.Config{Server: config.ServerConfig{WriteTimeout: 0}})

	plug := &pagingDBPlugin{
		rows: []map[string]any{
			{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5},
		},
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test/users/", nil)
	streamTableGetNDJSON(w, req, "test", map[string]any{}, plug, url.Values{}, "u", "users", nil, nil, nil, nil, 2, 3, 0)
	assertNDJSONTrailers(t, w, "3-4/*")
}

func TestStreamTableGetNDJSONLaterPageErrorTrailers(t *testing.T) {
	orig := GetConfig()
	t.Cleanup(func() { SetConfig(orig) })
	SetConfig(config.Config{Server: config.ServerConfig{WriteTimeout: 0}})

	plug := &pagingDBPlugin{
		rows: []map[string]any{
			{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5},
		},
		errAt: 2,
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test/users/", nil)
	streamTableGetNDJSON(w, req, "test", map[string]any{}, plug, url.Values{}, "u", "users", nil, nil, nil, nil, 2, 0, 0)
	assertNDJSONTrailers(t, w, "0-1/*")
}

func assertNDJSONTrailers(t *testing.T, w *httptest.ResponseRecorder, wantRange string) {
	t.Helper()
	if cr := w.Header().Get("Content-Range"); cr != "" {
		t.Fatalf("header Content-Range=%q", cr)
	}
	res := w.Result()
	t.Cleanup(func() { res.Body.Close() })
	if got := res.Trailer.Get("X-Content-Range"); got != wantRange {
		t.Fatalf("X-Content-Range trailer %q, want %q", got, wantRange)
	}
	if st := res.Trailer.Get("Server-Timing"); !strings.HasPrefix(st, "db;dur=") {
		t.Fatalf("Server-Timing trailer %q", st)
	}
}

type mutatingGetPlugin struct {
	fakeDBPlugin
	seen []map[string]any
}

func (p *mutatingGetPlugin) TableGet(_ string, _ string, _ []string, _ map[string]any, _ []string, _ []string, _, _ int, ctx map[string]any) ([]map[string]any, map[string]any, error) {
	if ctx != nil {
		ctx["mutated"] = true
	}
	p.seen = append(p.seen, ctx)
	return []map[string]any{{"ok": true}}, map[string]any{"next": 1}, nil
}

func TestPrefetchRowPageCloneAndDrain(t *testing.T) {
	plug := &pagingDBPlugin{
		rows: []map[string]any{
			{"id": 1}, {"id": 2}, {"id": 3},
		},
	}
	orig := map[string]any{"k": 1}
	ch := prefetchRowPage(plug, "u", "users", nil, nil, nil, nil, 2, 0, orig)
	page := <-ch
	if page.err != nil {
		t.Fatalf("page 0: %v", page.err)
	}
	if len(page.rows) != 2 {
		t.Fatalf("page 0 rows: %d", len(page.rows))
	}

	ch = prefetchRowPage(plug, "u", "users", nil, nil, nil, nil, 2, 2, orig)
	select {
	case page = <-ch:
		if page.err != nil {
			t.Fatalf("page 1: %v", page.err)
		}
		if len(page.rows) != 1 {
			t.Fatalf("page 1 rows: %d", len(page.rows))
		}
	case <-time.After(time.Second):
		t.Fatal("prefetch goroutine did not complete")
	}

	mut := &mutatingGetPlugin{}
	src := map[string]any{"k": 1}
	ch = prefetchRowPage(mut, "u", "users", nil, nil, nil, nil, 1, 0, src)
	if page = <-ch; page.err != nil {
		t.Fatalf("mutating get: %v", page.err)
	}
	if _, ok := src["mutated"]; ok {
		t.Fatal("prefetch must clone pluginCtx")
	}
	if len(mut.seen) != 1 || mut.seen[0]["mutated"] != true {
		t.Fatalf("clone was not used: %#v", mut.seen)
	}
}

func TestStreamTableGetNDJSONFirstPageError(t *testing.T) {
	orig := GetConfig()
	t.Cleanup(func() { SetConfig(orig) })
	SetConfig(config.Config{})

	plug := &pagingDBPlugin{errAt: 1}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test/users/", nil)
	streamTableGetNDJSON(w, req, "test", map[string]any{}, plug, url.Values{}, "u", "users", nil, nil, nil, nil, 2, 0, 0)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d body=%s", w.Code, w.Body.String())
	}
	res := w.Result()
	t.Cleanup(func() { res.Body.Close() })
	if got := res.Trailer.Get("X-Content-Range"); got != "" {
		t.Fatalf("first-page 500 must not send X-Content-Range trailer, got %q", got)
	}
	if strings.Contains(w.Header().Get("Trailer"), "X-Content-Range") {
		t.Fatal("first-page 500 must not announce trailers")
	}
}

type blockingPagePlugin struct {
	fakeDBPlugin
	started chan struct{}
	release chan struct{}
	calls   int
	mu      sync.Mutex
}

func (p *blockingPagePlugin) TableGet(_ string, _ string, _ []string, _ map[string]any, _ []string, _ []string, limit, offset int, _ map[string]any) ([]map[string]any, map[string]any, error) {
	p.mu.Lock()
	p.calls++
	n := p.calls
	p.mu.Unlock()
	if n == 1 {
		rows := make([]map[string]any, limit)
		for i := range rows {
			rows[i] = map[string]any{"id": i}
		}
		return rows, nil, nil
	}
	select {
	case p.started <- struct{}{}:
	default:
	}
	<-p.release
	return []map[string]any{{"id": limit}}, nil, nil
}

func TestStreamTableGetNDJSONDrainOnCancel(t *testing.T) {
	orig := GetConfig()
	t.Cleanup(func() { SetConfig(orig) })
	SetConfig(config.Config{Server: config.ServerConfig{WriteTimeout: 0}})

	plug := &blockingPagePlugin{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/test/users/", nil).WithContext(ctx)

	done := make(chan struct{})
	go func() {
		defer close(done)
		streamTableGetNDJSON(httptest.NewRecorder(), req, "test", map[string]any{}, plug, url.Values{}, "u", "users", nil, nil, nil, nil, 2, 0, 0)
	}()

	select {
	case <-plug.started:
	case <-time.After(time.Second):
		t.Fatal("prefetch TableGet did not start")
	}
	cancel()
	close(plug.release)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream did not return after draining in-flight TableGet")
	}
	plug.mu.Lock()
	calls := plug.calls
	plug.mu.Unlock()
	if calls != 2 {
		t.Fatalf("expected 2 TableGet calls (page + in-flight), got %d", calls)
	}
}
