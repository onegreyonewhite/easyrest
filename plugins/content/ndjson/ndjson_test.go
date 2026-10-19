package ndjson

import (
	"strings"
	"testing"

	gjson "github.com/goccy/go-json"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestInitParseRender(t *testing.T) {
	p := New()
	info, err := p.Init(nil)
	if err != nil || info.RenderMedia != easyrest.MediaTypeNDJSON || info.ParserMedia != easyrest.MediaTypeNDJSON || info.Format != "ndjson" {
		t.Fatalf("init %+v %v", info, err)
	}
	empty, _, err := p.Parse([]byte(" \n\t"), nil)
	if err != nil || len(empty.([]any)) != 0 {
		t.Fatalf("empty %#v %v", empty, err)
	}
	parsed, _, err := p.Parse([]byte("{\"a\":1}\n\n{\"b\":\"<x>\"}\n"), nil)
	rows, ok := parsed.([]any)
	if err != nil || !ok || len(rows) != 2 {
		t.Fatalf("lines %#v %v", parsed, err)
	}
	if _, _, err = p.Parse([]byte("{bad}\n"), nil); err == nil || !strings.Contains(err.Error(), "NDJSON parse error") {
		t.Fatalf("bad line %v", err)
	}

	raw, _, err := p.Render([]map[string]any{{"a": 1}, {"a": 2}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw.([]byte)), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("rows %q", raw)
	}
	raw, _, err = p.Render(map[string]any{"x": "<a>&"}, map[string]any{easyrest.CtxJSONEscapeHTML: false})
	if err != nil || !strings.Contains(string(raw.([]byte)), `<a>&`) {
		t.Fatalf("escape %q %v", raw, err)
	}
	raw, _, err = p.Render([]any{"not-a-row"}, nil)
	if err != nil || !strings.Contains(string(raw.([]byte)), "not-a-row") {
		t.Fatalf("scalar slice %q %v", raw, err)
	}

	body := map[string]any{"results": []map[string]any{{"name": "ada"}}}
	raw, _, err = p.Render(body, map[string]any{easyrest.CtxPagination: map[string]any{
		easyrest.PagResults: "results",
		easyrest.PagCount:   4,
		easyrest.PagNext:    "https://example/next",
		easyrest.PagPrev:    nil,
	}})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimSuffix(string(raw.([]byte)), "\n"), "\n")
	if len(parts) != 2 {
		t.Fatalf("meta+row %q", raw)
	}
	var meta map[string]any
	if err := gjson.Unmarshal([]byte(parts[0]), &meta); err != nil {
		t.Fatal(err)
	}
	if meta["count"] != float64(4) || meta["next"] != "https://example/next" || meta["previous"] != nil {
		t.Fatalf("meta %#v", meta)
	}
	if strings.Contains(parts[0], "results") {
		t.Fatalf("meta included results %s", parts[0])
	}
	raw, _, err = p.Render(body, map[string]any{easyrest.CtxPagination: map[string]any{easyrest.PagResults: "results"}})
	if err != nil || strings.Count(string(raw.([]byte)), "\n") != 1 || strings.Contains(string(raw.([]byte)), "count") {
		t.Fatalf("results only %q %v", raw, err)
	}
	if _, _, err = p.Render(map[string]any{}, map[string]any{easyrest.CtxPagination: "bad"}); err == nil {
		t.Fatal("expected pagination error")
	}
	if _, _, err = p.Render([]map[string]any{{"bad": make(chan int)}}, nil); err == nil {
		t.Fatal("expected row encode error")
	}
	if _, _, err = p.Render(make(chan int), nil); err == nil {
		t.Fatal("expected value encode error")
	}
	badMeta := map[string]any{"results": []map[string]any{{"name": "ada"}}}
	if _, _, err = p.Render(badMeta, map[string]any{easyrest.CtxPagination: map[string]any{
		easyrest.PagCount:   make(chan int),
		easyrest.PagResults: "results",
	}}); err == nil {
		t.Fatal("expected meta encode error")
	}
	if _, _, err = p.Render(map[string]any{"results": []map[string]any{{"bad": make(chan int)}}}, map[string]any{easyrest.CtxPagination: map[string]any{
		easyrest.PagNext:    "n",
		easyrest.PagResults: "results",
	}}); err == nil {
		t.Fatal("expected paged row encode error")
	}
}

func TestPrepareGetAndCreate(t *testing.T) {
	p := New()
	windows, repeat := p.PrepareGet(0, 5, 10)
	if !repeat || len(windows) != 1 || windows[0].Limit != 10 || windows[0].Offset != 5 {
		t.Fatalf("uncapped %+v %v", windows, repeat)
	}
	windows, repeat = p.PrepareGet(4, 0, 10)
	if !repeat || windows[0].Limit != 4 {
		t.Fatalf("short cap %+v %v", windows, repeat)
	}
	windows, repeat = p.PrepareGet(25, 0, 10)
	if !repeat || windows[0].Limit != 10 {
		t.Fatalf("page cap %+v %v", windows, repeat)
	}
	windows, repeat = p.PrepareGet(5, 0, 0)
	if repeat || windows != nil {
		t.Fatalf("no page %+v %v", windows, repeat)
	}
	windows, _ = p.PrepareGet(-1, 0, 10)
	if windows[0].Limit != 10 {
		t.Fatalf("negative cap %+v", windows)
	}

	one := p.PrepareCreate(map[string]any{"a": 1}, 2)
	if len(one) != 1 {
		t.Fatalf("scalar %#v", one)
	}
	if chunks := p.PrepareCreate([]any{1, 2, 3, 4, 5}, 0); len(chunks) != 1 {
		t.Fatalf("page 0 %#v", chunks)
	}
	chunks := p.PrepareCreate([]any{1, 2, 3, 4, 5}, 2)
	if len(chunks) != 3 || len(chunks[2].([]any)) != 1 {
		t.Fatalf("chunks %#v", chunks)
	}
	if chunks = p.PrepareCreate([]any{}, 2); len(chunks) != 1 {
		t.Fatalf("empty %#v", chunks)
	}
	maps := p.PrepareCreate([]map[string]any{{"a": 1}, {"a": 2}, {"a": 3}}, 2)
	if len(maps) != 2 || len(maps[0].([]map[string]any)) != 2 {
		t.Fatalf("maps %#v", maps)
	}
	if chunks = p.PrepareCreate([]map[string]any{}, 2); len(chunks) != 1 {
		t.Fatalf("empty maps %#v", chunks)
	}
}
