package json

import (
	"strings"
	"testing"

	gjson "github.com/goccy/go-json"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestInitParseAndRender(t *testing.T) {
	p := New()
	info, err := p.Init(nil)
	if err != nil || info.RenderMedia != easyrest.MediaTypeJSON || info.ParserMedia != easyrest.MediaTypeJSON || info.Format != "json" {
		t.Fatalf("init %+v %v", info, err)
	}
	if info.Metadata == nil || info.Ctx == nil {
		t.Fatalf("meta %#v ctx %#v", info.Metadata, info.Ctx)
	}
	obj, _, err := p.Parse([]byte(`{"name":"ada"}`), nil)
	row, ok := obj.(map[string]any)
	if err != nil || !ok || row["name"] != "ada" {
		t.Fatalf("object %#v %v", obj, err)
	}
	arr, _, err := p.Parse([]byte(`[1,{"b":2}]`), nil)
	items, ok := arr.([]any)
	if err != nil || !ok || len(items) != 2 {
		t.Fatalf("array %#v %v", arr, err)
	}
	if _, _, err = p.Parse([]byte(`true`), nil); err == nil || !strings.Contains(err.Error(), "JSON parse error") {
		t.Fatalf("scalar err %v", err)
	}
	if _, _, err = p.Parse([]byte(`{`), nil); err == nil || !strings.Contains(err.Error(), "JSON parse error") {
		t.Fatalf("broken err %v", err)
	}

	raw, ctx, err := p.Render(map[string]any{"x": "<a>&"}, nil)
	if err != nil || ctx != nil || !strings.Contains(string(raw.([]byte)), `\u003c`) || !strings.HasSuffix(string(raw.([]byte)), "\n") {
		t.Fatalf("escaped %q %v", raw, err)
	}
	raw, _, err = p.Render(map[string]any{"a": 1}, map[string]any{
		easyrest.CtxContentParams: map[string]string{"indent": "2"},
	})
	if err != nil || !strings.Contains(string(raw.([]byte)), "\n  \"a\": 1\n") {
		t.Fatalf("indent %q %v", raw, err)
	}
	for _, indent := range []string{"", "0", "nope"} {
		raw, _, err = p.Render(map[string]any{"a": 1}, map[string]any{
			easyrest.CtxContentParams: map[string]string{"indent": indent},
		})
		got := string(raw.([]byte))
		if err != nil || strings.Contains(got, "\n ") || got != "{\"a\":1}\n" {
			t.Fatalf("compact indent %q: %q %v", indent, got, err)
		}
	}
	raw, _, err = p.Render(map[string]any{"x": "<a>&"}, map[string]any{easyrest.CtxJSONEscapeHTML: false})
	if err != nil || !strings.Contains(string(raw.([]byte)), `<a>&`) || strings.Contains(string(raw.([]byte)), `\u003c`) {
		t.Fatalf("raw %q %v", raw, err)
	}
	body := map[string]any{"results": []any{map[string]any{"name": "ada"}}, "count": 1}
	raw, _, err = p.Render(body, map[string]any{easyrest.CtxPagination: map[string]any{
		easyrest.PagResults: "results",
		easyrest.PagCount:   1,
		easyrest.PagNext:    nil,
		easyrest.PagPrev:    "https://example/prev",
	}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := gjson.Unmarshal(raw.([]byte), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["count"] != float64(1) || decoded["next"] != nil || decoded["previous"] != "https://example/prev" {
		t.Fatalf("envelope %#v", decoded)
	}
	rows, _ := decoded["results"].([]any)
	if len(rows) != 1 {
		t.Fatalf("results %#v", decoded)
	}
	if _, _, err = p.Render(make(chan int), nil); err == nil {
		t.Fatal("expected encode error")
	}
	if _, _, err = p.Render(map[string]any{}, map[string]any{easyrest.CtxPagination: map[string]any{easyrest.PagResults: "missing"}}); err == nil {
		t.Fatal("expected pagination error")
	}
	windows, repeat := p.PrepareGet(0, 4, 25)
	if repeat || len(windows) != 1 || windows[0].Limit != 25 || windows[0].Offset != 4 {
		t.Fatalf("prepare %+v %v", windows, repeat)
	}
}
