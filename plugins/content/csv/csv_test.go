package csvcodec

import (
	"io"
	"strings"
	"testing"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestInitParseRender(t *testing.T) {
	p := New()
	info, err := p.Init(nil)
	if err != nil || info.RenderMedia != easyrest.MediaTypeCSV || info.ParserMedia != easyrest.MediaTypeCSV || info.Format != "csv" {
		t.Fatalf("init %+v %v", info, err)
	}
	one, _, err := p.Parse([]byte("name,update_field\nAlice,csv1\n"), nil)
	row, ok := one.(map[string]any)
	if err != nil || !ok || row["name"] != "Alice" || row["update_field"] != "csv1" {
		t.Fatalf("unwrap %#v %v", one, err)
	}
	many, _, err := p.Parse([]byte("name\nAda\nBea\n"), map[string]any{easyrest.CtxExpectArray: true})
	rows, ok := many.([]any)
	if err != nil || !ok || len(rows) != 2 {
		t.Fatalf("array %#v %v", many, err)
	}
	short, _, err := p.Parse([]byte("name,city\nAda\n"), map[string]any{easyrest.CtxExpectArray: true})
	shortRows := short.([]any)
	if err != nil || shortRows[0].(map[string]any)["city"] != "" {
		t.Fatalf("short %#v %v", short, err)
	}
	if _, _, err = p.Parse([]byte(""), nil); err == nil || !strings.Contains(err.Error(), "empty CSV data") {
		t.Fatalf("empty %v", err)
	}
	if _, _, err = p.Parse([]byte("\"open"), nil); err == nil || !strings.Contains(err.Error(), "CSV parse error") {
		t.Fatalf("broken %v", err)
	}
	headerOnly, _, err := p.Parse([]byte("name\n"), map[string]any{easyrest.CtxExpectArray: false})
	if err != nil || len(headerOnly.([]any)) != 0 {
		t.Fatalf("header only %#v %v", headerOnly, err)
	}

	raw, ctx, err := p.Render([]map[string]any{{"name": "Ada"}}, nil)
	if err != nil || ctx != nil || !strings.Contains(string(raw.([]byte)), "Ada") {
		t.Fatalf("rows %q ctx=%#v %v", raw, ctx, err)
	}
	raw, _, err = p.Render([]any{map[string]any{"name": "Bea"}}, nil)
	if err != nil || !strings.Contains(string(raw.([]byte)), "Bea") {
		t.Fatalf("any %q %v", raw, err)
	}
	raw, _, err = p.Render(map[string]any{"name": "Cy"}, nil)
	if err != nil || !strings.Contains(string(raw.([]byte)), "Cy") {
		t.Fatalf("object %q %v", raw, err)
	}
	if _, _, err = p.Render([]map[string]any{}, nil); err == nil || !strings.Contains(err.Error(), "not suitable for CSV") {
		t.Fatalf("empty rows %v", err)
	}
	body := map[string]any{"results": []map[string]any{{"name": "Ada"}}}
	raw, ctx, err = p.Render(body, map[string]any{
		easyrest.CtxPagination: map[string]any{
			easyrest.PagResults: "results",
			easyrest.PagPrev:    "https://api.example.com/issues?page=2",
			easyrest.PagNext:    "https://api.example.com/issues?page=4",
			easyrest.PagCount:   9,
		},
		easyrest.CtxResponseHeaders: []map[string]any{{"X-A": "1"}},
	})
	if err != nil || !strings.Contains(string(raw.([]byte)), "Ada") {
		t.Fatalf("paged %q %v", raw, err)
	}
	link := headerValue(ctx, "Link")
	if !strings.Contains(link, `<https://api.example.com/issues?page=2>; rel="prev"`) ||
		!strings.Contains(link, `<https://api.example.com/issues?page=4>; rel="next"`) ||
		!strings.Contains(link, `<>; rel="count"; total="9"`) {
		t.Fatalf("link %q", link)
	}
	_, ctx, err = p.Render(body, map[string]any{
		easyrest.CtxPagination: map[string]any{
			easyrest.PagResults: "results",
			easyrest.PagPrev:    "",
			easyrest.PagNext:    3,
			easyrest.PagCount:   int64(2),
		},
		easyrest.CtxResponseHeaders: []any{map[string]any{"X-B": "2"}},
	})
	if err != nil || !strings.Contains(headerValue(ctx, "Link"), `total="2"`) || strings.Contains(headerValue(ctx, "Link"), "rel=\"prev\"") {
		t.Fatalf("partial link %#v %v", ctx, err)
	}
	_, ctx, err = p.Render(body, map[string]any{easyrest.CtxPagination: map[string]any{
		easyrest.PagResults: "results",
		easyrest.PagCount:   "40",
	}})
	if err != nil || !strings.Contains(headerValue(ctx, "Link"), `total="40"`) {
		t.Fatalf("string count %#v %v", ctx, err)
	}
	_, ctx, err = p.Render(body, map[string]any{easyrest.CtxPagination: map[string]any{
		easyrest.PagResults: "results",
		easyrest.PagCount:   "",
	}})
	if err != nil || headerValue(ctx, "Link") != "" {
		t.Fatalf("blank count %#v %v", ctx, err)
	}
	_, _, err = p.Render(body, map[string]any{easyrest.CtxPagination: map[string]any{
		easyrest.PagResults: "results",
		easyrest.PagCount:   true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = p.Render(map[string]any{}, map[string]any{easyrest.CtxPagination: map[string]any{easyrest.PagResults: "results"}}); err == nil {
		t.Fatal("expected missing results")
	}
	if _, _, err = p.Render(float64(1.5), nil); err == nil {
		t.Fatal("expected unsuitable")
	}
	raw, _, err = p.Render([]map[string]any{{"a": 1}, {"b": 2}}, nil)
	if err != nil || !strings.Contains(string(raw.([]byte)), "a") || !strings.Contains(string(raw.([]byte)), "b") {
		t.Fatalf("sparse rows %q %v", raw, err)
	}
	_, ctx, err = p.Render(body, map[string]any{easyrest.CtxPagination: map[string]any{
		easyrest.PagResults: "results",
		easyrest.PagCount:   1.5,
	}})
	if err != nil || !strings.Contains(headerValue(ctx, "Link"), `total="1"`) {
		t.Fatalf("float count %#v %v", ctx, err)
	}
	origWrite := writeAll
	writeAll = func(io.Writer, [][]string) error { return errFail }
	t.Cleanup(func() { writeAll = origWrite })
	if _, _, err = p.Render([]map[string]any{{"name": "Ada"}}, nil); err == nil {
		t.Fatal("expected write failure")
	}
	if err := writeRecords(failWriter{}, [][]string{{"a"}}); err == nil || !strings.Contains(err.Error(), "Error writing CSV") {
		t.Fatalf("write %v", err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errFail }

var errFail = errString("fail")

type errString string

func (e errString) Error() string { return string(e) }

func TestPrepareGetAndContinuation(t *testing.T) {
	p := New()
	windows, repeat := p.PrepareGet(0, 0, 2)
	if !repeat || len(windows) != 1 || windows[0].Limit != 2 || windows[0].Offset != 0 {
		t.Fatalf("page window %#v repeat=%v", windows, repeat)
	}
	windows, repeat = p.PrepareGet(1, 4, 2)
	if !repeat || len(windows) != 1 || windows[0].Limit != 1 || windows[0].Offset != 4 {
		t.Fatalf("remaining %#v repeat=%v", windows, repeat)
	}
	windows, repeat = p.PrepareGet(5, 0, 2)
	if !repeat || len(windows) != 1 || windows[0].Limit != 2 {
		t.Fatalf("cap above page %#v repeat=%v", windows, repeat)
	}
	windows, repeat = p.PrepareGet(5, 0, 0)
	if repeat || windows != nil {
		t.Fatalf("one shot %#v repeat=%v", windows, repeat)
	}

	page1 := []map[string]any{{"id": "1", "name": "a"}, {"id": "2", "name": "b"}}
	raw1, ctx, err := p.Render(page1, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	ctx[easyrest.CtxContinue] = true
	raw2, _, err := p.Render([]map[string]any{{"id": "3", "name": "c"}}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw1.([]byte)) + string(raw2.([]byte))
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) != 4 {
		t.Fatalf("lines %d body %q", len(lines), body)
	}
	headers := 0
	for _, line := range lines {
		if strings.Contains(line, "id") && strings.Contains(line, "name") {
			headers++
		}
	}
	if headers != 1 {
		t.Fatalf("header rows %d body %q", headers, body)
	}
	empty, _, err := p.Render([]map[string]any{}, map[string]any{easyrest.CtxContinue: true})
	if err != nil || len(empty.([]byte)) != 0 {
		t.Fatalf("empty continuation %#v %v", empty, err)
	}
}

func headerValue(ctx map[string]any, name string) string {
	if ctx == nil {
		return ""
	}
	switch headers := ctx[easyrest.CtxResponseHeaders].(type) {
	case []map[string]any:
		for _, item := range headers {
			if v, ok := item[name].(string); ok {
				return v
			}
		}
	case []any:
		for _, item := range headers {
			obj, _ := item.(map[string]any)
			if v, ok := obj[name].(string); ok {
				return v
			}
		}
	}
	return ""
}
