package plugin

import (
	"errors"
	"testing"
)

func TestContentBasePrepareAndUnsupported(t *testing.T) {
	var base ContentBase
	windows, repeat := base.PrepareGet(5, 2, 10)
	if repeat || len(windows) != 1 || windows[0].Limit != 5 || windows[0].Offset != 2 {
		t.Fatalf("explicit limit: %+v repeat=%v", windows, repeat)
	}
	windows, repeat = base.PrepareGet(0, 3, 10)
	if repeat || len(windows) != 1 || windows[0].Limit != 10 || windows[0].Offset != 3 {
		t.Fatalf("page fallback: %+v repeat=%v", windows, repeat)
	}
	windows, repeat = base.PrepareGet(0, 1, 0)
	if repeat || windows[0].Limit != 0 || windows[0].Offset != 1 {
		t.Fatalf("zero page: %+v repeat=%v", windows, repeat)
	}
	chunks := base.PrepareCreate(map[string]any{"a": 1}, 5)
	if len(chunks) != 1 {
		t.Fatalf("chunks = %#v", chunks)
	}
	if _, _, err := base.Parse(nil, nil); !errors.Is(err, ErrContentUnsupported) {
		t.Fatalf("Parse err = %v", err)
	}
	if _, _, err := base.Render(nil, nil); !errors.Is(err, ErrContentUnsupported) {
		t.Fatalf("Render err = %v", err)
	}
}

func TestNewContentInfo(t *testing.T) {
	info := NewContentInfo(MediaTypeYAML, MediaTypeYAML, "yaml")
	if info.RenderMedia != MediaTypeYAML || info.ParserMedia != MediaTypeYAML || info.Format != "yaml" {
		t.Fatalf("info %+v", info)
	}
	if info.Metadata == nil || info.Ctx == nil {
		t.Fatalf("meta %#v ctx %#v", info.Metadata, info.Ctx)
	}
}

func TestExpectArrayAndEscape(t *testing.T) {
	if ExpectArray(nil) || ExpectArray(map[string]any{}) || ExpectArray(map[string]any{CtxExpectArray: "yes"}) {
		t.Fatal("expected false")
	}
	if !ExpectArray(map[string]any{CtxExpectArray: true}) {
		t.Fatal("expected true")
	}
	if !JSONEscapeHTML(nil) || !JSONEscapeHTML(map[string]any{}) || !JSONEscapeHTML(map[string]any{CtxJSONEscapeHTML: "no"}) {
		t.Fatal("default escape")
	}
	if JSONEscapeHTML(map[string]any{CtxJSONEscapeHTML: false}) {
		t.Fatal("escape disabled")
	}
	if !JSONEscapeHTML(map[string]any{CtxJSONEscapeHTML: true}) {
		t.Fatal("escape enabled")
	}
}

func TestMapRows(t *testing.T) {
	rows, ok := MapRows([]map[string]any{{"a": 1}})
	if !ok || len(rows) != 1 || rows[0]["a"] != 1 {
		t.Fatalf("maps %#v %v", rows, ok)
	}
	rows, ok = MapRows([]any{map[string]any{"b": 2}})
	if !ok || rows[0]["b"] != 2 {
		t.Fatalf("any %#v %v", rows, ok)
	}
	if _, ok = MapRows([]any{"nope"}); ok {
		t.Fatal("mixed slice")
	}
	if _, ok = MapRows(map[string]any{}); ok {
		t.Fatal("object")
	}
}

func TestPaginationView(t *testing.T) {
	data := []map[string]any{{"id": 1}}
	payload, meta, err := PaginationView(data, nil)
	if err != nil || meta != nil || payload == nil {
		t.Fatalf("nil ctx payload=%#v meta=%#v err=%v", payload, meta, err)
	}
	payload, meta, err = PaginationView(data, map[string]any{})
	if err != nil || meta != nil {
		t.Fatalf("absent pagination meta=%#v err=%v", meta, err)
	}
	_, _, err = PaginationView(data, map[string]any{CtxPagination: "bad"})
	if err == nil {
		t.Fatal("expected object error")
	}
	payload, meta, err = PaginationView(data, map[string]any{CtxPagination: map[string]any{PagNext: "n"}})
	if err != nil || meta[PagNext] != "n" || payload == nil {
		t.Fatalf("no results field payload=%#v err=%v", payload, err)
	}
	body := map[string]any{"results": data, "count": 3}
	payload, meta, err = PaginationView(body, map[string]any{CtxPagination: map[string]any{PagResults: "results", PagCount: 3}})
	rows, ok := payload.([]map[string]any)
	if err != nil || !ok || len(rows) != 1 || meta[PagCount] != 3 {
		t.Fatalf("extract payload=%#v meta=%#v err=%v", payload, meta, err)
	}
	_, _, err = PaginationView([]any{}, map[string]any{CtxPagination: map[string]any{PagResults: "results"}})
	if err == nil {
		t.Fatal("expected non-object error")
	}
	_, _, err = PaginationView(map[string]any{}, map[string]any{CtxPagination: map[string]any{PagResults: "results"}})
	if err == nil {
		t.Fatal("expected missing field")
	}
}

func TestStandardContentNames(t *testing.T) {
	names := StandardContentNames()
	if len(names) != 5 || names[0] != "json" || names[4] != "form" {
		t.Fatalf("names = %#v", names)
	}
	for _, name := range names {
		if name == "html" {
			t.Fatal("html is not a standard content plugin")
		}
	}
}

func TestSwaggerContextConstants(t *testing.T) {
	if MediaTypeHTML != "text/html" || CtxSwagger != "content.swagger" || SwaggerDocument != "document" || SwaggerCatalog != "catalog" {
		t.Fatalf("swagger constants %q %q %q %q", MediaTypeHTML, CtxSwagger, SwaggerDocument, SwaggerCatalog)
	}
	if CtxSwaggerFormat == "" || CtxSwaggerAssets == "" || CtxSwaggerURL == "" || CtxSwaggerAuth == "" || CtxSwaggerEmbed == "" || CtxSwaggerTemplate == "" {
		t.Fatal("swagger url constants are empty")
	}
}

func TestRenderedBytes(t *testing.T) {
	got, err := RenderedBytes([]byte("ab"))
	if err != nil || string(got) != "ab" {
		t.Fatalf("bytes %q %v", got, err)
	}
	got, err = RenderedBytes("cd")
	if err != nil || string(got) != "cd" {
		t.Fatalf("string %q %v", got, err)
	}
	if _, err = RenderedBytes(1); err == nil {
		t.Fatal("expected type error")
	}
}
