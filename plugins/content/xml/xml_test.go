package xmlcodec

import (
	"strings"
	"testing"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestInitParseRender(t *testing.T) {
	p := New()
	info, err := p.Init(nil)
	if err != nil || info.RenderMedia != easyrest.MediaTypeXML || info.ParserMedia != easyrest.MediaTypeXML || info.Format != "xml" {
		t.Fatalf("init %+v %v", info, err)
	}
	obj, _, err := p.Parse([]byte(`<?xml version="1.0"?><item> <name>After</name> <update_field>xml</update_field></item>`), nil)
	row, ok := obj.(map[string]any)
	if err != nil || !ok || row["name"] != "After" || row["update_field"] != "xml" {
		t.Fatalf("object %#v %v", obj, err)
	}
	items, _, err := p.Parse([]byte(`<items><note>skip</note><item><name>ada</name></item><item><name>bea</name></item></items>`), map[string]any{easyrest.CtxExpectArray: true})
	list, ok := items.([]any)
	if err != nil || !ok || len(list) != 2 {
		t.Fatalf("items %#v %v", items, err)
	}
	if _, _, err = p.Parse([]byte(`<item><name><b>x</b></name></item>`), nil); err == nil || !strings.Contains(err.Error(), "XML parse error") {
		t.Fatalf("nested %v", err)
	}
	if _, _, err = p.Parse([]byte(`not-xml`), nil); err == nil || !strings.Contains(err.Error(), "XML parse error") {
		t.Fatalf("garbage %v", err)
	}
	if _, _, err = p.Parse([]byte(``), map[string]any{easyrest.CtxExpectArray: true}); err == nil {
		t.Fatal("expected empty array error")
	}
	if _, _, err = p.Parse([]byte(`<items><<<`), map[string]any{easyrest.CtxExpectArray: true}); err == nil {
		t.Fatal("expected broken items")
	}
	if _, _, err = p.Parse([]byte(`<items><note>`), map[string]any{easyrest.CtxExpectArray: true}); err == nil {
		t.Fatal("expected skip error")
	}
	if _, _, err = p.Parse([]byte(`<items><item><name><b>x</b></name></item></items>`), map[string]any{easyrest.CtxExpectArray: true}); err == nil {
		t.Fatal("expected nested item error")
	}
	if _, _, err = p.Parse([]byte(`<item><name>`), nil); err == nil {
		t.Fatal("expected truncated field")
	}
	if _, _, err = p.Parse([]byte(`<item>`), nil); err == nil {
		t.Fatal("expected truncated object")
	}

	raw, _, err := p.Render([]map[string]any{{"name": "ada"}}, nil)
	if err != nil || !strings.Contains(string(raw.([]byte)), "<name>ada</name>") || !strings.Contains(string(raw.([]byte)), "<items>") {
		t.Fatalf("rows %q %v", raw, err)
	}
	raw, _, err = p.Render([]any{map[string]any{"name": "bea"}}, nil)
	if err != nil || !strings.Contains(string(raw.([]byte)), "<name>bea</name>") {
		t.Fatalf("any rows %q %v", raw, err)
	}
	raw, _, err = p.Render(map[string]any{
		"name":    "ada",
		"results": []map[string]any{{"name": "ada"}},
	}, nil)
	if err != nil || !strings.Contains(string(raw.([]byte)), "<name>ada</name>") || !strings.Contains(string(raw.([]byte)), "<results>") {
		t.Fatalf("envelope %q %v", raw, err)
	}
	raw, _, err = p.Render(map[string]any{"results": []any{map[string]any{"name": "cy"}}}, nil)
	if err != nil || !strings.Contains(string(raw.([]byte)), "<name>cy</name>") {
		t.Fatalf("any nested %q %v", raw, err)
	}
	if _, _, err = p.Render("nope", nil); err == nil || !strings.Contains(err.Error(), "not suitable for XML") {
		t.Fatalf("bad type %v", err)
	}
	if _, _, err = p.Render(map[string]any{}, map[string]any{easyrest.CtxPagination: map[string]any{easyrest.PagResults: "missing"}}); err == nil {
		t.Fatal("expected pagination error")
	}
	windows, repeat := p.PrepareGet(2, 1, 9)
	if repeat || windows[0].Limit != 2 || windows[0].Offset != 1 {
		t.Fatalf("prepare %+v %v", windows, repeat)
	}
}
