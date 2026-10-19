package formcodec

import (
	"net/url"
	"strings"
	"testing"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestInitParseRender(t *testing.T) {
	p := New()
	info, err := p.Init(nil)
	if err != nil || info.RenderMedia != easyrest.MediaTypeForm || info.ParserMedia != easyrest.MediaTypeForm || info.Format != "form" {
		t.Fatalf("init %+v %v", info, err)
	}
	obj, _, err := p.Parse([]byte("name=FormUser&update_field=viaform"), nil)
	row, ok := obj.(map[string]any)
	if err != nil || !ok || row["name"] != "FormUser" || row["update_field"] != "viaform" {
		t.Fatalf("object %#v %v", obj, err)
	}
	many, _, err := p.Parse([]byte("name=Ada&tag=a&tag=b"), map[string]any{easyrest.CtxExpectArray: true})
	list, ok := many.([]any)
	if err != nil || !ok || len(list) != 1 {
		t.Fatalf("array %#v %v", many, err)
	}
	tags, ok := list[0].(map[string]any)["tag"].([]string)
	if !ok || len(tags) != 2 {
		t.Fatalf("tags %#v", list[0])
	}
	if _, _, err = p.Parse([]byte("%"), nil); err == nil || !strings.Contains(err.Error(), "form parse error") {
		t.Fatalf("bad form %v", err)
	}

	raw, _, err := p.Render(map[string]any{"name": "Ada"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	values, err := url.ParseQuery(string(raw.([]byte)))
	if err != nil || values.Get("name") != "Ada" {
		t.Fatalf("object body %q %v", raw, err)
	}
	raw, _, err = p.Render([]map[string]any{{"name": "Bea"}, {"name": "Cy"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	values, _ = url.ParseQuery(string(raw.([]byte)))
	if values.Get("name") != "Bea" {
		t.Fatalf("first row %q", raw)
	}
	raw, _, err = p.Render([]any{map[string]any{"name": "Dee"}}, nil)
	values, _ = url.ParseQuery(string(raw.([]byte)))
	if err != nil || values.Get("name") != "Dee" {
		t.Fatalf("any row %q %v", raw, err)
	}
	if _, _, err = p.Render([]map[string]any{}, nil); err == nil || !strings.Contains(err.Error(), "not suitable") {
		t.Fatalf("empty %v", err)
	}
	if _, _, err = p.Render("nope", nil); err == nil {
		t.Fatal("expected unsuitable string")
	}
	if _, _, err = p.Render(map[string]any{}, map[string]any{easyrest.CtxPagination: "bad"}); err == nil {
		t.Fatal("expected pagination error")
	}
}
