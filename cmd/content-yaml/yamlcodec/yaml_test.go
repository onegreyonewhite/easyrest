package yamlcodec

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestInit(t *testing.T) {
	info, err := New().Init(map[string]any{"ignored": true})
	if err != nil {
		t.Fatal(err)
	}
	if info.RenderMedia != easyrest.MediaTypeYAML || info.ParserMedia != easyrest.MediaTypeYAML || info.Format != "yaml" {
		t.Fatalf("Init %+v", info)
	}
	if info.Metadata == nil || info.Ctx == nil {
		t.Fatalf("meta %#v ctx %#v", info.Metadata, info.Ctx)
	}
}

func TestParseMappingAndSequence(t *testing.T) {
	p := New()
	value, _, err := p.Parse([]byte("name: ada\nn: 9\nneg: -3\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	row, ok := value.(map[string]any)
	if !ok || row["name"] != "ada" || row["n"] != uint64(9) || row["neg"] != int64(-3) {
		t.Fatalf("mapping %#v", value)
	}

	seq, _, err := p.Parse([]byte("- ada\n- bob\n"), map[string]any{easyrest.CtxExpectArray: true})
	if err != nil {
		t.Fatal(err)
	}
	list, ok := seq.([]any)
	if !ok || len(list) != 2 || list[0] != "ada" || list[1] != "bob" {
		t.Fatalf("sequence %#v", seq)
	}
}

func TestParseExpectArrayMismatch(t *testing.T) {
	p := New()
	if _, _, err := p.Parse([]byte("name: ada\n"), map[string]any{easyrest.CtxExpectArray: true}); err == nil || !strings.Contains(err.Error(), "expected array") {
		t.Fatalf("map: %v", err)
	}
	if _, _, err := p.Parse([]byte("- ada\n"), nil); err == nil || !strings.Contains(err.Error(), "expected object") {
		t.Fatalf("sequence: %v", err)
	}
}

func TestParseRejectsInvalidScalarAndNonFinite(t *testing.T) {
	p := New()
	if _, _, err := p.Parse([]byte(":\n"), nil); err == nil || !strings.Contains(err.Error(), "YAML parse error") {
		t.Fatalf("invalid: %v", err)
	}
	if _, _, err := p.Parse([]byte("hello\n"), nil); err == nil || !strings.Contains(err.Error(), "expected object or array") {
		t.Fatalf("scalar: %v", err)
	}
	for _, doc := range []string{"n: .nan\n", "n: .inf\n", "n: -.inf\n"} {
		if _, _, err := p.Parse([]byte(doc), nil); err == nil || !strings.Contains(err.Error(), "non-finite") {
			t.Fatalf("%q: %v", doc, err)
		}
	}
}

func TestRenderMappingAndPagination(t *testing.T) {
	p := New()
	raw, _, err := p.Render(map[string]any{"name": "ada"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := easyrest.RenderedBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	if err := yaml.Unmarshal(body, &row); err != nil {
		t.Fatal(err)
	}
	if row["name"] != "ada" {
		t.Fatalf("render %#v", row)
	}

	raw, _, err = p.Render(map[string]any{
		"results": []any{map[string]any{"name": "ada"}},
	}, map[string]any{
		easyrest.CtxPagination: map[string]any{
			easyrest.PagResults: "results",
			easyrest.PagCount:   9,
			easyrest.PagNext:    "https://example/next",
			easyrest.PagPrev:    nil,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err = easyrest.RenderedBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	var page map[string]any
	if err := yaml.Unmarshal(body, &page); err != nil {
		t.Fatalf("%v\n%s", err, body)
	}
	if page["count"] != uint64(9) || page["next"] != "https://example/next" || page["previous"] != nil {
		t.Fatalf("page %#v", page)
	}
	results, ok := page["results"].([]any)
	if !ok || len(results) != 1 {
		t.Fatalf("results %#v", page["results"])
	}
}

func TestPrepareGetAndCreate(t *testing.T) {
	p := New()
	windows, repeat := p.PrepareGet(0, 4, 2)
	if repeat || len(windows) != 1 || windows[0].Limit != 2 || windows[0].Offset != 4 {
		t.Fatalf("PrepareGet %+v repeat %v", windows, repeat)
	}
	body := map[string]any{"name": "ada"}
	chunks := p.PrepareCreate(body, 10)
	if len(chunks) != 1 || chunks[0] == nil {
		t.Fatalf("PrepareCreate %#v", chunks)
	}
}
