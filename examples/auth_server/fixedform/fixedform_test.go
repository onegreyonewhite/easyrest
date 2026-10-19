package fixedform

import (
	"strings"
	"testing"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestFixedForm(t *testing.T) {
	p := New()
	info, err := p.Init(map[string]any{
		"fields": []any{"email", "password", "next"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.RenderMedia != "" || info.ParserMedia != easyrest.MediaTypeForm || info.Format != "form" {
		t.Fatalf("Init %+v", info)
	}

	got, _, err := p.Parse([]byte("email=ada%40example.com&password=secret&extra=1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	row, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("parse %#v", got)
	}
	if row["email"] != "ada@example.com" || row["password"] != "secret" || row["next"] != nil {
		t.Fatalf("row %#v", row)
	}
	if _, ok := row["extra"]; ok {
		t.Fatalf("unknown key kept %#v", row)
	}

	if _, _, err := p.Parse([]byte("email=a&email=b&password=secret"), nil); err == nil || !strings.Contains(err.Error(), "repeated") {
		t.Fatalf("repeated: %v", err)
	}
	if _, _, err := p.Parse([]byte("email=%zz"), nil); err == nil {
		t.Fatal("bad encoding accepted")
	}
}
