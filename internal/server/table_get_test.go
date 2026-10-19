package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/config"
)

type totalGetPlugin struct {
	fakeDBPlugin
	total any
}

func (p *totalGetPlugin) TableGet(string, string, []string, map[string]any, []string, []string, int, int, map[string]any) ([]map[string]any, map[string]any, error) {
	ctx := map[string]any{}
	if p.total != nil {
		ctx["total"] = p.total
	}
	return []map[string]any{{"id": 1}}, ctx, nil
}

func TestPreferPageSize(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ctx  map[string]any
		want int
	}{
		{name: "nil ctx"},
		{name: "missing prefer", ctx: map[string]any{}},
		{name: "missing key", ctx: map[string]any{"prefer": map[string]any{}}},
		{name: "valid", ctx: map[string]any{"prefer": map[string]any{"page_size": "50"}}, want: 50},
		{name: "zero", ctx: map[string]any{"prefer": map[string]any{"page_size": "0"}}},
		{name: "negative", ctx: map[string]any{"prefer": map[string]any{"page_size": "-1"}}},
		{name: "non integer", ctx: map[string]any{"prefer": map[string]any{"page_size": "abc"}}},
		{name: "non string", ctx: map[string]any{"prefer": map[string]any{"page_size": 20}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := preferPageSize(tc.ctx); got != tc.want {
				t.Fatalf("preferPageSize = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestTableGetContentRangeUsesTotal(t *testing.T) {
	orig := GetConfig()
	t.Cleanup(func() { SetConfig(orig) })
	SetConfig(config.Config{DefaultLimit: 10})

	plug := &totalGetPlugin{total: int64(40)}
	req := httptest.NewRequest(http.MethodGet, "/api/app/users/", nil)
	bag, req := newAPIRequest(req)
	t.Cleanup(func() { releaseAPIRequest(bag) })
	bag.dbKey = "app"
	bag.resource = "users"
	bag.userID = "u"
	bag.dbPlug = plug
	bag.pluginCfg = config.PluginConfig{DefaultLimit: 10}
	bag.pluginCtx = map[string]any{}
	bag.query = url.Values{}
	bag.respType = "application/json"

	w := httptest.NewRecorder()
	tableGet(w, req)
	if got := w.Header().Get("Content-Range"); got != "0-0/40" {
		t.Fatalf("Content-Range = %q, want 0-0/40", got)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}
