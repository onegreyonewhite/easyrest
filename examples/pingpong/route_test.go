package pingpong_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/onegreyonewhite/easyrest/embed"
	"github.com/onegreyonewhite/easyrest/examples/pingpong"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	sqliteplugin "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
)

func TestPongViewRoute(t *testing.T) {
	t.Cleanup(func() {
		_, _ = embed.Handler("port: \"1\"\n", nil)
	})
	handler, err := embed.Handler(`
check_scope: false
port: "1"
plugins:
  app:
    uri: "sqlite://:memory:"
application:
  source: app
  public: true
  api:
    v1:
      auth: []
      endpoints:
        game:
          table: game
          views:
            pong:
              path: pong
              methods: [GET]
              handler: pong
`, nil,
		embed.WithDB("sqlite", func() easyrest.DBPlugin { return sqliteplugin.NewSqlitePlugin() }),
		embed.WithView("pong", pingpong.PongView),
	)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, pingpong.PongPath, nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "pong" {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
}