package pingpong

import (
	"context"
	"net/http"

	"github.com/onegreyonewhite/easyrest/embed"
	sqliteplugin "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// PongView is the embed rest view that answers ping with pong.
func PongView(w http.ResponseWriter, _ embed.Call) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("pong"))
}

// EmbedOptions registers the sqlite plugin, pong view, and ping service for embed.Run.
func EmbedOptions(pingURL string, logf func(string, ...any)) []embed.Option {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	url := pingURL
	return []embed.Option{
		embed.WithDB("sqlite", func() easyrest.DBPlugin { return sqliteplugin.NewSqlitePlugin() }),
		embed.WithView("pong", PongView),
		embed.WithService(func(ctx context.Context, _ embed.PluginCaller) error {
			return RunPing(ctx, url, logf)
		}),
	}
}