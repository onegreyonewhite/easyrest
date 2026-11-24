package pingpong_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/onegreyonewhite/easyrest/embed"
	"github.com/onegreyonewhite/easyrest/examples/pingpong"
	"github.com/onegreyonewhite/easyrest/internal/server"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	sqliteplugin "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
)

func TestPingReceivesPong(t *testing.T) {
	t.Cleanup(func() {
		server.StopPlugins()
		_, _ = embed.Handler("port: \"1\"\n", nil)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	pingURL := fmt.Sprintf("http://127.0.0.1:%d%s", port, pingpong.PongPath)
	first := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opts := []embed.Option{
		embed.WithDB("sqlite", func() easyrest.DBPlugin { return sqliteplugin.NewSqlitePlugin() }),
		embed.WithView("pong", pingpong.PongView),
		embed.WithService(func(runCtx context.Context) error {
			timer := time.NewTimer(0)
			defer timer.Stop()
			for {
				select {
				case <-runCtx.Done():
					return nil
				case <-timer.C:
				}
				body, err := pingpong.PingOnce(runCtx, pingURL)
				if err != nil {
					timer.Reset(100 * time.Millisecond)
					continue
				}
				select {
				case first <- body:
					<-runCtx.Done()
					return nil
				default:
				}
				timer.Reset(100 * time.Millisecond)
			}
		}),
	}

	done := make(chan error, 1)
	go func() {
		done <- embed.Serve(ctx, fmt.Sprintf(`
check_scope: false
port: "%d"
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
`, port), nil, opts...)
	}()

	select {
	case body := <-first:
		if body != "pong" {
			t.Fatalf("body: %q", body)
		}
		cancel()
	case <-time.After(15 * time.Second):
		t.Fatal(pingpong.ErrPingTimeout)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not stop")
	}
}