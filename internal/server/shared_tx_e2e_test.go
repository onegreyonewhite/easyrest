package server

import (
	"context"
	"database/sql"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	"github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
)

func TestSharedTx_SQLiteThroughInternalDispatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	plug := sqlite.NewSqlitePlugin()
	if err := plug.InitConnection("sqlite://" + path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { plug.Close() })

	other, err := sql.Open("sqlite", "file:"+path+"?_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { other.Close() })
	if _, err := other.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)`); err != nil {
		t.Fatal(err)
	}

	origCfg := GetConfig()
	origDB := DbPlugins.Load()
	t.Cleanup(func() {
		SetConfig(origCfg)
		DbPlugins.Store(origDB)
	})
	SetConfig(config.Config{
		PluginMap: map[string]config.PluginConfig{"db": {Uri: "sqlite://" + path}},
	})
	DbPlugins.Store(&map[string]easyrest.DBPlugin{"db": plug})

	count := func() int {
		t.Helper()
		var n int
		if err := other.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	create := func(session DBSession, name string) {
		t.Helper()
		res, err := session.TableCreate(easyrest.HostCall{
			DB:     "db",
			Name:   "users",
			Header: map[string]string{"Content-Type": "application/json"},
			Body:   []byte(`[{"name":"` + name + `"}]`),
		})
		if err != nil || res.Status != http.StatusCreated {
			t.Fatalf("create %s: status %d err %v body %q", name, res.Status, err, res.Body)
		}
	}

	session, err := directPlugins{}.Begin(context.Background(), "db")
	if err != nil {
		t.Fatal(err)
	}
	create(session, "ada")
	create(session, "grace")
	if n := count(); n != 0 {
		t.Fatalf("uncommitted rows visible: %d", n)
	}
	if err := session.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 0 {
		t.Fatalf("rows after rollback: %d", n)
	}

	session, err = directPlugins{}.Begin(context.Background(), "db")
	if err != nil {
		t.Fatal(err)
	}
	create(session, "ada")
	create(session, "grace")
	if _, err := session.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 2 {
		t.Fatalf("committed rows: %d", n)
	}
}
