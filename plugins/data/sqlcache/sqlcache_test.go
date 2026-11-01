package sqlcache

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func testDialect() Dialect {
	return Dialect{
		CreateTable:   "CREATE TABLE cache",
		DeleteExpired: "DELETE FROM cache",
		Upsert:        "UPSERT cache",
		SelectLive:    "SELECT value FROM cache WHERE key = ?",
		DeleteKey:     "DELETE FROM cache WHERE key = ?",
	}
}

func TestSQLDBNilAndRoundTrip(t *testing.T) {
	ctx := context.Background()
	if err := (SQLDB{}).Exec(ctx, "x"); !errors.Is(err, ErrNoDB) {
		t.Fatalf("nil exec: %v", err)
	}
	if _, err := (SQLDB{}).QueryValue(ctx, "x"); !errors.Is(err, ErrNoDB) {
		t.Fatalf("nil query: %v", err)
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := SQLDB{DB: db}
	mock.ExpectExec("CREATE TABLE cache").WillReturnResult(sqlmock.NewResult(0, 0))
	if err := exec.Exec(ctx, "CREATE TABLE cache"); err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery("SELECT value FROM cache WHERE key = ?").
		WithArgs("k").
		WillReturnRows(sqlmock.NewRows([]string{"value"}).AddRow("v"))
	got, err := exec.QueryValue(ctx, "SELECT value FROM cache WHERE key = ?", "k")
	if err != nil || got != "v" {
		t.Fatalf("query: %q %v", got, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFuncExecNil(t *testing.T) {
	ctx := context.Background()
	if err := (FuncExec{}).Exec(ctx, "x"); !errors.Is(err, ErrNoDB) {
		t.Fatalf("nil execfn: %v", err)
	}
	if _, err := (FuncExec{}).QueryValue(ctx, "x"); !errors.Is(err, ErrNoDB) {
		t.Fatalf("nil queryfn: %v", err)
	}
	called := false
	f := FuncExec{
		ExecFn: func(context.Context, string, ...any) error {
			called = true
			return nil
		},
		QueryFn: func(context.Context, string, ...any) (string, error) { return "ok", nil },
	}
	if err := f.Exec(ctx, "q"); err != nil || !called {
		t.Fatal(err)
	}
	if got, err := f.QueryValue(ctx, "q"); err != nil || got != "ok" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestStoreSetGetAndCleanup(t *testing.T) {
	ctx := context.Background()
	var lastQuery string
	var lastArgs []any
	store := Store{
		Dialect: testDialect(),
		Exec: FuncExec{
			ExecFn: func(_ context.Context, query string, args ...any) error {
				lastQuery = query
				lastArgs = args
				return nil
			},
			QueryFn: func(_ context.Context, query string, args ...any) (string, error) {
				lastQuery = query
				lastArgs = args
				return "hit", nil
			},
		},
	}
	if err := store.EnsureTable(ctx); err != nil || lastQuery != "CREATE TABLE cache" {
		t.Fatalf("ensure: %q %v", lastQuery, err)
	}
	if err := store.DeleteExpired(ctx); err != nil || lastQuery != "DELETE FROM cache" {
		t.Fatalf("delete: %q %v", lastQuery, err)
	}
	if err := store.Delete(ctx, "k"); err != nil || lastQuery != store.Dialect.DeleteKey || len(lastArgs) != 1 || lastArgs[0] != "k" {
		t.Fatalf("delete key: %q %#v %v", lastQuery, lastArgs, err)
	}
	if err := store.Set(ctx, "k", "v", time.Minute); err != nil {
		t.Fatal(err)
	}
	if lastQuery != "UPSERT cache" || len(lastArgs) != 3 || lastArgs[0] != "k" || lastArgs[1] != "v" {
		t.Fatalf("set args: %#v query=%s", lastArgs, lastQuery)
	}
	got, err := store.Get(ctx, "k")
	if err != nil || got != "hit" || lastQuery != store.Dialect.SelectLive {
		t.Fatalf("get: %q %v %s", got, err, lastQuery)
	}

	store.Dialect.GetUsesNowArg = true
	if _, err := store.Get(ctx, "k2"); err != nil || len(lastArgs) != 2 {
		t.Fatalf("get now arg: %#v %v", lastArgs, err)
	}

	store.StartCleanup()
	store.Stop()
	store.Stop() // second close is a no-op via stopOnce
}

func TestStorePrepareAndPreparedGetSet(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := Store{Dialect: testDialect()}

	mock.ExpectPrepare("SELECT value FROM cache WHERE key = ?").WillReturnError(errors.New("prep get"))
	if err := store.Prepare(db); err == nil {
		t.Fatal("expected prepare get error")
	}

	mock.ExpectPrepare("SELECT value FROM cache WHERE key = ?").WillBeClosed()
	mock.ExpectPrepare("UPSERT cache").WillReturnError(errors.New("prep set"))
	if err := store.Prepare(db); err == nil {
		t.Fatal("expected prepare set error")
	}

	get := mock.ExpectPrepare("SELECT value FROM cache WHERE key = ?")
	set := mock.ExpectPrepare("UPSERT cache")
	del := mock.ExpectPrepare("DELETE FROM cache WHERE key = ?")
	if err := store.Prepare(db); err != nil {
		t.Fatal(err)
	}
	set.ExpectExec().WithArgs("k", "v", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.Set(context.Background(), "k", "v", time.Second); err != nil {
		t.Fatal(err)
	}
	get.ExpectQuery().WithArgs("k").WillReturnRows(sqlmock.NewRows([]string{"value"}).AddRow("v"))
	got, err := store.Get(context.Background(), "k")
	if err != nil || got != "v" {
		t.Fatalf("prepared get: %q %v", got, err)
	}

	store.Dialect.GetUsesNowArg = true
	get.ExpectQuery().WithArgs("k", sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"value"}).AddRow("now"))
	got, err = store.Get(context.Background(), "k")
	if err != nil || got != "now" {
		t.Fatalf("prepared get now: %q %v", got, err)
	}

	del.ExpectExec().WithArgs("k").WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.Delete(context.Background(), "k"); err != nil {
		t.Fatal(err)
	}
	get.WillBeClosed()
	set.WillBeClosed()
	del.WillBeClosed()
	store.Stop()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreSetGetErrors(t *testing.T) {
	store := Store{
		Dialect: testDialect(),
		Exec: FuncExec{
			ExecFn:  func(context.Context, string, ...any) error { return errors.New("set fail") },
			QueryFn: func(context.Context, string, ...any) (string, error) { return "", sql.ErrNoRows },
		},
	}
	if err := store.Set(context.Background(), "k", "v", time.Second); err == nil {
		t.Fatal("expected set error")
	}
	if _, err := store.Get(context.Background(), "k"); !errors.Is(err, sql.ErrNoRows) || !errors.Is(err, easyrest.ErrCacheMiss) {
		t.Fatalf("expected miss: %v", err)
	}
}
