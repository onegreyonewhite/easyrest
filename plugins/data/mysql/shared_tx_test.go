package mysql

import (
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestSharedTx_TwoUpdatesOneCommit(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	t.Cleanup(func() { plugin.Close() })

	mock.ExpectBegin()
	id, _, err := plugin.BeginTx(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := map[string]any{easyrest.SharedTxKey: id}
	upQ := regexp.QuoteMeta("UPDATE items SET note = ? WHERE id = ?")
	where := map[string]any{"id": map[string]any{"=": 1}}
	mock.ExpectExec(upQ).WithArgs("a", 1).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(upQ).WithArgs("b", 1).WillReturnResult(sqlmock.NewResult(0, 1))
	if _, _, err := plugin.TableUpdate("u", "items", map[string]any{"note": "a"}, where, ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := plugin.TableUpdate("u", "items", map[string]any{"note": "b"}, where, ctx); err != nil {
		t.Fatal(err)
	}
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()
	mock.ExpectExec(regexp.QuoteMeta(clearKnownResponseVarsSQL)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	if _, err := plugin.CommitTx(id, ctx); err != nil {
		t.Fatal(err)
	}
	if err := plugin.RollbackTx(id); err != nil {
		t.Fatalf("rollback after commit: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSharedTx_StatementErrorAbortsCommit(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	t.Cleanup(func() { plugin.Close() })

	mock.ExpectBegin()
	id, _, err := plugin.BeginTx(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := map[string]any{easyrest.SharedTxKey: id}
	upQ := regexp.QuoteMeta("UPDATE items SET note = ? WHERE id = ?")
	mock.ExpectExec(upQ).WithArgs("a", 1).WillReturnError(errors.New("statement failed"))
	_, _, err = plugin.TableUpdate("u", "items", map[string]any{"note": "a"}, map[string]any{"id": map[string]any{"=": 1}}, ctx)
	if err == nil {
		t.Fatal("expected statement error")
	}
	if _, err := plugin.CommitTx(id, ctx); !errors.Is(err, easyrest.ErrSharedTxAborted) {
		t.Fatalf("commit: %v", err)
	}
	mock.ExpectRollback()
	if err := plugin.RollbackTx(id); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
