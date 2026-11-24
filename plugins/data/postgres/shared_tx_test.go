package postgres

import (
	"errors"
	"strings"
	"testing"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	pgxmock "github.com/pashagolub/pgxmock/v4"
)

func TestSharedTx_TwoUpdatesOneCommit(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	t.Cleanup(plugin.Close)

	mock.ExpectBegin()
	id, _, err := plugin.BeginTx(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := map[string]any{easyrest.SharedTxKey: id}
	where := map[string]any{"id": map[string]any{"=": 1}}
	sqlText := `UPDATE users SET name = $1 WHERE id = $2`
	mock.ExpectExec(sqlText).WithArgs("ada", 1).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectExec(sqlText).WithArgs("grace", 1).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	if _, _, err := plugin.TableUpdate("u", "users", map[string]any{"name": "ada"}, where, ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := plugin.TableUpdate("u", "users", map[string]any{"name": "grace"}, where, ctx); err != nil {
		t.Fatal(err)
	}
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()
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
	t.Cleanup(plugin.Close)

	mock.ExpectBegin()
	id, _, err := plugin.BeginTx(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := map[string]any{easyrest.SharedTxKey: id}
	mock.ExpectExec(`UPDATE users SET name = $1 WHERE id = $2`).
		WithArgs("ada", 1).
		WillReturnError(errors.New("statement failed"))
	_, _, err = plugin.TableUpdate("u", "users", map[string]any{"name": "ada"}, map[string]any{"id": map[string]any{"=": 1}}, ctx)
	if err == nil || !strings.Contains(err.Error(), "statement failed") {
		t.Fatalf("update: %v", err)
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

func TestSharedTx_BulkCreateRefused(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	t.Cleanup(plugin.Close)
	plugin.bulkThreshold = 1
	ctx := map[string]any{easyrest.SharedTxKey: "session"}
	_, _, err := plugin.TableCreate("u", "users", []map[string]any{{"name": "ada"}}, ctx)
	if err == nil || !strings.Contains(err.Error(), "bulk create is not supported") {
		t.Fatalf("bulk: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
