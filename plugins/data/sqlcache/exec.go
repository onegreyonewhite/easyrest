package sqlcache

import (
	"context"
	"database/sql"
	"errors"
)

// ErrNoDB is returned when the underlying connection is missing.
var ErrNoDB = errors.New("database connection not available")

// SQLDB adapts *sql.DB to Executor.
type SQLDB struct {
	DB *sql.DB
}

func (s SQLDB) Exec(ctx context.Context, query string, args ...any) error {
	if s.DB == nil {
		return ErrNoDB
	}
	_, err := s.DB.ExecContext(ctx, query, args...)
	return err
}

func (s SQLDB) QueryValue(ctx context.Context, query string, args ...any) (string, error) {
	if s.DB == nil {
		return "", ErrNoDB
	}
	var value string
	err := s.DB.QueryRowContext(ctx, query, args...).Scan(&value)
	return value, err
}

// FuncExec adapts arbitrary Exec/QueryValue functions to Executor.
type FuncExec struct {
	ExecFn  func(ctx context.Context, query string, args ...any) error
	QueryFn func(ctx context.Context, query string, args ...any) (string, error)
}

func (f FuncExec) Exec(ctx context.Context, query string, args ...any) error {
	if f.ExecFn == nil {
		return ErrNoDB
	}
	return f.ExecFn(ctx, query, args...)
}

func (f FuncExec) QueryValue(ctx context.Context, query string, args ...any) (string, error) {
	if f.QueryFn == nil {
		return "", ErrNoDB
	}
	return f.QueryFn(ctx, query, args...)
}
