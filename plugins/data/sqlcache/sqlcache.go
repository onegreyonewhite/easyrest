package sqlcache

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"time"
)

// Dialect holds backend-specific SQL for the easyrest_cache table.
type Dialect struct {
	CreateTable   string
	DeleteExpired string
	Upsert        string
	SelectLive    string
	GetUsesNowArg bool
}

// Executor runs cache SQL against a backend connection.
type Executor interface {
	Exec(ctx context.Context, query string, args ...any) error
	QueryValue(ctx context.Context, query string, args ...any) (string, error)
}

// Store implements cache.Store lifecycle shared by SQL backends.
type Store struct {
	Exec     Executor
	Dialect  Dialect
	stopCh   chan struct{}
	stopOnce sync.Once
	setStmt  *sql.Stmt
	getStmt  *sql.Stmt
}

func (s *Store) EnsureTable(ctx context.Context) error {
	return s.Exec.Exec(ctx, s.Dialect.CreateTable)
}

func (s *Store) Prepare(db *sql.DB) error {
	getStmt, err := db.Prepare(s.Dialect.SelectLive)
	if err != nil {
		return fmt.Errorf("failed to prepare get cache statement: %w", err)
	}
	setStmt, err := db.Prepare(s.Dialect.Upsert)
	if err != nil {
		getStmt.Close()
		return fmt.Errorf("failed to prepare set cache statement: %w", err)
	}
	s.getStmt = getStmt
	s.setStmt = setStmt
	return nil
}

func (s *Store) StartCleanup() {
	if s.stopCh == nil {
		s.stopCh = make(chan struct{})
	}
	go s.cleanup()
}

func (s *Store) Stop() {
	s.stopOnce.Do(func() {
		if s.stopCh != nil {
			close(s.stopCh)
		}
	})
	if s.getStmt != nil {
		s.getStmt.Close()
		s.getStmt = nil
	}
	if s.setStmt != nil {
		s.setStmt.Close()
		s.setStmt = nil
	}
}

func (s *Store) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	ctx := context.Background()
	for {
		select {
		case <-ticker.C:
			if err := s.DeleteExpired(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "Error cleaning up expired cache entries: %v\n", err)
			}
		case <-s.stopCh:
			return
		}
	}
}

func (s *Store) DeleteExpired(ctx context.Context) error {
	return s.Exec.Exec(ctx, s.Dialect.DeleteExpired)
}

func (s *Store) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	expiresAt := time.Now().Add(ttl)
	if s.setStmt != nil {
		_, err := s.setStmt.Exec(key, value, expiresAt)
		return err
	}
	return s.Exec.Exec(ctx, s.Dialect.Upsert, key, value, expiresAt)
}

func (s *Store) Get(ctx context.Context, key string) (string, error) {
	if s.getStmt != nil {
		var value string
		args := []any{key}
		if s.Dialect.GetUsesNowArg {
			args = append(args, time.Now())
		}
		err := s.getStmt.QueryRow(args...).Scan(&value)
		return value, err
	}
	args := []any{key}
	if s.Dialect.GetUsesNowArg {
		args = append(args, time.Now())
	}
	return s.Exec.QueryValue(ctx, s.Dialect.SelectLive, args...)
}
