package plugin

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestSharedTxID(t *testing.T) {
	if id, ok := SharedTxID(nil); ok || id != "" {
		t.Fatalf("nil ctx: %q %v", id, ok)
	}
	if id, ok := SharedTxID(map[string]any{}); ok || id != "" {
		t.Fatalf("missing key: %q %v", id, ok)
	}
	if _, ok := SharedTxID(map[string]any{SharedTxKey: ""}); ok {
		t.Fatal("empty id must be absent")
	}
	if _, ok := SharedTxID(map[string]any{SharedTxKey: 7}); ok {
		t.Fatal("non-string id must be absent")
	}
	id, ok := SharedTxID(map[string]any{SharedTxKey: "abc"})
	if !ok || id != "abc" {
		t.Fatalf("id: %q %v", id, ok)
	}
	if !SkipDBSessionKey(SharedTxKey) {
		t.Fatal("shared tx id must stay out of the SQL session")
	}
}

func TestSharedTxDeadline(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	got := SharedTxDeadline(nil, now)
	if !got.Equal(now.Add(SharedTxDefaultLifetime)) {
		t.Fatalf("fallback: %s", got)
	}
	want := now.Add(5 * time.Second)
	got = SharedTxDeadline(map[string]any{SharedTxDeadlineKey: want}, now)
	if !got.Equal(want) {
		t.Fatalf("time: %s", got)
	}
	got = SharedTxDeadline(map[string]any{SharedTxDeadlineKey: want.Format(time.RFC3339Nano)}, now)
	if !got.Equal(want) {
		t.Fatalf("string: %s", got)
	}
}

func TestSharedTx_UseSeesSameHandle(t *testing.T) {
	reg := NewSharedTx[string](4, 0)
	t.Cleanup(reg.Close)
	id, err := reg.Put("conn-1", time.Now().Add(time.Minute), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 32 {
		t.Fatalf("id length: %d", len(id))
	}
	var seen string
	if err := reg.Use(id, func(handle string) error {
		seen = handle
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if seen != "conn-1" {
		t.Fatalf("handle: %q", seen)
	}
}

func TestSharedTx_CommitOnceThenMissing(t *testing.T) {
	reg := NewSharedTx[int](4, 0)
	t.Cleanup(reg.Close)
	id, err := reg.Put(1, time.Now().Add(time.Minute), func(int) {})
	if err != nil {
		t.Fatal(err)
	}
	commits := 0
	if err := reg.Commit(id, func(int) error {
		commits++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if commits != 1 {
		t.Fatalf("commits: %d", commits)
	}
	if err := reg.Use(id, func(int) error { return nil }); !errors.Is(err, ErrSharedTxNotFound) {
		t.Fatalf("use after commit: %v", err)
	}
	if err := reg.Commit(id, func(int) error { return nil }); !errors.Is(err, ErrSharedTxNotFound) {
		t.Fatalf("second commit: %v", err)
	}
	if err := reg.Rollback(id, func(int) error { return errors.New("should not run") }); err != nil {
		t.Fatalf("rollback after commit: %v", err)
	}
}

func TestSharedTx_RollbackDropsSession(t *testing.T) {
	reg := NewSharedTx[int](4, 0)
	t.Cleanup(reg.Close)
	rolled := 0
	id, err := reg.Put(1, time.Now().Add(time.Minute), func(int) { rolled++ })
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Rollback(id, func(int) error {
		rolled++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if rolled != 1 {
		t.Fatalf("rollback calls: %d", rolled)
	}
	if err := reg.Rollback(id, func(int) error { return errors.New("again") }); err != nil {
		t.Fatalf("second rollback: %v", err)
	}
	if err := reg.Commit(id, func(int) error { return nil }); !errors.Is(err, ErrSharedTxNotFound) {
		t.Fatalf("commit after rollback: %v", err)
	}
}

func TestSharedTx_OperationErrorAborts(t *testing.T) {
	reg := NewSharedTx[int](4, 0)
	t.Cleanup(reg.Close)
	id, err := reg.Put(1, time.Now().Add(time.Minute), func(int) {})
	if err != nil {
		t.Fatal(err)
	}
	opErr := errors.New("statement failed")
	if err := reg.Use(id, func(int) error { return opErr }); !errors.Is(err, opErr) {
		t.Fatalf("use: %v", err)
	}
	if err := reg.Use(id, func(int) error { return nil }); !errors.Is(err, ErrSharedTxAborted) {
		t.Fatalf("use after abort: %v", err)
	}
	if err := reg.Commit(id, func(int) error { return nil }); !errors.Is(err, ErrSharedTxAborted) {
		t.Fatalf("commit after abort: %v", err)
	}
	rolled := 0
	if err := reg.Rollback(id, func(int) error {
		rolled++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if rolled != 1 {
		t.Fatalf("rollback calls: %d", rolled)
	}
}

func TestSharedTx_Busy(t *testing.T) {
	reg := NewSharedTx[int](4, 0)
	t.Cleanup(reg.Close)
	id, err := reg.Put(1, time.Now().Add(time.Minute), func(int) {})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = reg.Use(id, func(int) error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	if err := reg.Use(id, func(int) error { return nil }); !errors.Is(err, ErrSharedTxBusy) {
		t.Fatalf("overlapping use: %v", err)
	}
	close(release)
	wg.Wait()
}

func TestSharedTx_Limit(t *testing.T) {
	reg := NewSharedTx[int](1, 0)
	t.Cleanup(reg.Close)
	if _, err := reg.Put(1, time.Now().Add(time.Minute), func(int) {}); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Put(2, time.Now().Add(time.Minute), func(int) {}); !errors.Is(err, ErrSharedTxLimit) {
		t.Fatalf("second put: %v", err)
	}
}

func TestSharedTx_ExpireRollsBack(t *testing.T) {
	reg := NewSharedTx[string](4, 0)
	t.Cleanup(reg.Close)
	rolled := 0
	id, err := reg.Put("h", time.Now().Add(-time.Second), func(string) { rolled++ })
	if err != nil {
		t.Fatal(err)
	}
	reg.expire(time.Now())
	if rolled != 1 {
		t.Fatalf("rollback calls: %d", rolled)
	}
	if err := reg.Use(id, func(string) error { return nil }); !errors.Is(err, ErrSharedTxNotFound) {
		t.Fatalf("use after expire: %v", err)
	}
}

func TestSharedTx_CloseRollsBackOpen(t *testing.T) {
	reg := NewSharedTx[int](4, 0)
	rolled := 0
	if _, err := reg.Put(1, time.Now().Add(time.Minute), func(int) { rolled++ }); err != nil {
		t.Fatal(err)
	}
	reg.Close()
	if rolled != 1 {
		t.Fatalf("rollback calls: %d", rolled)
	}
	reg.Close()
}
