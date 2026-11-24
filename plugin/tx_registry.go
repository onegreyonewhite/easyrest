package plugin

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	// SharedTxKey is the plugin context key for a shared transaction id.
	// The leading underscore keeps it out of SQL session variables.
	SharedTxKey = "_tx"

	sharedTxDefaultMax = 16

	// SharedTxDeadlineKey is the absolute expiry time for BeginTx.
	// The value is a time.Time or an RFC3339Nano string.
	SharedTxDeadlineKey = "_tx_deadline"

	// SharedTxDefaultLifetime is the session lifetime when BeginTx has no deadline.
	SharedTxDefaultLifetime = 30 * time.Second
)

var (
	// ErrSharedTxNotFound means the id is unknown, expired, or already finished.
	ErrSharedTxNotFound = errors.New("shared transaction not found")
	// ErrSharedTxDone means commit or rollback already finished the session.
	ErrSharedTxDone = errors.New("shared transaction finished")
	// ErrSharedTxAborted means a statement failed and commit is no longer possible.
	ErrSharedTxAborted = errors.New("shared transaction aborted")
	// ErrSharedTxBusy means another call is using the session.
	ErrSharedTxBusy = errors.New("shared transaction is in use")
	// ErrSharedTxUnsupported means this database plugin cannot hold a shared transaction.
	ErrSharedTxUnsupported = errors.New("shared transactions are not supported")
	// ErrSharedTxLimit means the plugin is already holding its maximum number of sessions.
	ErrSharedTxLimit = errors.New("shared transaction limit reached")
)

// SharedTxDeadline returns when a new shared transaction must end.
// A missing or unusable value is now plus SharedTxDefaultLifetime.
func SharedTxDeadline(ctx map[string]any, now time.Time) time.Time {
	fallback := now.Add(SharedTxDefaultLifetime)
	if ctx == nil {
		return fallback
	}
	switch v := ctx[SharedTxDeadlineKey].(type) {
	case time.Time:
		if !v.IsZero() {
			return v
		}
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, v)
		if err == nil && !parsed.IsZero() {
			return parsed
		}
	}
	return fallback
}

// SharedTxID returns the shared transaction id stored in ctx.
func SharedTxID(ctx map[string]any) (string, bool) {
	if ctx == nil {
		return "", false
	}
	id, ok := ctx[SharedTxKey].(string)
	if !ok || id == "" {
		return "", false
	}
	return id, true
}

type sharedSlot[T any] struct {
	handle   T
	rollback func(T)
	deadline time.Time
	aborted  bool
	busy     sync.Mutex
}

// SharedTx tracks driver transactions that outlive a single plugin call.
// T is the driver handle. The registry does not store a context.Context.
type SharedTx[T any] struct {
	mu        sync.Mutex
	items     map[string]*sharedSlot[T]
	max       int
	interval  time.Duration
	stop      chan struct{}
	stopped   chan struct{}
	closeOnce sync.Once
}

// NewSharedTx starts a reaper when interval is positive.
// A non-positive max uses the default cap of 16.
// Close stops the reaper and rolls back every open session.
func NewSharedTx[T any](max int, interval time.Duration) *SharedTx[T] {
	if max <= 0 {
		max = sharedTxDefaultMax
	}
	reg := &SharedTx[T]{
		items:    make(map[string]*sharedSlot[T]),
		max:      max,
		interval: interval,
		stop:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
	if interval > 0 {
		go reg.reap()
	} else {
		close(reg.stopped)
	}
	return reg
}

// Put stores handle until Commit, Rollback, expiry, or Close.
// rollback runs on expiry and Close. deadline is the absolute expiry time.
func (s *SharedTx[T]) Put(handle T, deadline time.Time, rollback func(T)) (string, error) {
	if rollback == nil {
		return "", fmt.Errorf("shared transaction rollback is nil")
	}
	id, err := newSharedTxID()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.items) >= s.max {
		return "", ErrSharedTxLimit
	}
	s.items[id] = &sharedSlot[T]{handle: handle, rollback: rollback, deadline: deadline}
	return id, nil
}

// Use runs fn on the handle. A non-nil error from fn aborts the session.
func (s *SharedTx[T]) Use(id string, fn func(T) error) error {
	slot, err := s.lockLive(id, time.Now())
	if err != nil {
		return err
	}
	defer slot.busy.Unlock()
	if err := fn(slot.handle); err != nil {
		s.mu.Lock()
		slot.aborted = true
		s.mu.Unlock()
		return err
	}
	return nil
}

// Commit runs fn and drops the session. After an aborted statement, fn is not called.
func (s *SharedTx[T]) Commit(id string, fn func(T) error) error {
	slot, err := s.lockLive(id, time.Now())
	if err != nil {
		return err
	}
	if err := fn(slot.handle); err != nil {
		s.mu.Lock()
		slot.aborted = true
		s.mu.Unlock()
		slot.busy.Unlock()
		return err
	}
	s.mu.Lock()
	delete(s.items, id)
	s.mu.Unlock()
	slot.busy.Unlock()
	return nil
}

// Rollback runs fn and drops the session.
// A missing id returns nil so a later rollback after commit is a no-op.
func (s *SharedTx[T]) Rollback(id string, fn func(T) error) error {
	s.mu.Lock()
	slot, ok := s.items[id]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	if !slot.busy.TryLock() {
		s.mu.Unlock()
		return ErrSharedTxBusy
	}
	delete(s.items, id)
	s.mu.Unlock()
	var err error
	if fn != nil {
		err = fn(slot.handle)
	}
	if err != nil {
		s.mu.Lock()
		if _, exists := s.items[id]; !exists {
			s.items[id] = slot
		}
		s.mu.Unlock()
	}
	slot.busy.Unlock()
	return err
}

// Close stops the reaper and rolls back every session still open.
// A second call is a no-op.
func (s *SharedTx[T]) Close() {
	s.closeOnce.Do(func() {
		close(s.stop)
	})
	<-s.stopped
	s.mu.Lock()
	slots := s.items
	s.items = make(map[string]*sharedSlot[T])
	s.mu.Unlock()
	for _, slot := range slots {
		slot.busy.Lock()
		if slot.rollback != nil {
			slot.rollback(slot.handle)
		}
		slot.busy.Unlock()
	}
}

func (s *SharedTx[T]) reap() {
	defer close(s.stopped)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case now := <-ticker.C:
			s.expire(now)
		}
	}
}

func (s *SharedTx[T]) expire(now time.Time) {
	s.mu.Lock()
	var due []*sharedSlot[T]
	for id, slot := range s.items {
		if slot.deadline.IsZero() || now.Before(slot.deadline) {
			continue
		}
		if !slot.busy.TryLock() {
			continue
		}
		delete(s.items, id)
		due = append(due, slot)
	}
	s.mu.Unlock()
	for _, slot := range due {
		if slot.rollback != nil {
			slot.rollback(slot.handle)
		}
		slot.busy.Unlock()
	}
}

// lockLive locks the busy mutex of a session that can still run work.
// An expired session is rolled back and reported as not found.
func (s *SharedTx[T]) lockLive(id string, now time.Time) (*sharedSlot[T], error) {
	s.mu.Lock()
	slot, ok := s.items[id]
	if !ok {
		s.mu.Unlock()
		return nil, ErrSharedTxNotFound
	}
	if !slot.deadline.IsZero() && !now.Before(slot.deadline) {
		if !slot.busy.TryLock() {
			s.mu.Unlock()
			return nil, ErrSharedTxBusy
		}
		delete(s.items, id)
		s.mu.Unlock()
		if slot.rollback != nil {
			slot.rollback(slot.handle)
		}
		slot.busy.Unlock()
		return nil, ErrSharedTxNotFound
	}
	if slot.aborted {
		s.mu.Unlock()
		return nil, ErrSharedTxAborted
	}
	if !slot.busy.TryLock() {
		s.mu.Unlock()
		return nil, ErrSharedTxBusy
	}
	s.mu.Unlock()
	return slot, nil
}

func newSharedTxID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("shared transaction id: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}
