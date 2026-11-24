package plugin

import (
	"context"
	"net"
	"net/rpc"
	"sync"
	"testing"
	"time"
)

type hostTxServer struct {
	mu        sync.Mutex
	id        string
	deadline  time.Time
	calls     []HostCall
	commits   int
	rollbacks int
}

func (s *hostTxServer) BeginTx(req HostTxRequest, resp *HostTxResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.id = "tx-1"
	s.deadline = req.Deadline
	resp.ID = s.id
	return nil
}

func (s *hostTxServer) CommitTx(req HostTxRequest, resp *HostTxResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.ID != s.id || req.DB != "orders" {
		resp.Error = ErrSharedTxNotFound.Error()
		return nil
	}
	s.commits++
	return nil
}

func (s *hostTxServer) RollbackTx(req HostTxRequest, resp *HostTxResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.ID != s.id {
		resp.Error = ErrSharedTxNotFound.Error()
		return nil
	}
	s.rollbacks++
	return nil
}

func (s *hostTxServer) TableGet(req HostCall, resp *HostResult) error {
	s.mu.Lock()
	s.calls = append(s.calls, req)
	s.mu.Unlock()
	resp.Status = 200
	return nil
}

func (s *hostTxServer) TableCreate(req HostCall, resp *HostResult) error {
	s.mu.Lock()
	s.calls = append(s.calls, req)
	s.mu.Unlock()
	resp.Status = 201
	return nil
}

func (s *hostTxServer) TableUpdate(HostCall, *HostResult) error  { return nil }
func (s *hostTxServer) TableDelete(HostCall, *HostResult) error  { return nil }
func (s *hostTxServer) CallFunction(HostCall, *HostResult) error { return nil }

func dialInternal(t *testing.T, svc any) *Host {
	t.Helper()
	srv := rpc.NewServer()
	if err := srv.RegisterName("Internal", svc); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Accept(ln)
	client, err := rpc.Dial("tcp", ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.Close()
		ln.Close()
	})
	return &Host{client: client}
}

func TestHostSession_StampsOneID(t *testing.T) {
	srv := &hostTxServer{}
	host := dialInternal(t, srv)
	deadline := time.Now().Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	session, err := host.BeginSession(ctx, "orders")
	if err != nil {
		t.Fatal(err)
	}
	if session.ID() != "tx-1" {
		t.Fatalf("id: %s", session.ID())
	}
	if srv.deadline.IsZero() || srv.deadline.Sub(deadline) > time.Second || deadline.Sub(srv.deadline) > time.Second {
		t.Fatalf("deadline: got %s want %s", srv.deadline, deadline)
	}
	if _, err := session.TableGet(HostCall{Name: "invoices"}); err != nil {
		t.Fatal(err)
	}
	if _, err := session.TableCreate(HostCall{DB: "orders", Name: "stock"}); err != nil {
		t.Fatal(err)
	}
	if _, err := session.TableGet(HostCall{DB: "audit"}); err == nil {
		t.Fatal("expected database mismatch")
	}
	if err := session.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := session.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback after commit: %v", err)
	}
	if err := session.Commit(context.Background()); err != ErrSharedTxDone {
		t.Fatalf("second commit: %v", err)
	}
	if srv.commits != 1 || srv.rollbacks != 0 {
		t.Fatalf("commits=%d rollbacks=%d", srv.commits, srv.rollbacks)
	}
	if len(srv.calls) != 2 || srv.calls[0].TxID != "tx-1" || srv.calls[1].TxID != "tx-1" {
		t.Fatalf("calls: %#v", srv.calls)
	}
	if srv.calls[0].DB != "orders" {
		t.Fatalf("default db: %s", srv.calls[0].DB)
	}
}
