package server

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/rpc"
	"path/filepath"
	"reflect"
	"testing"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	dbsession "github.com/onegreyonewhite/easyrest/plugins/auth/dbsession"
	jwtsession "github.com/onegreyonewhite/easyrest/plugins/auth/jwtsession"
)

func TestAuthPluginTrialOrder(t *testing.T) {
	plugins := map[string]easyrest.AuthPlugin{}
	for _, name := range []string{"zeta", "dbsession", "jwtsession", "jwt", "basic", "apikey", "oidc", "awssigv4"} {
		plugins[name] = &cookieCountPlugin{}
	}
	got := authPluginTrialOrder(plugins)
	want := []string{"jwt", "jwtsession", "basic", "apikey", "dbsession", "oidc", "awssigv4", "zeta"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v", got)
	}
}

type sessionHost struct {
	rows []map[string]any
}

func (s *sessionHost) TableGet(_ easyrest.HostCall, resp *easyrest.HostResult) error {
	raw, err := json.Marshal(s.rows)
	if err != nil {
		return err
	}
	resp.Status = http.StatusOK
	resp.Body = raw
	return nil
}

func startSessionHost(t *testing.T, rows []map[string]any) easyrest.HostRPC {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "session.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := rpc.NewServer()
	if err := srv.RegisterName("Internal", &sessionHost{rows: rows}); err != nil {
		t.Fatal(err)
	}
	go srv.Accept(lis)
	t.Cleanup(func() { lis.Close() })
	return easyrest.HostRPC{Network: "unix", Address: sock}
}

type namedAuth struct {
	name  string
	inner easyrest.AuthPlugin
	calls *[]string
}

func (n *namedAuth) Init(settings map[string]any, host easyrest.HostRPC) (easyrest.AuthInfo, error) {
	return n.inner.Init(settings, host)
}

func (n *namedAuth) Authenticate(headers map[string]string, method, path, query string) (map[string]any, error) {
	*n.calls = append(*n.calls, n.name)
	return n.inner.Authenticate(headers, method, path, query)
}

func TestAuthenticate_DBSession(t *testing.T) {
	useAuthCache(t)
	claimsCache = nil
	host := startSessionHost(t, []map[string]any{{
		"claims": map[string]any{"sub": "ada"},
		"exp":    "2999-01-02T03:04:05Z",
	}})
	dbPlug := dbsession.New()
	dbInfo, err := dbPlug.Init(map[string]any{"plugin": "app", "table": "sessions"}, host)
	if err != nil {
		t.Fatal(err)
	}
	jwtPlug := jwtsession.New()
	jwtInfo, err := jwtPlug.Init(map[string]any{"jwt_secret": "secret"}, easyrest.HostRPC{})
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	plugins := map[string]easyrest.AuthPlugin{
		"jwtsession": &namedAuth{name: "jwtsession", inner: jwtPlug, calls: &calls},
		"dbsession":  &namedAuth{name: "dbsession", inner: dbPlug, calls: &calls},
	}
	AuthPlugins.Store(&plugins)
	setAuthPluginOrder(plugins)
	creds := map[string]authCredential{
		"jwtsession": credentialFrom(jwtInfo),
		"dbsession":  credentialFrom(dbInfo),
	}
	authCredentials.Store(&creds)

	req := httptest.NewRequest(http.MethodGet, "/api/app/sessions/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "sess-1"})
	user, _, err := Authenticate(req)
	if err != nil || user != "ada" {
		t.Fatalf("user %q err %v", user, err)
	}
	if !reflect.DeepEqual(calls, []string{"jwtsession", "dbsession"}) {
		t.Fatalf("calls %v", calls)
	}
}
