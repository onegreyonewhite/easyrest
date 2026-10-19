package tests

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/config"
	"github.com/onegreyonewhite/easyrest/internal/server"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	jwtplugin "github.com/onegreyonewhite/easyrest/plugins/auth/jwt"
	sqlitePlugin "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
	ratelimit "github.com/onegreyonewhite/easyrest/plugins/middleware/ratelimit"
	_ "modernc.org/sqlite"
)

func setupRatelimitIntegration(t *testing.T, settings map[string]any) (http.Handler, func()) {
	t.Helper()

	origPreserved := server.PreservedMiddlewarePlugins["ratelimit"]
	server.PreservedMiddlewarePlugins["ratelimit"] = func() easyrest.MiddlewarePlugin {
		return ratelimit.New()
	}
	server.PreservedAuthPlugins["jwt"] = func() easyrest.AuthPlugin {
		return &jwtplugin.JWTAuthPlugin{}
	}
	server.PreservedDbPlugins["sqlite"] = func() easyrest.DBPlugin {
		return sqlitePlugin.NewSqlitePlugin()
	}

	dbPath := setupTestDB(t)
	applyTestConfig(t, testSQLiteYAML("sqlite://"+dbPath, false, ""))
	cfg := server.GetConfig()
	cfg.MiddlewarePlugins = map[string]config.MiddlewareConfig{
		"ratelimit": {Settings: settings},
	}
	cfg.GlobalRequestMiddlewares = []string{"ratelimit"}
	server.SetConfig(cfg)

	router := server.SetupRouter()
	insertUser(t, dbPath, "Alice", "")

	cleanup := func() {
		server.StopPlugins()
		os.Remove(dbPath)
		if origPreserved != nil {
			server.PreservedMiddlewarePlugins["ratelimit"] = origPreserved
		} else {
			delete(server.PreservedMiddlewarePlugins, "ratelimit")
		}
	}
	return router, cleanup
}

func doUsersGET(t *testing.T, router http.Handler, token string, remoteAddr, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	req, err := http.NewRequest("GET", "/api/test/users/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func TestMiddlewareRatelimitGlobal(t *testing.T) {
	router, cleanup := setupRatelimitIntegration(t, map[string]any{
		"limit":  2,
		"period": "1m",
		"key":    "global",
	})
	defer cleanup()

	token := generateToken(t)
	if rr := doUsersGET(t, router, token, "", ""); rr.Code != http.StatusOK {
		t.Fatalf("first: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr := doUsersGET(t, router, token, "", ""); rr.Code != http.StatusOK {
		t.Fatalf("second: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	rr := doUsersGET(t, router, token, "", "")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("third: expected 429, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "rate limit exceeded" {
		t.Fatalf("unexpected body: %q", rr.Body.String())
	}
	if rr.Header().Get("X-RateLimit-Limit") != "2" {
		t.Fatalf("X-RateLimit-Limit: %q", rr.Header().Get("X-RateLimit-Limit"))
	}
	if rr.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Fatalf("X-RateLimit-Remaining: %q", rr.Header().Get("X-RateLimit-Remaining"))
	}
	retryAfter, err := strconv.Atoi(rr.Header().Get("Retry-After"))
	if err != nil || retryAfter < 1 {
		t.Fatalf("Retry-After: %q", rr.Header().Get("Retry-After"))
	}
}

func TestMiddlewareRatelimitIP(t *testing.T) {
	router, cleanup := setupRatelimitIntegration(t, map[string]any{
		"limit":  1,
		"period": "1m",
		"key":    "ip",
	})
	defer cleanup()

	token := generateToken(t)
	if rr := doUsersGET(t, router, token, "203.0.113.10:1000", ""); rr.Code != http.StatusOK {
		t.Fatalf("ip A first: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr := doUsersGET(t, router, token, "203.0.113.10:1001", ""); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("ip A second: expected 429, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr := doUsersGET(t, router, token, "198.51.100.20:2000", ""); rr.Code != http.StatusOK {
		t.Fatalf("ip B: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMiddlewareRatelimitCookie(t *testing.T) {
	router, cleanup := setupRatelimitIntegration(t, map[string]any{
		"limit":  1,
		"period": "1m",
		"key":    "cookie",
		"cookie": "sid",
	})
	defer cleanup()

	token := generateToken(t)
	if rr := doUsersGET(t, router, token, "", "sid=alpha"); rr.Code != http.StatusOK {
		t.Fatalf("cookie alpha first: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr := doUsersGET(t, router, token, "", "sid=alpha"); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("cookie alpha second: expected 429, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr := doUsersGET(t, router, token, "", "sid=beta"); rr.Code != http.StatusOK {
		t.Fatalf("cookie beta: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMiddlewareRatelimitCookieAssignsWhenMissing(t *testing.T) {
	router, cleanup := setupRatelimitIntegration(t, map[string]any{
		"limit":  1,
		"period": "1m",
		"key":    "cookie",
		"cookie": "sid",
	})
	defer cleanup()

	token := generateToken(t)
	first := doUsersGET(t, router, token, "203.0.113.1:1", "")
	if first.Code != http.StatusOK {
		t.Fatalf("no cookie first: expected 200, got %d body=%s", first.Code, first.Body.String())
	}
	setCookie := first.Header().Get("Set-Cookie")
	if setCookie == "" || !strings.Contains(setCookie, "sid=") {
		t.Fatalf("expected Set-Cookie sid, got %q", setCookie)
	}
	sid := cookieValueFromSetCookie(t, setCookie, "sid")

	second := doUsersGET(t, router, token, "203.0.113.1:1", "sid="+sid)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("replay cookie: expected 429, got %d body=%s", second.Code, second.Body.String())
	}

	other := doUsersGET(t, router, token, "203.0.113.2:2", "")
	if other.Code != http.StatusOK {
		t.Fatalf("other client no cookie: expected 200, got %d body=%s", other.Code, other.Body.String())
	}
	otherSid := cookieValueFromSetCookie(t, other.Header().Get("Set-Cookie"), "sid")
	if otherSid == "" || otherSid == sid {
		t.Fatalf("expected a different assigned cookie, got %q vs %q", otherSid, sid)
	}
}

func cookieValueFromSetCookie(t *testing.T, raw, name string) string {
	t.Helper()
	resp := &http.Response{Header: http.Header{"Set-Cookie": {raw}}}
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	t.Fatalf("cookie %q not found in %q", name, raw)
	return ""
}
