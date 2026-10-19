package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	jwtplugin "github.com/onegreyonewhite/easyrest/plugins/auth/jwt"
	cachepkg "github.com/patrickmn/go-cache"
)

type cookieCountPlugin struct {
	calls int
}

func (p *cookieCountPlugin) Init(map[string]any, easyrest.HostRPC) (easyrest.AuthInfo, error) {
	return easyrest.AuthInfo{
		PluginMeta: easyrest.EmptyPluginMeta(),
		Schema:     map[string]any{"type": "apiKey", "in": "cookie", "name": "sid"},
		Key:        "sid",
		IsCookie:   true,
	}, nil
}

func (p *cookieCountPlugin) Authenticate(headers map[string]string, _, _, _ string) (map[string]any, error) {
	p.calls++
	value := headers["sid"]
	if value == "" {
		return nil, errors.New("missing sid")
	}
	return map[string]any{"sub": value}, nil
}

func useAuthCache(t *testing.T) {
	t.Helper()
	origCfg := GetConfig()
	origPlugins := AuthPlugins.Load()
	origOrder := authPluginOrder.Load()
	origCreds := authCredentials.Load()
	origCache := claimsCache
	t.Cleanup(func() {
		SetConfig(origCfg)
		AuthPlugins.Store(origPlugins)
		authPluginOrder.Store(origOrder)
		authCredentials.Store(origCreds)
		claimsCache = origCache
	})
	SetConfig(config.Config{TokenUserSearch: "sub", AnonClaims: map[string]any{}})
	claimsCache = cachepkg.New(time.Minute, time.Minute)
}

func TestAuthenticate_CookieSource(t *testing.T) {
	useAuthCache(t)
	plug := &cookieCountPlugin{}
	plugins := map[string]easyrest.AuthPlugin{"sid": plug}
	AuthPlugins.Store(&plugins)
	setAuthPluginOrder(plugins)
	creds := map[string]authCredential{"sid": {Key: "sid", IsCookie: true}}
	authCredentials.Store(&creds)

	first := httptest.NewRequest(http.MethodGet, "/api/db/users/", nil)
	first.AddCookie(&http.Cookie{Name: "sid", Value: "abc"})
	user, _, err := Authenticate(first)
	if err != nil || user != "abc" || plug.calls != 1 {
		t.Fatalf("first user %q calls %d err %v", user, plug.calls, err)
	}

	second := httptest.NewRequest(http.MethodGet, "/api/db/users/", nil)
	second.AddCookie(&http.Cookie{Name: "sid", Value: "abc"})
	user, _, err = Authenticate(second)
	if err != nil || user != "abc" || plug.calls != 1 {
		t.Fatalf("cached user %q calls %d err %v", user, plug.calls, err)
	}

	other := httptest.NewRequest(http.MethodGet, "/api/db/users/", nil)
	other.AddCookie(&http.Cookie{Name: "sid", Value: "xyz"})
	user, _, err = Authenticate(other)
	if err != nil || user != "xyz" || plug.calls != 2 {
		t.Fatalf("miss user %q calls %d err %v", user, plug.calls, err)
	}
}

func TestAuthenticate_AuthorizationCache(t *testing.T) {
	useAuthCache(t)
	jwtPlug := &jwtplugin.JWTAuthPlugin{}
	if _, err := jwtPlug.Init(map[string]any{"jwt_secret": "secret"}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	counter := &countingAuth{inner: jwtPlug}
	plugins := map[string]easyrest.AuthPlugin{"jwt": counter}
	AuthPlugins.Store(&plugins)
	setAuthPluginOrder(plugins)
	creds := map[string]authCredential{"jwt": {Key: "Authorization"}}
	authCredentials.Store(&creds)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "ada"})
	signed, err := token.SignedString([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	first := httptest.NewRequest(http.MethodGet, "/api/db/users/", nil)
	first.Header.Set("Authorization", "Bearer "+signed)
	user, _, err := Authenticate(first)
	if err != nil || user != "ada" || counter.calls != 1 {
		t.Fatalf("first user %q calls %d err %v", user, counter.calls, err)
	}

	second := httptest.NewRequest(http.MethodGet, "/api/db/users/", nil)
	second.Header.Set("Authorization", "Bearer "+signed)
	user, _, err = Authenticate(second)
	if err != nil || user != "ada" || counter.calls != 1 {
		t.Fatalf("cached user %q calls %d err %v", user, counter.calls, err)
	}
}

type countingAuth struct {
	inner easyrest.AuthPlugin
	calls int
}

func (c *countingAuth) Init(settings map[string]any, host easyrest.HostRPC) (easyrest.AuthInfo, error) {
	return c.inner.Init(settings, host)
}

func (c *countingAuth) Authenticate(headers map[string]string, method, path, query string) (map[string]any, error) {
	c.calls++
	return c.inner.Authenticate(headers, method, path, query)
}
