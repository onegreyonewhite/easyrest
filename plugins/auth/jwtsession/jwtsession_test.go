package jwtsession

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestJWTSessionInit(t *testing.T) {
	plug := New()
	info, err := plug.Init(map[string]any{"jwt_secret": "secret"}, easyrest.HostRPC{})
	if err != nil {
		t.Fatal(err)
	}
	if info.Key != "session" || !info.IsCookie {
		t.Fatalf("key %q cookie %v", info.Key, info.IsCookie)
	}
	if info.Schema["type"] != "apiKey" || info.Schema["in"] != "cookie" || info.Schema["name"] != "session" {
		t.Fatalf("schema %#v", info.Schema)
	}
	if plug.secret != "secret" || plug.cookie != "session" {
		t.Fatalf("stored secret %q cookie %q", plug.secret, plug.cookie)
	}

	custom := New()
	info, err = custom.Init(map[string]any{"jwt_secret": "other", "cookie": "auth"}, easyrest.HostRPC{})
	if err != nil {
		t.Fatal(err)
	}
	if custom.cookie != "auth" || info.Key != "auth" || info.Schema["name"] != "auth" {
		t.Fatalf("custom %#v key %q schema %#v", custom, info.Key, info.Schema)
	}
}

func TestJWTSessionAuthenticate(t *testing.T) {
	claims := jwt.MapClaims{"sub": "ada", "exp": time.Now().Add(time.Hour).Unix()}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	plug := New()
	if _, err := plug.Init(map[string]any{"jwt_secret": "secret"}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	got, err := plug.Authenticate(map[string]string{"session": signed}, http.MethodGet, "/", "")
	if err != nil || got["sub"] != "ada" {
		t.Fatalf("claims %#v err %v", got, err)
	}

	got, err = plug.Authenticate(map[string]string{"session": "Bearer " + signed}, http.MethodGet, "/", "")
	if err != nil || got["sub"] != "ada" {
		t.Fatalf("bearer cookie %#v err %v", got, err)
	}

	if _, err := plug.Authenticate(map[string]string{"session": signed + "x"}, http.MethodGet, "/", ""); err == nil {
		t.Fatal("expected a bad signature to fail")
	}

	expired := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "ada",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	old, err := expired.SignedString([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plug.Authenticate(map[string]string{"session": old}, http.MethodGet, "/", ""); err == nil {
		t.Fatal("expected an expired token to fail")
	}
}
