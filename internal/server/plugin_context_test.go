package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildPluginContextPublicURL(t *testing.T) {
	plain := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	request := pluginRequest(t, buildPluginContext(plain, "", "", ""))
	if request["scheme"] != "http" || request["host"] != "example.com" || request["prefix"] != "" {
		t.Fatalf("request %#v", request)
	}

	proxied := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	proxied.Header.Set("X-Forwarded-Proto", "https")
	proxied.Header.Set("X-Forwarded-Host", "example.com:8433")
	request = pluginRequest(t, buildPluginContext(proxied, "", "", ""))
	if request["scheme"] != "https" || request["host"] != "example.com:8433" {
		t.Fatalf("request %#v", request)
	}

	fromHeader, err := http.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	if err != nil {
		t.Fatal(err)
	}
	fromHeader.Host = "request-host.example"
	fromHeader.Header["Host"] = []string{"header-host.example"}
	request = pluginRequest(t, buildPluginContext(fromHeader, "", "", ""))
	if request["scheme"] != "http" || request["host"] != "header-host.example" {
		t.Fatalf("request %#v", request)
	}

	fromRequest, err := http.NewRequest(http.MethodGet, "https://from-url.example/restapi/v1/users/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request = pluginRequest(t, buildPluginContext(fromRequest, "", "", ""))
	if request["scheme"] != "https" || request["host"] != "from-url.example" {
		t.Fatalf("request %#v", request)
	}

	forwarded := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	forwarded.Header.Set("Forwarded", "for=203.0.113.10;proto=https;host=example.com:8433")
	request = pluginRequest(t, buildPluginContext(forwarded, "", "", ""))
	if request["scheme"] != "https" || request["host"] != "example.com:8433" {
		t.Fatalf("request %#v", request)
	}

	both := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	both.Header.Set("Forwarded", "proto=http;host=other.example")
	both.Header.Set("X-Forwarded-Proto", "https, http")
	both.Header.Set("X-Forwarded-Host", "example.com:8433, other.example")
	request = pluginRequest(t, buildPluginContext(both, "", "", ""))
	if request["scheme"] != "https" || request["host"] != "example.com:8433" {
		t.Fatalf("request %#v", request)
	}

	identity := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	identity.Header.Set("X-Forwarded-Prefix", "/someapp/")
	identity.Header.Set("X-Forwarded-For", "203.0.113.10")
	identity.Header.Set("X-Real-IP", "203.0.113.10")
	identity.Header.Set("Via", "1.1 proxy")
	ctx := buildPluginContext(identity, "", "", "")
	request = pluginRequest(t, ctx)
	if request["prefix"] != "/someapp" || request["scheme"] != "http" || request["host"] != "example.com" {
		t.Fatalf("request %#v", request)
	}
	if request["forwarded_for"] != "203.0.113.10" || request["real_ip"] != "203.0.113.10" || request["via"] != "1.1 proxy" {
		t.Fatalf("request %#v", request)
	}
	headers, _ := ctx["headers"].(map[string]any)
	if headers["x-forwarded-prefix"] != "/someapp/" || headers["x-forwarded-for"] != "203.0.113.10" || headers["x-real-ip"] != "203.0.113.10" || headers["via"] != "1.1 proxy" {
		t.Fatalf("headers %#v", headers)
	}
}

func pluginRequest(t *testing.T, ctx map[string]any) map[string]any {
	t.Helper()
	request, ok := ctx["request"].(map[string]any)
	if !ok {
		t.Fatalf("request %#v", ctx["request"])
	}
	return request
}
