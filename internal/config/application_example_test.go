package config

import "testing"

func TestApplicationExampleLoads(t *testing.T) {
	t.Chdir("../../examples/application")
	cfg, err := Load([]string{"config.yaml"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.RestAPI["v1"]; !ok {
		t.Fatal("missing v1")
	}
	login := cfg.RestAPI["v1"].Endpoints["login"]
	if login.URL != "/" {
		t.Fatalf("login url %q", login.URL)
	}
	if login.ListActions["login"].Func != "app.login" {
		t.Fatalf("login func %#v", login.ListActions["login"])
	}
	discovery := cfg.RestAPI["v1"].Endpoints["discovery"].StateActions["openid_configuration"]
	if discovery.URL != "openid-configuration" || discovery.Func != "app.openid_configuration" {
		t.Fatalf("discovery %#v", discovery)
	}
	labels := cfg.RestAPI["v1"].Endpoints["labels"].Actions["list"]
	if labels.Parsers == nil || len(*labels.Parsers) != 0 {
		t.Fatalf("labels parsers %#v", labels.Parsers)
	}
	if labels.Renderers == nil || len(*labels.Renderers) != 1 || (*labels.Renderers)[0] != "json" {
		t.Fatalf("labels renderers %#v", labels.Renderers)
	}
}
