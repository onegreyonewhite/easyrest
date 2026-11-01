package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestRestSchedulerClaimSkipsTenantFilter(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"id": "g1", "tenant_id": "other"}}}
	cfg := config.Config{
		AnonClaims: map[string]any{"sub": "scheduler", "scheduler": true},
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"groups": {
						Table: "project_groups",
						Filters: map[string]config.RestFilter{
							"tenant_id": {Op: "eq", Claim: "tenant_id"},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	list := httptest.NewRecorder()
	router.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/restapi/v1/groups/", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("list %d %s", list.Code, list.Body.String())
	}
	if _, ok := plugin.getWhere["tenant_id"]; ok {
		t.Fatalf("tenant filter applied: %#v", plugin.getWhere)
	}
}

func TestRestClaimFilter_CreateArray(t *testing.T) {
	plugin := &restRecPlugin{}
	cfg := config.Config{
		AnonClaims: map[string]any{"sub": "ada", "tenant_id": "default"},
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"groups": {
						Table: "project_groups",
						Filters: map[string]config.RestFilter{
							"tenant_id": {Op: "eq", Claim: "tenant_id"},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	ok := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/restapi/v1/groups/", strings.NewReader(`[{"id":"g1","name":"home"},{"id":"g2","name":"away"}]`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(ok, req)
	if ok.Code != http.StatusCreated || plugin.creates != 1 || len(plugin.createData) != 2 {
		t.Fatalf("stamped %d creates %d %#v", ok.Code, plugin.creates, plugin.createData)
	}
	if plugin.createData[0]["tenant_id"] != "default" || plugin.createData[1]["tenant_id"] != "default" {
		t.Fatalf("claims %#v", plugin.createData)
	}

	plugin.creates = 0
	plugin.createData = nil
	conflict := httptest.NewRecorder()
	bad := httptest.NewRequest(http.MethodPost, "/restapi/v1/groups/", strings.NewReader(`[{"id":"g3","name":"home"},{"id":"g4","name":"away","tenant_id":"other"}]`))
	bad.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(conflict, bad)
	if conflict.Code != http.StatusForbidden || !strings.Contains(conflict.Body.String(), "row 1: Forbidden") {
		t.Fatalf("conflict %d %s", conflict.Code, conflict.Body.String())
	}
	if plugin.creates != 0 {
		t.Fatalf("creates %d", plugin.creates)
	}
}

func TestRestClaimFilter(t *testing.T) {
	plugin := &restRecPlugin{rows: []map[string]any{{"id": "g1", "tenant_id": "default"}}}
	cfg := config.Config{
		AnonClaims: map[string]any{"sub": "ada", "tenant_id": "default"},
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"groups": {
						Table: "project_groups",
						Filters: map[string]config.RestFilter{
							"tenant_id": {Op: "eq", Claim: "tenant_id"},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	list := httptest.NewRecorder()
	router.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/restapi/v1/groups/?tenant_id=other", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("list %d %s", list.Code, list.Body.String())
	}
	got, _ := plugin.getWhere["tenant_id"].(map[string]any)
	if got["="] != "default" {
		t.Fatalf("where %#v", plugin.getWhere)
	}

	create := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/restapi/v1/groups/", strings.NewReader(`{"id":"g1","name":"home","tenant_id":"other"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(create, req)
	if create.Code != http.StatusForbidden {
		t.Fatalf("create %d %s", create.Code, create.Body.String())
	}

	okCreate := httptest.NewRecorder()
	okReq := httptest.NewRequest(http.MethodPost, "/restapi/v1/groups/", strings.NewReader(`{"id":"g1","name":"home"}`))
	okReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(okCreate, okReq)
	if okCreate.Code != http.StatusCreated || plugin.createData[0]["tenant_id"] != "default" {
		t.Fatalf("stamped %d %#v", okCreate.Code, plugin.createData)
	}

	one := httptest.NewRecorder()
	router.ServeHTTP(one, httptest.NewRequest(http.MethodGet, "/restapi/v1/groups/g1/", nil))
	if one.Code != http.StatusOK {
		t.Fatalf("retrieve %d %s", one.Code, one.Body.String())
	}
	got, _ = plugin.getWhere["tenant_id"].(map[string]any)
	id, _ := plugin.getWhere["id"].(map[string]any)
	if got["="] != "default" || id["="] != "g1" {
		t.Fatalf("retrieve where %#v", plugin.getWhere)
	}

	patch := httptest.NewRecorder()
	patchReq := httptest.NewRequest(http.MethodPatch, "/restapi/v1/groups/g1/", strings.NewReader(`{"name":"home"}`))
	patchReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(patch, patchReq)
	if patch.Code != http.StatusOK {
		t.Fatalf("patch %d %s", patch.Code, patch.Body.String())
	}
	got, _ = plugin.updateWhere["tenant_id"].(map[string]any)
	if got["="] != "default" {
		t.Fatalf("update where %#v", plugin.updateWhere)
	}

	del := httptest.NewRecorder()
	router.ServeHTTP(del, httptest.NewRequest(http.MethodDelete, "/restapi/v1/groups/g1/", nil))
	if del.Code != http.StatusNoContent {
		t.Fatalf("delete %d %s", del.Code, del.Body.String())
	}
	got, _ = plugin.deleteWhere["tenant_id"].(map[string]any)
	if got["="] != "default" {
		t.Fatalf("delete where %#v", plugin.deleteWhere)
	}

	settings := &restRecPlugin{rows: []map[string]any{{"tenant_id": "default"}}}
	cfg.RestAPI["v1"].Endpoints["settings"] = config.RestEndpoint{
		Table:      "tenant_settings",
		PrimaryKey: "tenant_id",
		Filters: map[string]config.RestFilter{
			"tenant_id": {Op: "eq", Claim: "tenant_id"},
		},
	}
	router = serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": settings})
	other := httptest.NewRecorder()
	router.ServeHTTP(other, httptest.NewRequest(http.MethodGet, "/restapi/v1/settings/other/", nil))
	if other.Code != http.StatusNotFound || settings.getCalls != 0 {
		t.Fatalf("other settings %d calls %d", other.Code, settings.getCalls)
	}

	bare := config.Config{
		AnonClaims: map[string]any{"sub": "ada"},
		RestAPI:    cfg.RestAPI,
	}
	open := serveRest(t, bare, map[string]easyrest.DBPlugin{"db": plugin})
	missing := httptest.NewRecorder()
	open.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/restapi/v1/groups/", nil))
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("missing %d %s", missing.Code, missing.Body.String())
	}
}
