package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestRestAPI_CreateFieldType(t *testing.T) {
	plugin := &restRecPlugin{
		schema: map[string]any{
			"tables": map[string]any{
				"users": map[string]any{
					"properties": map[string]any{
						"age": map[string]any{"type": "integer"},
					},
				},
			},
		},
	}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Actions: map[string]config.RestAction{
							"create": {},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	bad := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"age":"x"}`))
	bad.Header.Set("Content-Type", "application/json")
	badW := httptest.NewRecorder()
	router.ServeHTTP(badW, bad)
	if badW.Code != http.StatusBadRequest || !strings.Contains(badW.Body.String(), "invalid field age") {
		t.Fatalf("status %d body %q", badW.Code, badW.Body.String())
	}
	if plugin.creates != 0 {
		t.Fatalf("creates %d", plugin.creates)
	}

	ok := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"age":20}`))
	ok.Header.Set("Content-Type", "application/json")
	okW := httptest.NewRecorder()
	router.ServeHTTP(okW, ok)
	if okW.Code != http.StatusCreated {
		t.Fatalf("status %d body %q", okW.Code, okW.Body.String())
	}
	if len(plugin.createData) != 1 || plugin.createData[0]["age"] != float64(20) {
		t.Fatalf("row %#v", plugin.createData)
	}
}

func TestRestAPI_ExtraFieldOverridesColumnType(t *testing.T) {
	plugin := &restRecPlugin{
		schema: map[string]any{
			"tables": map[string]any{
				"users": map[string]any{
					"properties": map[string]any{
						"age": map[string]any{"type": "string"},
					},
				},
			},
		},
	}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Actions: map[string]config.RestAction{
							"create": {
								ExtraFields: map[string]any{
									"age": map[string]any{"type": "integer"},
								},
							},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	bad := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"age":"x"}`))
	bad.Header.Set("Content-Type", "application/json")
	badW := httptest.NewRecorder()
	router.ServeHTTP(badW, bad)
	if badW.Code != http.StatusBadRequest || !strings.Contains(badW.Body.String(), "invalid field age") {
		t.Fatalf("status %d body %q", badW.Code, badW.Body.String())
	}

	ok := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"age":20}`))
	ok.Header.Set("Content-Type", "application/json")
	okW := httptest.NewRecorder()
	router.ServeHTTP(okW, ok)
	if okW.Code != http.StatusCreated {
		t.Fatalf("status %d body %q", okW.Code, okW.Body.String())
	}
}

func TestRestAPI_CreateRequired(t *testing.T) {
	plugin := &restRecPlugin{
		schema: map[string]any{
			"tables": map[string]any{
				"users": map[string]any{
					"properties": map[string]any{
						"title":  map[string]any{"type": "string"},
						"org_id": map[string]any{"type": "string"},
						"owner":  map[string]any{"type": "string"},
						"note":   map[string]any{"type": "string"},
					},
					"required": []string{"title", "org_id", "owner", "note"},
				},
			},
		},
	}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						URL: "orgs/{org_id}/users",
						Filters: map[string]config.RestFilter{
							"owner": {Field: "owner", Claim: "sub"},
						},
						Actions: map[string]config.RestAction{
							"create": {
								ExtraFields: map[string]any{
									"note": map[string]any{"type": "string", "readOnly": true},
								},
							},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	missing := httptest.NewRequest(http.MethodPost, "/restapi/v1/orgs/7/users/", strings.NewReader(`{}`))
	missing.Header.Set("Content-Type", "application/json")
	missingW := httptest.NewRecorder()
	router.ServeHTTP(missingW, missing)
	if missingW.Code != http.StatusBadRequest || !strings.Contains(missingW.Body.String(), "missing field title") {
		t.Fatalf("status %d body %q", missingW.Code, missingW.Body.String())
	}
	if plugin.creates != 0 {
		t.Fatalf("creates %d", plugin.creates)
	}

	ok := httptest.NewRequest(http.MethodPost, "/restapi/v1/orgs/7/users/", strings.NewReader(`{"title":"a"}`))
	ok.Header.Set("Content-Type", "application/json")
	okW := httptest.NewRecorder()
	router.ServeHTTP(okW, ok)
	if okW.Code != http.StatusCreated {
		t.Fatalf("status %d body %q", okW.Code, okW.Body.String())
	}
	row := plugin.createData[0]
	if row["title"] != "a" || row["org_id"] != "7" || row["owner"] != "tester" {
		t.Fatalf("row %#v", row)
	}
	if _, exists := row["note"]; exists {
		t.Fatalf("readOnly note %#v", row)
	}
}

func TestRestAPI_CreateArrayRequired(t *testing.T) {
	plugin := &restRecPlugin{
		schema: map[string]any{
			"tables": map[string]any{
				"users": map[string]any{
					"properties": map[string]any{
						"title":  map[string]any{"type": "string"},
						"org_id": map[string]any{"type": "string"},
						"owner":  map[string]any{"type": "string"},
						"note":   map[string]any{"type": "string"},
					},
					"required": []string{"title", "org_id", "owner", "note"},
				},
			},
		},
	}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						URL: "orgs/{org_id}/users",
						Filters: map[string]config.RestFilter{
							"owner": {Field: "owner", Claim: "sub"},
						},
						Actions: map[string]config.RestAction{
							"create": {
								ExtraFields: map[string]any{
									"note": map[string]any{"type": "string", "readOnly": true},
								},
							},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	one := httptest.NewRequest(http.MethodPost, "/restapi/v1/orgs/7/users/", strings.NewReader(`[{}]`))
	one.Header.Set("Content-Type", "application/json")
	oneW := httptest.NewRecorder()
	router.ServeHTTP(oneW, one)
	if oneW.Code != http.StatusBadRequest || !strings.Contains(oneW.Body.String(), "missing field title") || strings.Contains(oneW.Body.String(), "row ") {
		t.Fatalf("status %d body %q", oneW.Code, oneW.Body.String())
	}

	missing := httptest.NewRequest(http.MethodPost, "/restapi/v1/orgs/7/users/", strings.NewReader(`[{"title":"a"},{}]`))
	missing.Header.Set("Content-Type", "application/json")
	missingW := httptest.NewRecorder()
	router.ServeHTTP(missingW, missing)
	if missingW.Code != http.StatusBadRequest || !strings.Contains(missingW.Body.String(), "row 1: missing field title") {
		t.Fatalf("status %d body %q", missingW.Code, missingW.Body.String())
	}
	if plugin.creates != 0 {
		t.Fatalf("creates %d", plugin.creates)
	}

	ok := httptest.NewRequest(http.MethodPost, "/restapi/v1/orgs/7/users/", strings.NewReader(`[{"title":"a","note":"x"},{"title":"b"}]`))
	ok.Header.Set("Content-Type", "application/json")
	okW := httptest.NewRecorder()
	router.ServeHTTP(okW, ok)
	if okW.Code != http.StatusCreated {
		t.Fatalf("status %d body %q", okW.Code, okW.Body.String())
	}
	if plugin.creates != 1 || len(plugin.createData) != 2 {
		t.Fatalf("creates %d data %#v", plugin.creates, plugin.createData)
	}
	for i, title := range []string{"a", "b"} {
		row := plugin.createData[i]
		if row["title"] != title || row["org_id"] != "7" || row["owner"] != "tester" {
			t.Fatalf("row %d %#v", i, row)
		}
		if _, exists := row["note"]; exists {
			t.Fatalf("readOnly note %#v", row)
		}
	}
}

func TestRestAPI_PatchFieldType(t *testing.T) {
	plugin := &restRecPlugin{
		updated: 1,
		schema: map[string]any{
			"tables": map[string]any{
				"users": map[string]any{
					"properties": map[string]any{
						"title": map[string]any{"type": "string"},
						"name":  map[string]any{"type": "string"},
						"age":   map[string]any{"type": "integer"},
					},
					"required": []string{"title"},
				},
			},
		},
	}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Actions: map[string]config.RestAction{
							"update": {},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	partial := httptest.NewRequest(http.MethodPatch, "/restapi/v1/users/1/", strings.NewReader(`{"name":"a"}`))
	partial.Header.Set("Content-Type", "application/json")
	partialW := httptest.NewRecorder()
	router.ServeHTTP(partialW, partial)
	if partialW.Code != http.StatusOK {
		t.Fatalf("partial status %d body %q", partialW.Code, partialW.Body.String())
	}
	if plugin.updateCalls != 1 || plugin.updateData["name"] != "a" {
		t.Fatalf("update %#v calls %d", plugin.updateData, plugin.updateCalls)
	}

	bad := httptest.NewRequest(http.MethodPatch, "/restapi/v1/users/1/", strings.NewReader(`{"age":"x"}`))
	bad.Header.Set("Content-Type", "application/json")
	badW := httptest.NewRecorder()
	router.ServeHTTP(badW, bad)
	if badW.Code != http.StatusBadRequest || !strings.Contains(badW.Body.String(), "invalid field age") {
		t.Fatalf("status %d body %q", badW.Code, badW.Body.String())
	}
	if plugin.updateCalls != 1 {
		t.Fatalf("update calls %d", plugin.updateCalls)
	}
}

func TestRestAPI_FilterFieldType(t *testing.T) {
	plugin := &restRecPlugin{
		rows: []map[string]any{{"name": "ada"}},
		schema: map[string]any{
			"tables": map[string]any{
				"users": map[string]any{
					"properties": map[string]any{
						"name":    map[string]any{"type": "integer"},
						"done":    map[string]any{"type": "boolean"},
						"payload": map[string]any{"type": "integer"},
						"status":  map[string]any{"type": "integer"},
						"city":    map[string]any{"type": "string"},
						"age":     map[string]any{"type": "integer"},
						"ids":     map[string]any{"type": "integer"},
					},
				},
			},
		},
	}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Filters: map[string]config.RestFilter{
							"done":   {Op: "eq"},
							"kind":   {Field: "payload->>kind", Op: "eq"},
							"label":  {Field: "name", Op: "like"},
							"folded": {Field: "name", Op: "ilike"},
							"empty":  {Field: "status", Op: "is"},
							"city":   {Op: "eq"},
							"ids":    {Op: "in"},
							"owner":  {Field: "age", Claim: "sub"},
						},
						Actions: map[string]config.RestAction{
							"list": {
								ExtraFields: map[string]any{
									"city": map[string]any{"type": "integer"},
								},
							},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	bad := httptest.NewRecorder()
	router.ServeHTTP(bad, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?done=nope", nil))
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "invalid filter done") {
		t.Fatalf("done status %d body %q", bad.Code, bad.Body.String())
	}
	if plugin.getCalls != 0 {
		t.Fatalf("get calls %d", plugin.getCalls)
	}

	ok := httptest.NewRecorder()
	router.ServeHTTP(ok, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?done=false", nil))
	if ok.Code != http.StatusOK {
		t.Fatalf("done ok status %d body %q", ok.Code, ok.Body.String())
	}
	got, _ := plugin.getWhere["done"].(map[string]any)
	if got["="] != "false" {
		t.Fatalf("where %#v", plugin.getWhere)
	}

	arrow := httptest.NewRecorder()
	router.ServeHTTP(arrow, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?kind=nope", nil))
	if arrow.Code != http.StatusOK {
		t.Fatalf("json filter status %d body %q", arrow.Code, arrow.Body.String())
	}
	arrowWhere, _ := plugin.getWhere["payload->>kind"].(map[string]any)
	if arrowWhere["="] != "nope" {
		t.Fatalf("json where %#v", plugin.getWhere)
	}

	like := httptest.NewRecorder()
	router.ServeHTTP(like, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?label=a%25", nil))
	if like.Code != http.StatusOK {
		t.Fatalf("like status %d body %q", like.Code, like.Body.String())
	}

	ilike := httptest.NewRecorder()
	router.ServeHTTP(ilike, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?folded=A%25", nil))
	if ilike.Code != http.StatusOK {
		t.Fatalf("ilike status %d body %q", ilike.Code, ilike.Body.String())
	}

	isNull := httptest.NewRecorder()
	router.ServeHTTP(isNull, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?empty=null", nil))
	if isNull.Code != http.StatusOK {
		t.Fatalf("is status %d body %q", isNull.Code, isNull.Body.String())
	}

	city := httptest.NewRecorder()
	router.ServeHTTP(city, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?city=Berlin", nil))
	if city.Code != http.StatusBadRequest || !strings.Contains(city.Body.String(), "invalid filter city") {
		t.Fatalf("city status %d body %q", city.Code, city.Body.String())
	}

	ids := httptest.NewRecorder()
	router.ServeHTTP(ids, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?ids=1,2,x", nil))
	if ids.Code != http.StatusBadRequest || !strings.Contains(ids.Body.String(), "invalid filter ids") {
		t.Fatalf("in status %d body %q", ids.Code, ids.Body.String())
	}

	before := plugin.getCalls
	idsOK := httptest.NewRecorder()
	router.ServeHTTP(idsOK, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?ids=1,2", nil))
	if idsOK.Code != http.StatusOK {
		t.Fatalf("in ok status %d body %q", idsOK.Code, idsOK.Body.String())
	}
	inWhere, _ := plugin.getWhere["ids"].(map[string]any)
	if inWhere["IN"] != "1,2" {
		t.Fatalf("in where %#v", plugin.getWhere)
	}
	if plugin.getCalls != before+1 {
		t.Fatalf("get calls %d before %d", plugin.getCalls, before)
	}

	claim := httptest.NewRecorder()
	router.ServeHTTP(claim, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if claim.Code != http.StatusOK {
		t.Fatalf("claim status %d body %q", claim.Code, claim.Body.String())
	}
	claimWhere, _ := plugin.getWhere["age"].(map[string]any)
	if claimWhere["="] != "tester" {
		t.Fatalf("claim where %#v", plugin.getWhere)
	}
}

func TestRestAPI_CallFieldType(t *testing.T) {
	plugin := &restRecPlugin{updated: 1}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						DetailActions: map[string]config.RestCallAction{
							"archive": {
								Func: "archive_user",
								Fields: map[string]any{
									"rows": map[string]any{"type": "integer"},
								},
							},
						},
						StateActions: map[string]config.RestStateAction{
							"settings": {
								SourceField: "settings",
								Fields: map[string]any{
									"rows": map[string]any{"type": "integer"},
								},
							},
						},
						Actions: map[string]config.RestAction{
							"create": {
								Handler: "appendTaskLines",
								ExtraFields: map[string]any{
									"lines": map[string]any{
										"type":  "array",
										"items": map[string]any{"type": "integer"},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	t.Cleanup(func() { SetRestHandlers(nil) })
	SetRestHandlers(map[string]Handler{
		"appendTaskLines": func(call Call) (any, error) {
			return call.Body, nil
		},
	})
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	bad := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/1/archive/", strings.NewReader(`{"rows":"x"}`))
	bad.Header.Set("Content-Type", "application/json")
	badW := httptest.NewRecorder()
	router.ServeHTTP(badW, bad)
	if badW.Code != http.StatusBadRequest || !strings.Contains(badW.Body.String(), "invalid field rows") {
		t.Fatalf("detail status %d body %q", badW.Code, badW.Body.String())
	}
	if plugin.funcName != "" {
		t.Fatalf("func %q", plugin.funcName)
	}

	ok := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/1/archive/", strings.NewReader(`{"rows":2}`))
	ok.Header.Set("Content-Type", "application/json")
	okW := httptest.NewRecorder()
	router.ServeHTTP(okW, ok)
	if okW.Code != http.StatusOK {
		t.Fatalf("detail ok status %d body %q", okW.Code, okW.Body.String())
	}
	if plugin.funcData["rows"] != float64(2) || plugin.funcData["id"] != "1" {
		t.Fatalf("func data %#v", plugin.funcData)
	}

	stateBad := httptest.NewRequest(http.MethodPut, "/restapi/v1/users/1/settings/", strings.NewReader(`{"rows":"x"}`))
	stateBad.Header.Set("Content-Type", "application/json")
	stateBadW := httptest.NewRecorder()
	router.ServeHTTP(stateBadW, stateBad)
	if stateBadW.Code != http.StatusBadRequest || !strings.Contains(stateBadW.Body.String(), "invalid field rows") {
		t.Fatalf("state status %d body %q", stateBadW.Code, stateBadW.Body.String())
	}
	if plugin.updateCalls != 0 {
		t.Fatalf("updates %d", plugin.updateCalls)
	}

	lines := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`[1,"x"]`))
	lines.Header.Set("Content-Type", "application/json")
	linesW := httptest.NewRecorder()
	router.ServeHTTP(linesW, lines)
	if linesW.Code != http.StatusBadRequest || !strings.Contains(linesW.Body.String(), "invalid field lines") {
		t.Fatalf("lines status %d body %q", linesW.Code, linesW.Body.String())
	}
}

func TestRestAPI_NullableField(t *testing.T) {
	plugin := &restRecPlugin{
		schema: map[string]any{
			"tables": map[string]any{
				"users": map[string]any{
					"properties": map[string]any{
						"age":  map[string]any{"type": "integer", "x-nullable": true},
						"name": map[string]any{"type": "string"},
					},
				},
			},
		},
	}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Actions: map[string]config.RestAction{
							"create": {},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})

	ok := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"age":null}`))
	ok.Header.Set("Content-Type", "application/json")
	okW := httptest.NewRecorder()
	router.ServeHTTP(okW, ok)
	if okW.Code != http.StatusCreated {
		t.Fatalf("null age status %d body %q", okW.Code, okW.Body.String())
	}
	if len(plugin.createData) != 1 || plugin.createData[0]["age"] != nil {
		t.Fatalf("row %#v", plugin.createData)
	}

	bad := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"name":null}`))
	bad.Header.Set("Content-Type", "application/json")
	badW := httptest.NewRecorder()
	router.ServeHTTP(badW, bad)
	if badW.Code != http.StatusBadRequest || !strings.Contains(badW.Body.String(), "invalid field name") {
		t.Fatalf("null name status %d body %q", badW.Code, badW.Body.String())
	}
}

func TestRestAPI_BadFieldSchema(t *testing.T) {
	plugin := &restRecPlugin{}
	cfg := config.Config{
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source: "db",
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Actions: map[string]config.RestAction{
							"create": {
								ExtraFields: map[string]any{
									"code": map[string]any{"type": "string", "pattern": "["},
								},
							},
						},
					},
				},
			},
		},
	}
	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plugin})
	req := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"code":"a"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if plugin.creates != 0 {
		t.Fatalf("creates %d", plugin.creates)
	}
}
