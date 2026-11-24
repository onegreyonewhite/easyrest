package server

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	"github.com/onegreyonewhite/easyrest/plugins/storage/dbglob"
	"github.com/onegreyonewhite/easyrest/plugins/storage/memory"
)

func useStoragePlugins(t *testing.T, refs map[string]storagePluginRef) {
	t.Helper()
	orig := storagePlugins.Load()
	t.Cleanup(func() { storagePlugins.Store(orig) })
	storagePlugins.Store(&refs)
}

func memoryStorageRef(t *testing.T) storagePluginRef {
	t.Helper()
	plug := memory.New()
	if _, err := plug.Init(map[string]any{"name": "memory"}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	return storagePluginRef{Name: "memory", Plugin: plug, Root: ".", Inline: false}
}

func dbglobStorageRef(t *testing.T) storagePluginRef {
	t.Helper()
	plug := dbglob.New()
	if _, err := plug.Init(nil, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	return storagePluginRef{Name: "dbglob", Plugin: plug, Inline: true}
}

func storageUsersConfig(storageName string) config.Config {
	binary := map[string]any{"type": "string", "format": "binary"}
	photos := map[string]any{"type": "array", "items": map[string]any{"type": "string", "format": "binary"}}
	thumb := map[string]any{"type": "string", "format": "base64"}
	extra := map[string]any{"avatar": binary, "photos": photos, "thumb": thumb}
	fields := []string{"title", "avatar", "photos", "thumb"}
	props := map[string]any{
		"title":  map[string]any{"type": "string"},
		"avatar": binary,
		"photos": photos,
		"thumb":  thumb,
	}
	return config.Config{
		DefaultStoragePlugin: storageName,
		RestAPI: map[string]config.RestAPIApp{
			"v1": {
				Source:  "db",
				Storage: storageName,
				Endpoints: map[string]config.RestEndpoint{
					"users": {
						Actions: map[string]config.RestAction{
							"list":     {Fields: fields, ExtraFields: extra, Storage: storageName},
							"create":   {Fields: fields, ExtraFields: extra, Storage: storageName},
							"retrieve": {Fields: fields, ExtraFields: extra, Storage: storageName},
							"update":   {Fields: fields, ExtraFields: extra, Storage: storageName},
						},
						DetailActions: map[string]config.RestCallAction{
							"export": {Func: "export_users", Fields: props, Storage: storageName},
						},
						ListActions: map[string]config.RestCallAction{
							"import": {Func: "import_users", Fields: props, Storage: storageName},
						},
						StateActions: map[string]config.RestStateAction{
							"avatar": {SourceField: "avatar_state", Fields: props, Storage: storageName},
						},
					},
				},
			},
		},
	}
}

func usersSchema() any {
	return map[string]any{
		"tables": map[string]any{
			"users": map[string]any{
				"properties": map[string]any{
					"title":  map[string]any{"type": "string"},
					"avatar": map[string]any{"type": "string"},
					"photos": map[string]any{"type": "string"},
					"thumb":  map[string]any{"type": "string"},
				},
			},
		},
	}
}

func multipartBody(t *testing.T, payload string, files map[string][]byte) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreatePart(map[string][]string{
		"Content-Disposition": {`form-data; name="payload"`},
		"Content-Type":        {"application/json"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		file, err := writer.CreateFormFile(name, name+".bin")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return &body, writer.FormDataContentType()
}

func TestRestStorageMultipartAndBase64(t *testing.T) {
	mem := memoryStorageRef(t)
	useStoragePlugins(t, map[string]storagePluginRef{"memory": mem})
	plugin := &restRecPlugin{schema: usersSchema(), updated: 1}
	router := serveRest(t, storageUsersConfig("memory"), map[string]easyrest.DBPlugin{"db": plugin})

	body, contentType := multipartBody(t, `{"title":"ada","thumb":"`+easyrest.FormatDataURL("image/png", []byte("png"))+`"}`, map[string][]byte{
		"avatar": []byte("one"),
		"photos": []byte("p1"),
	})
	req := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", body)
	req.Header.Set("Content-Type", contentType)
	req.Host = "example.test"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create %d %s", w.Code, w.Body.String())
	}
	storedAvatar, _ := plugin.createData[0]["avatar"].(string)
	if strings.Contains(storedAvatar, "http") || storedAvatar == "" {
		t.Fatalf("stored avatar %q", storedAvatar)
	}
	var created []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created[0]["avatar"].(string), "http://example.test/media/memory/") {
		t.Fatalf("response avatar %v", created[0]["avatar"])
	}
	photos, _ := plugin.createData[0]["photos"].(string)
	if !strings.HasPrefix(photos, "[") {
		t.Fatalf("stored photos %q", photos)
	}

	plugin.rows = []map[string]any{plugin.createData[0]}
	getW := httptest.NewRecorder()
	getReq := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/1/", nil)
	getReq.Host = "example.test"
	router.ServeHTTP(getW, getReq)
	if getW.Code != http.StatusOK || !strings.Contains(getW.Body.String(), "http://example.test/media/memory/") {
		t.Fatalf("retrieve %d %s", getW.Code, getW.Body.String())
	}
	if plugin.createData[0]["avatar"] != storedAvatar {
		t.Fatal("retrieve rewrote the stored path")
	}

	listW := httptest.NewRecorder()
	listReq := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil)
	listReq.Host = "example.test"
	router.ServeHTTP(listW, listReq)
	if listW.Code != http.StatusOK || !strings.Contains(listW.Body.String(), "http://example.test/media/memory/") {
		t.Fatalf("list %d %s", listW.Code, listW.Body.String())
	}

	plain := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"title":"grace"}`))
	plain.Header.Set("Content-Type", "application/json")
	plainW := httptest.NewRecorder()
	before := plugin.creates
	router.ServeHTTP(plainW, plain)
	if plainW.Code != http.StatusCreated || plugin.creates != before+1 {
		t.Fatalf("plain create %d %s", plainW.Code, plainW.Body.String())
	}

	bad := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(`{"title":"x","thumb":"@@@"}`))
	bad.Header.Set("Content-Type", "application/json")
	badW := httptest.NewRecorder()
	creates := plugin.creates
	router.ServeHTTP(badW, bad)
	if badW.Code != http.StatusBadRequest || plugin.creates != creates {
		t.Fatalf("bad data url %d creates %d", badW.Code, plugin.creates)
	}

	patchBody, patchType := multipartBody(t, `{"title":"ada"}`, map[string][]byte{"avatar": []byte("two")})
	patch := httptest.NewRequest(http.MethodPatch, "/restapi/v1/users/1/", patchBody)
	patch.Header.Set("Content-Type", patchType)
	patchW := httptest.NewRecorder()
	router.ServeHTTP(patchW, patch)
	if patchW.Code != http.StatusOK {
		t.Fatalf("update %d %s", patchW.Code, patchW.Body.String())
	}
	if _, ok := plugin.updateData["avatar"].(string); !ok {
		t.Fatalf("update data %#v", plugin.updateData)
	}

	stateBody, stateType := multipartBody(t, `{"title":"state"}`, map[string][]byte{"avatar": []byte("st")})
	state := httptest.NewRequest(http.MethodPut, "/restapi/v1/users/1/avatar/", stateBody)
	state.Header.Set("Content-Type", stateType)
	stateW := httptest.NewRecorder()
	router.ServeHTTP(stateW, state)
	if stateW.Code != http.StatusOK {
		t.Fatalf("state %d %s", stateW.Code, stateW.Body.String())
	}

	callBody, callType := multipartBody(t, `{"title":"call"}`, map[string][]byte{"avatar": []byte("call")})
	call := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/1/export/", callBody)
	call.Header.Set("Content-Type", callType)
	call.Host = "example.test"
	callW := httptest.NewRecorder()
	router.ServeHTTP(callW, call)
	if callW.Code != http.StatusOK || !strings.Contains(callW.Body.String(), "http://example.test/media/memory/") {
		t.Fatalf("detail %d %s", callW.Code, callW.Body.String())
	}
	if _, ok := plugin.funcData["avatar"].(string); !ok || strings.Contains(plugin.funcData["avatar"].(string), "http") {
		t.Fatalf("func data %#v", plugin.funcData)
	}

	listCallBody, listCallType := multipartBody(t, `{"title":"imp"}`, map[string][]byte{"avatar": []byte("imp")})
	listCall := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/import/", listCallBody)
	listCall.Header.Set("Content-Type", listCallType)
	listCallW := httptest.NewRecorder()
	router.ServeHTTP(listCallW, listCall)
	if listCallW.Code != http.StatusOK {
		t.Fatalf("list action %d %s", listCallW.Code, listCallW.Body.String())
	}
}

func TestRestStorageDBGlob(t *testing.T) {
	useStoragePlugins(t, map[string]storagePluginRef{"dbglob": dbglobStorageRef(t)})
	plugin := &restRecPlugin{schema: usersSchema(), updated: 1}
	router := serveRest(t, storageUsersConfig("dbglob"), map[string]easyrest.DBPlugin{"db": plugin})
	thumb := easyrest.FormatDataURL("image/png", []byte("png"))
	payload := `{"title":"ada","thumb":"` + thumb + `"}`
	req := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create %d %s", w.Code, w.Body.String())
	}
	if plugin.createData[0]["thumb"] != thumb {
		t.Fatalf("stored %#v", plugin.createData[0])
	}
	if !strings.Contains(w.Body.String(), thumb) {
		t.Fatalf("response %s", w.Body.String())
	}

	specW := httptest.NewRecorder()
	router.ServeHTTP(specW, httptest.NewRequest(http.MethodGet, "/restapi/v1/", nil))
	if specW.Code != http.StatusOK {
		t.Fatalf("spec %d", specW.Code)
	}
	if !strings.Contains(specW.Body.String(), `"format":"data-url"`) {
		t.Fatalf("spec missing data-url format: %s", specW.Body.String())
	}
	if strings.Contains(specW.Body.String(), `"format":"uri"`) {
		t.Fatalf("dbglob spec used uri: %s", specW.Body.String())
	}
}

func TestRestStorageSchemaURI(t *testing.T) {
	useStoragePlugins(t, map[string]storagePluginRef{"memory": memoryStorageRef(t)})
	plugin := &restRecPlugin{schema: usersSchema()}
	router := serveRest(t, storageUsersConfig("memory"), map[string]easyrest.DBPlugin{"db": plugin})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/restapi/v1/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("spec %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"format":"uri"`) {
		t.Fatalf("spec missing uri: %s", w.Body.String())
	}
	var spec map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths, _ := spec["paths"].(map[string]any)
	users, _ := paths["/users/"].(map[string]any)
	post, _ := users["post"].(map[string]any)
	params, _ := post["parameters"].([]any)
	if post["requestBody"] != nil || len(params) != 1 {
		t.Fatalf("create request schema should stay undescribed, got %#v", post)
	}
	prefer, _ := params[0].(map[string]any)
	if prefer["name"] != "Prefer" || prefer["in"] != "header" {
		t.Fatalf("create parameters %#v", params)
	}
}

func TestRestMultipartRejectedWithoutBinary(t *testing.T) {
	plugin := &restRecPlugin{}
	router := serveRest(t, restUsersConfig(), map[string]easyrest.DBPlugin{"db": plugin})
	body, contentType := multipartBody(t, `{"name":"ada"}`, nil)
	req := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", body)
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
}
