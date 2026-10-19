package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	"github.com/onegreyonewhite/easyrest/plugins/storage/dbglob"
	"github.com/onegreyonewhite/easyrest/plugins/storage/memory"
)

func testMemoryRef(t *testing.T) storagePluginRef {
	t.Helper()
	plug := memory.New()
	if _, err := plug.Init(map[string]any{"name": "memory"}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	return storagePluginRef{Name: "memory", Plugin: plug, Root: ".", Inline: false}
}

func testDBGlobRef(t *testing.T) storagePluginRef {
	t.Helper()
	plug := dbglob.New()
	if _, err := plug.Init(nil, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	return storagePluginRef{Name: "dbglob", Plugin: plug, Inline: true}
}

func TestStoreObjectFieldsMemory(t *testing.T) {
	ref := testMemoryRef(t)
	kinds := map[string]storageValueKind{
		"avatar": storageValueBinary,
		"photos": storageValueBinaryList,
		"thumb":  storageValueBase64,
		"extra":  storageValueBase64List,
		"note":   storageValueNone,
	}
	row := map[string]any{
		"title": "ada",
		"thumb": base64.StdEncoding.EncodeToString([]byte("png")),
		"extra": []any{base64.StdEncoding.EncodeToString([]byte("a")), base64.StdEncoding.EncodeToString([]byte("b"))},
		"blank": "",
	}
	kinds["blank"] = storageValueBase64
	files := []multipartFile{
		{Name: "avatar", Filename: "../a.png", Body: []byte("one")},
		{Name: "photos", Filename: "1.jpg", Body: []byte("p1")},
		{Name: "photos", Filename: "2.jpg", Body: []byte("p2")},
	}
	err := storeObjectFields(context.Background(), row, files, kinds, ref, "users", map[string]any{
		"request": map[string]any{"scheme": "http", "host": "example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	avatar, _ := row["avatar"].(string)
	if strings.Contains(avatar, "..") || !strings.HasSuffix(avatar, "/a.png") {
		t.Fatalf("avatar path %q", avatar)
	}
	photos, _ := row["photos"].(string)
	if !strings.HasPrefix(photos, "[") || !strings.Contains(photos, "1.jpg") || !strings.Contains(photos, "2.jpg") {
		t.Fatalf("photos %q", photos)
	}
	thumb, _ := row["thumb"].(string)
	if !strings.HasSuffix(thumb, "/object") {
		t.Fatalf("thumb %q", thumb)
	}
	if _, ok := row["blank"]; ok {
		t.Fatal("empty base64 should be unset")
	}
	body, _, _, err := ref.Plugin.GetBin(avatar, nil)
	if err != nil || string(body) != "one" {
		t.Fatalf("stored avatar %q %v", body, err)
	}

	bad := map[string]any{"thumb": "@@@"}
	err = storeObjectFields(context.Background(), bad, nil, map[string]storageValueKind{"thumb": storageValueBase64}, ref, "users", nil)
	if err == nil || storageStatus(err) != http.StatusBadRequest {
		t.Fatalf("invalid base64: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = storeObjectFields(ctx, map[string]any{"thumb": base64.StdEncoding.EncodeToString([]byte("x"))}, nil, map[string]storageValueKind{"thumb": storageValueBase64}, ref, "users", nil)
	if err == nil {
		t.Fatal("expected canceled context to fail")
	}
}

func TestStoreObjectFieldsDBGlob(t *testing.T) {
	ref := testDBGlobRef(t)
	row := map[string]any{"thumb": base64.StdEncoding.EncodeToString([]byte("png"))}
	err := storeObjectFields(context.Background(), row, []multipartFile{{Name: "avatar", Filename: "a.png", Body: []byte("one")}}, map[string]storageValueKind{
		"avatar": storageValueBinary,
		"thumb":  storageValueBase64,
	}, ref, "users", nil)
	if err != nil {
		t.Fatal(err)
	}
	if row["avatar"] != base64.StdEncoding.EncodeToString([]byte("one")) {
		t.Fatalf("avatar %v", row["avatar"])
	}
	if row["thumb"] != base64.StdEncoding.EncodeToString([]byte("png")) {
		t.Fatalf("thumb %v", row["thumb"])
	}
}

func TestReadMultipartJSONAndFile(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreatePart(textprotoJSON())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(`{"title":"ada"}`)); err != nil {
		t.Fatal(err)
	}
	file, err := writer.CreateFormFile("avatar", "a.png")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("png")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/restapi/v1/users/", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	allowed := contentRefsNamed([]string{"json"})
	parsed, files, err := readMultipart(req, allowed)
	if err != nil {
		t.Fatal(err)
	}
	obj, _ := parsed.(map[string]any)
	if obj["title"] != "ada" || len(files) != 1 || files[0].Name != "avatar" {
		t.Fatalf("parsed %#v files %#v", parsed, files)
	}
}

func textprotoJSON() map[string][]string {
	return map[string][]string{
		"Content-Disposition": {`form-data; name="payload"`},
		"Content-Type":        {easyrest.MediaTypeJSON},
	}
}

func TestReadMultipartRejects(t *testing.T) {
	allowed := contentRefsNamed([]string{"json"})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("--b\r\n"))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=b")
	if _, _, err := readMultipart(req, allowed); err == nil {
		t.Fatal("expected a missing document to fail")
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreatePart(map[string][]string{
		"Content-Disposition": {`form-data; name="payload"`},
		"Content-Type":        {"application/xml"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("<title>ada</title>"))
	_ = writer.Close()
	req = httptest.NewRequest(http.MethodPost, "/", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if _, _, err := readMultipart(req, allowed); err == nil || storageStatus(err) != http.StatusBadRequest {
		t.Fatalf("disallowed media type: %v", err)
	}
}
