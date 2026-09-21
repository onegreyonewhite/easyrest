package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/server"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	jwtplugin "github.com/onegreyonewhite/easyrest/plugins/auth/jwt"
	sqlitePlugin "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
)

func decodeNDJSON(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var rows []map[string]any
	dec := json.NewDecoder(strings.NewReader(string(body)))
	for {
		var row map[string]any
		if err := dec.Decode(&row); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("NDJSON decode: %v body=%q", err, body)
		}
		rows = append(rows, row)
	}
	return rows
}

func setupNDJSONTable(t *testing.T) (http.Handler, string) {
	t.Helper()
	dbPath := setupTestDB(t)
	t.Cleanup(func() {
		os.Remove(dbPath)
		server.StopPlugins()
	})
	insertUser(t, dbPath, "Alice", "")
	insertUser(t, dbPath, "Bob", "")
	insertUser(t, dbPath, "Charlie", "")
	insertUser(t, dbPath, "Diana", "")
	insertUser(t, dbPath, "Eve", "")
	server.PreservedAuthPlugins["jwt"] = func() easyrest.AuthPlugin {
		return &jwtplugin.JWTAuthPlugin{}
	}
	server.PreservedDbPlugins["sqlite"] = func() easyrest.DBPlugin {
		return sqlitePlugin.NewSqlitePlugin()
	}
	router := setupServerWithDB(t, dbPath)
	cfg := server.GetConfig()
	plugin := cfg.PluginMap["test"]
	plugin.DefaultLimit = 2
	cfg.PluginMap["test"] = plugin
	server.SetConfig(cfg)
	return router, generateToken(t)
}

func TestSelectNDJSONAutoPagesAllRows(t *testing.T) {
	router, tokenStr := setupNDJSONTable(t)
	req, err := http.NewRequest(http.MethodGet, "/api/test/users/?select=id,name&ordering=id", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Accept", "application/x-ndjson")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/x-ndjson") {
		t.Fatalf("content-type %s", rr.Header().Get("Content-Type"))
	}
	if cr := rr.Header().Get("Content-Range"); cr != "" {
		t.Fatalf("auto-stream Content-Range=%q", cr)
	}
	if rr.Header().Get("Accept-Ranges") != "items" {
		t.Fatalf("Accept-Ranges %s", rr.Header().Get("Accept-Ranges"))
	}
	assertVaryAcceptAndContentType(t, rr.Header())
	body := rr.Body.String()
	if strings.HasPrefix(strings.TrimSpace(body), "[") {
		t.Fatalf("expected NDJSON, got JSON array: %s", body)
	}
	rows := decodeNDJSON(t, rr.Body.Bytes())
	if len(rows) != 5 {
		t.Fatalf("expected 5 rows, got %d (%s)", len(rows), body)
	}
	if fmt.Sprint(rows[0]["name"]) != "Alice" || fmt.Sprint(rows[4]["name"]) != "Eve" {
		t.Fatalf("unexpected names: %#v", rows)
	}
	assertSelectNDJSONTrailers(t, rr, "0-4/*")
}

func TestSelectNDJSONLimitCapsTotalRows(t *testing.T) {
	router, tokenStr := setupNDJSONTable(t)
	req, err := http.NewRequest(http.MethodGet, "/api/test/users/?select=id,name&ordering=id&limit=2", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Accept", "application/x-ndjson")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	rows := decodeNDJSON(t, rr.Body.Bytes())
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
	if cr := rr.Header().Get("Content-Range"); cr != "" {
		t.Fatalf("capped NDJSON must omit Content-Range, got %q", cr)
	}
	assertSelectNDJSONTrailers(t, rr, "0-1/*")
}

func TestSelectNDJSONRangeCapsTotalRows(t *testing.T) {
	router, tokenStr := setupNDJSONTable(t)
	req, err := http.NewRequest(http.MethodGet, "/api/test/users/?select=id,name&ordering=id", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Accept", "application/x-ndjson")
	req.Header.Set("Range-Unit", "items")
	req.Header.Set("Range", "0-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	rows := decodeNDJSON(t, rr.Body.Bytes())
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d body=%s", len(rows), rr.Body.String())
	}
	if cr := rr.Header().Get("Content-Range"); cr != "" {
		t.Fatalf("capped NDJSON must omit Content-Range, got %q", cr)
	}
	assertSelectNDJSONTrailers(t, rr, "0-1/*")
}

func TestSelectNDJSONOffsetWithoutLimit(t *testing.T) {
	router, tokenStr := setupNDJSONTable(t)
	req, err := http.NewRequest(http.MethodGet, "/api/test/users/?select=id,name&ordering=id&offset=3", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Accept", "application/x-ndjson")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	rows := decodeNDJSON(t, rr.Body.Bytes())
	if len(rows) != 2 {
		t.Fatalf("expected 2 remaining rows, got %d body=%s", len(rows), rr.Body.String())
	}
	if fmt.Sprint(rows[0]["name"]) != "Diana" {
		t.Fatalf("expected Diana first, got %#v", rows[0])
	}
	assertSelectNDJSONTrailers(t, rr, "3-4/*")
}

func TestSelectNDJSONFormatJSONWins(t *testing.T) {
	router, tokenStr := setupNDJSONTable(t)
	req, err := http.NewRequest(http.MethodGet, "/api/test/users/?select=id,name&ordering=id&format=json", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Accept", "application/x-ndjson")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("content-type %s", rr.Header().Get("Content-Type"))
	}
	var result []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("json: %v body=%s", err, rr.Body.String())
	}
	if len(result) != 2 {
		t.Fatalf("JSON path should honor DefaultLimit=2, got %d", len(result))
	}
}

func TestSelectJSONDefaultLimitUnchanged(t *testing.T) {
	router, tokenStr := setupNDJSONTable(t)
	req, err := http.NewRequest(http.MethodGet, "/api/test/users/?select=id,name&ordering=id", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("content-type %s", rr.Header().Get("Content-Type"))
	}
	var result []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("json: %v body=%s", err, rr.Body.String())
	}
	if len(result) != 2 {
		t.Fatalf("expected DefaultLimit=2 JSON page, got %d", len(result))
	}
	if !strings.HasPrefix(rr.Header().Get("Content-Range"), "0-1/") {
		t.Fatalf("Content-Range %s", rr.Header().Get("Content-Range"))
	}
}

func TestSelectNDJSONPreferPageSize(t *testing.T) {
	router, tokenStr := setupNDJSONTable(t)
	req, err := http.NewRequest(http.MethodGet, "/api/test/users/?select=id,name&ordering=id", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Accept", "application/x-ndjson")
	req.Header.Set("Prefer", "page_size=3")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	rows := decodeNDJSON(t, rr.Body.Bytes())
	if len(rows) != 5 {
		t.Fatalf("expected 5 rows with page_size=3, got %d", len(rows))
	}
	if cr := rr.Header().Get("Content-Range"); cr != "" {
		t.Fatalf("auto-stream Content-Range=%q", cr)
	}
	if !strings.Contains(rr.Header().Get("Preference-Applied"), "page_size=3") {
		t.Fatalf("Preference-Applied %q", rr.Header().Get("Preference-Applied"))
	}
}

func TestSelectNDJSONLimitAndPageSize(t *testing.T) {
	router, tokenStr := setupNDJSONTable(t)
	req, err := http.NewRequest(http.MethodGet, "/api/test/users/?select=id,name&ordering=id&limit=3", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Accept", "application/x-ndjson")
	req.Header.Set("Prefer", "page_size=2")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	rows := decodeNDJSON(t, rr.Body.Bytes())
	if len(rows) != 3 {
		t.Fatalf("expected 3 capped rows, got %d", len(rows))
	}
	if cr := rr.Header().Get("Content-Range"); cr != "" {
		t.Fatalf("capped NDJSON must omit Content-Range, got %q", cr)
	}
}

func TestSelectJSONPreferPageSize(t *testing.T) {
	router, tokenStr := setupNDJSONTable(t)
	req, err := http.NewRequest(http.MethodGet, "/api/test/users/?select=id,name&ordering=id", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Prefer", "page_size=3")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var result []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("json: %v body=%s", err, rr.Body.String())
	}
	if len(result) != 3 {
		t.Fatalf("JSON Prefer page_size=3, got %d", len(result))
	}
	if !strings.HasPrefix(rr.Header().Get("Content-Range"), "0-2/") {
		t.Fatalf("Content-Range %s", rr.Header().Get("Content-Range"))
	}
	if !strings.Contains(rr.Header().Get("Preference-Applied"), "page_size=3") {
		t.Fatalf("Preference-Applied %q", rr.Header().Get("Preference-Applied"))
	}
}

func TestSelectJSONLimitWinsOverPageSize(t *testing.T) {
	router, tokenStr := setupNDJSONTable(t)
	req, err := http.NewRequest(http.MethodGet, "/api/test/users/?select=id,name&ordering=id&limit=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Prefer", "page_size=3")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var result []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("json: %v body=%s", err, rr.Body.String())
	}
	if len(result) != 1 {
		t.Fatalf("query limit should win, got %d", len(result))
	}
	if strings.Contains(rr.Header().Get("Preference-Applied"), "page_size=") {
		t.Fatalf("page_size should not be applied, got %q", rr.Header().Get("Preference-Applied"))
	}
}

func TestSelectJSONInvalidPageSizeIgnored(t *testing.T) {
	router, tokenStr := setupNDJSONTable(t)
	req, err := http.NewRequest(http.MethodGet, "/api/test/users/?select=id,name&ordering=id", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Prefer", "page_size=abc")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var result []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("json: %v body=%s", err, rr.Body.String())
	}
	if len(result) != 2 {
		t.Fatalf("invalid page_size should keep DefaultLimit=2, got %d", len(result))
	}
	if strings.Contains(rr.Header().Get("Preference-Applied"), "page_size=") {
		t.Fatalf("invalid page_size echoed: %q", rr.Header().Get("Preference-Applied"))
	}
}

func assertSelectNDJSONTrailers(t *testing.T, rr *httptest.ResponseRecorder, wantRange string) {
	t.Helper()
	res := rr.Result()
	t.Cleanup(func() { res.Body.Close() })
	if got := res.Trailer.Get("X-Content-Range"); got != wantRange {
		t.Fatalf("X-Content-Range trailer %q, want %q", got, wantRange)
	}
	if st := res.Trailer.Get("Server-Timing"); !strings.HasPrefix(st, "db;dur=") {
		t.Fatalf("Server-Timing trailer %q", st)
	}
}
