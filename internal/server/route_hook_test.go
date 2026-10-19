package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestRouteHook_SurvivesRebuild(t *testing.T) {
	orig := GetConfig()
	t.Cleanup(func() {
		SetRoutes(nil)
		SetConfig(orig)
	})
	if err := SetupApplication("port: \"8080\"\n", nil); err != nil {
		t.Fatal(err)
	}
	SetRoutes(func(r chi.Router) {
		r.Get("/extra", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("extra"))
		})
	})

	for i := 0; i < 2; i++ {
		router := SetupRouter()
		extra := httptest.NewRecorder()
		router.ServeHTTP(extra, httptest.NewRequest(http.MethodGet, "/extra", nil))
		if extra.Code != http.StatusOK || extra.Body.String() != "extra" {
			t.Fatalf("rebuild %d extra: %d %s", i, extra.Code, extra.Body.String())
		}
		health := httptest.NewRecorder()
		router.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/health", nil))
		if health.Code != http.StatusOK || health.Body.String() != "OK" {
			t.Fatalf("rebuild %d health: %d %s", i, health.Code, health.Body.String())
		}
	}
}
