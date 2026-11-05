package tests

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/umai-protocol/umai/pkg/umaiserver"
)

func TestStaticAssets_ServingAndMimeTypes(t *testing.T) {
	cfg := umaiserver.DefaultConfig("app-b")
	cfg.DataDir = t.TempDir()

	staticDir, err := filepath.Abs("../examples/app-b/static")
	if err != nil {
		t.Fatalf("Failed to resolve static dir: %v", err)
	}

	server, err := umaiserver.NewServer(cfg, staticDir)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	handler := server.Handler()

	// 1. Request /
	reqIndex, _ := http.NewRequest("GET", "/", nil)
	recIndex := httptest.NewRecorder()
	handler.ServeHTTP(recIndex, reqIndex)
	if recIndex.Code != http.StatusOK {
		t.Errorf("Expected 200 for /, got %d", recIndex.Code)
	}

	// 2. Request /style.css
	reqCSS, _ := http.NewRequest("GET", "/style.css", nil)
	recCSS := httptest.NewRecorder()
	handler.ServeHTTP(recCSS, reqCSS)
	t.Logf("style.css Status: %d, Content-Type: %s", recCSS.Code, recCSS.Header().Get("Content-Type"))
	if recCSS.Code != http.StatusOK {
		t.Errorf("Expected 200 for /style.css, got %d", recCSS.Code)
	}

	// 3. Request /app.js
	reqJS, _ := http.NewRequest("GET", "/app.js", nil)
	recJS := httptest.NewRecorder()
	handler.ServeHTTP(recJS, reqJS)
	t.Logf("app.js Status: %d, Content-Type: %s", recJS.Code, recJS.Header().Get("Content-Type"))
	if recJS.Code != http.StatusOK {
		t.Errorf("Expected 200 for /app.js, got %d", recJS.Code)
	}

	// 4. Request /js/umai.js
	reqUmaiJS, _ := http.NewRequest("GET", "/js/umai.js", nil)
	recUmaiJS := httptest.NewRecorder()
	handler.ServeHTTP(recUmaiJS, reqUmaiJS)
	t.Logf("/js/umai.js Status: %d, Content-Type: %s", recUmaiJS.Code, recUmaiJS.Header().Get("Content-Type"))
	if recUmaiJS.Code != http.StatusOK {
		t.Errorf("Expected 200 for /js/umai.js, got %d", recUmaiJS.Code)
	}
}
