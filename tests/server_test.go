package tests

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/umai-protocol/umai/internal/demoapp"
)

func TestStaticAssets_ServingAndMimeTypes(t *testing.T) {
	cfg := demoapp.DefaultConfig("app-b")
	cfg.AllowDemoDefaults = true
	cfg.DataDir = t.TempDir()

	staticDir, err := filepath.Abs("../examples/app-b/static")
	if err != nil {
		t.Fatalf("Failed to resolve static dir: %v", err)
	}

	server, err := demoapp.NewServer(cfg, staticDir)
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
	if recCSS.Code != http.StatusOK {
		t.Errorf("Expected 200 for /style.css, got %d", recCSS.Code)
	}

	// 3. Request /app.js
	reqJS, _ := http.NewRequest("GET", "/app.js", nil)
	recJS := httptest.NewRecorder()
	handler.ServeHTTP(recJS, reqJS)
	if recJS.Code != http.StatusOK {
		t.Errorf("Expected 200 for /app.js, got %d", recJS.Code)
	}

	// 4. Request /js/umai.js and /js/umai-spool.js
	for _, scriptPath := range []string{"/js/umai.js", "/js/umai-spool.js"} {
		reqScript, _ := http.NewRequest("GET", scriptPath, nil)
		recScript := httptest.NewRecorder()
		handler.ServeHTTP(recScript, reqScript)
		if recScript.Code != http.StatusOK {
			t.Errorf("Expected 200 for %s, got %d", scriptPath, recScript.Code)
		}
		if ct := recScript.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/javascript") {
			t.Errorf("Expected application/javascript Content-Type for %s, got %q", scriptPath, ct)
		}
	}

	// 5. Request /minimal.html
	reqMinHTML, _ := http.NewRequest("GET", "/minimal.html", nil)
	recMinHTML := httptest.NewRecorder()
	handler.ServeHTTP(recMinHTML, reqMinHTML)
	if recMinHTML.Code != http.StatusOK {
		t.Errorf("Expected 200 for /minimal.html, got %d", recMinHTML.Code)
	}

	// 6. Request /minimal.css
	reqMinCSS, _ := http.NewRequest("GET", "/minimal.css", nil)
	recMinCSS := httptest.NewRecorder()
	handler.ServeHTTP(recMinCSS, reqMinCSS)
	if recMinCSS.Code != http.StatusOK {
		t.Errorf("Expected 200 for /minimal.css, got %d", recMinCSS.Code)
	}

	// 7. Test App A serving /sync.html
	cfgA := demoapp.DefaultConfig("app-a")
	cfgA.AllowDemoDefaults = true
	cfgA.DataDir = t.TempDir()
	staticDirA, err := filepath.Abs("../examples/app-a/static")
	if err != nil {
		t.Fatalf("Failed to resolve App A static dir: %v", err)
	}
	serverA, err := demoapp.NewServer(cfgA, staticDirA)
	if err != nil {
		t.Fatalf("Failed to create App A server: %v", err)
	}
	reqSyncHTML, _ := http.NewRequest("GET", "/sync.html", nil)
	recSyncHTML := httptest.NewRecorder()
	serverA.Handler().ServeHTTP(recSyncHTML, reqSyncHTML)
	if recSyncHTML.Code != http.StatusOK {
		t.Errorf("Expected 200 for App A /sync.html, got %d", recSyncHTML.Code)
	}
}
