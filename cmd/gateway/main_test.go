package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aveiga/archgate/internal/config"
	"github.com/aveiga/archgate/internal/middleware"
	"github.com/aveiga/archgate/internal/router"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}

	os.Stdout = writer
	defer func() {
		os.Stdout = originalStdout
	}()

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}

	return strings.TrimSpace(buf.String())
}

func TestGatewayHandlerAuditsUnmatchedRoute(t *testing.T) {
	routeRouter := router.NewRouter(nil)
	authMW := middleware.NewAuthMiddleware(nil)
	auditMW := middleware.NewAuditMiddleware()
	handler := newGatewayHandler(routeRouter, authMW, auditMW)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/unknown/path", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	output := captureStdout(t, func() {
		handler.ServeHTTP(rec, req)
	})

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	var entry middleware.AuditLogEntry
	if err := json.Unmarshal([]byte(output), &entry); err != nil {
		t.Fatalf("unmarshal audit log output: %v\noutput: %s", err, output)
	}
	if entry.ResponseStatus != http.StatusNotFound {
		t.Fatalf("expected responseStatus 404, got %d", entry.ResponseStatus)
	}
	if entry.Method != http.MethodGet {
		t.Fatalf("expected method GET, got %q", entry.Method)
	}
	if entry.Path != "/unknown/path" {
		t.Fatalf("expected path /unknown/path, got %q", entry.Path)
	}
	if entry.Type != "audit_log" {
		t.Fatalf("expected type audit_log, got %q", entry.Type)
	}
	if entry.UserID != nil {
		t.Fatalf("expected userId to be null, got %#v", entry.UserID)
	}
	if entry.UserName != nil {
		t.Fatalf("expected userName to be null, got %#v", entry.UserName)
	}
	if entry.Roles != nil {
		t.Fatalf("expected roles to be null, got %#v", entry.Roles)
	}
}

func TestGatewayHandlerAuditsProtectedRouteAuthFailure(t *testing.T) {
	routes := []config.RouteConfig{
		{
			Name:            "users",
			PathPattern:     "^/api/users(/.*)?$",
			CompiledPattern: regexp.MustCompile("^/api/users(/.*)?$"),
			Upstream:        "http://analytics:3000",
			Rules: []config.RouteRule{
				{
					Methods:       []string{"GET"},
					RequiredRoles: []string{"admin"},
				},
			},
		},
	}
	routeRouter := router.NewRouter(routes)
	authMW := middleware.NewAuthMiddleware(nil)
	auditMW := middleware.NewAuditMiddleware()
	handler := newGatewayHandler(routeRouter, authMW, auditMW)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	output := captureStdout(t, func() {
		handler.ServeHTTP(rec, req)
	})

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	var entry middleware.AuditLogEntry
	if err := json.Unmarshal([]byte(output), &entry); err != nil {
		t.Fatalf("unmarshal audit log output: %v\noutput: %s", err, output)
	}
	if entry.ResponseStatus != http.StatusUnauthorized {
		t.Fatalf("expected responseStatus 401, got %d", entry.ResponseStatus)
	}
	if entry.Method != http.MethodGet {
		t.Fatalf("expected method GET, got %q", entry.Method)
	}
	if entry.Path != "/api/users" {
		t.Fatalf("expected path /api/users, got %q", entry.Path)
	}
	if entry.Type != "audit_log" {
		t.Fatalf("expected type audit_log, got %q", entry.Type)
	}
	if entry.UserID != nil {
		t.Fatalf("expected userId to be null, got %#v", entry.UserID)
	}
	if entry.UserName != nil {
		t.Fatalf("expected userName to be null, got %#v", entry.UserName)
	}
	if entry.Roles != nil {
		t.Fatalf("expected roles to be null, got %#v", entry.Roles)
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func TestSplitRulesByAuth(t *testing.T) {
	rules := []config.RouteRule{
		{Methods: []string{"GET"}, RequireAuth: boolPtr(false)},
		{Methods: []string{"POST"}},
		{Methods: []string{"DELETE"}, RequireAuth: boolPtr(true)},
	}

	publicRules, protectedRules := splitRulesByAuth(rules)
	if len(publicRules) != 1 {
		t.Fatalf("expected 1 public rule, got %d", len(publicRules))
	}
	if len(protectedRules) != 2 {
		t.Fatalf("expected 2 protected rules, got %d", len(protectedRules))
	}
}

func TestLoadEnvFileSetsVariables(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("TEST_KEY=test_value\n# comment\nANOTHER=val2\n"), 0644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	os.Unsetenv("TEST_KEY")
	os.Unsetenv("ANOTHER")
	defer func() {
		os.Unsetenv("TEST_KEY")
		os.Unsetenv("ANOTHER")
	}()

	loadEnvFile(envPath)

	if os.Getenv("TEST_KEY") != "test_value" {
		t.Errorf("expected TEST_KEY=test_value, got %q", os.Getenv("TEST_KEY"))
	}
	if os.Getenv("ANOTHER") != "val2" {
		t.Errorf("expected ANOTHER=val2, got %q", os.Getenv("ANOTHER"))
	}
}

func TestLoadEnvFileNoErrorWhenMissing(t *testing.T) {
	loadEnvFile("/nonexistent/.env")
	// Should not panic or fail
}

func TestLoadEnvFileStripsQuotes(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte(`QUOTED="value with spaces"`), 0644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	os.Unsetenv("QUOTED")
	defer os.Unsetenv("QUOTED")

	loadEnvFile(envPath)

	if os.Getenv("QUOTED") != "value with spaces" {
		t.Errorf("expected stripped quotes, got %q", os.Getenv("QUOTED"))
	}
}

func TestResolveRoutesDirDefaultsToRoutes(t *testing.T) {
	os.Unsetenv("ROUTES_DIR_PATH")

	if got := resolveRoutesDir(); got != defaultRoutesDir {
		t.Fatalf("expected default routes dir %q, got %q", defaultRoutesDir, got)
	}
}

func TestResolveRoutesDirUsesOverride(t *testing.T) {
	os.Setenv("ROUTES_DIR_PATH", "/custom-routes")
	defer os.Unsetenv("ROUTES_DIR_PATH")

	if got := resolveRoutesDir(); got != "/custom-routes" {
		t.Fatalf("expected ROUTES_DIR_PATH override, got %q", got)
	}
}
