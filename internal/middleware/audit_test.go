package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aveiga/archgate/internal/auth"
)

func TestAuditMiddlewareSkipsHealthPath(t *testing.T) {
	mw := NewAuditMiddleware()

	rec := httptest.NewRecorder()
	nextCalled := false
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/health", nil)
	handler.ServeHTTP(rec, req)

	if !nextCalled || rec.Code != http.StatusOK {
		t.Fatalf("expected request to pass through, status=%d nextCalled=%v", rec.Code, nextCalled)
	}
}

func TestAuditMiddlewareSkipsOPTIONSMethod(t *testing.T) {
	mw := NewAuditMiddleware()

	rec := httptest.NewRecorder()
	nextCalled := false
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("OPTIONS", "/api/users", nil)
	handler.ServeHTTP(rec, req)

	if !nextCalled || rec.Code != http.StatusOK {
		t.Fatalf("expected OPTIONS to pass through, status=%d nextCalled=%v", rec.Code, nextCalled)
	}
}

func TestAuditMiddlewareLogsNormalRequest(t *testing.T) {
	mw := NewAuditMiddleware()

	rec := httptest.NewRecorder()
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestShouldSkipLoggingMatchesPathPrefix(t *testing.T) {
	tests := []struct {
		path   string
		expect bool
	}{
		{"/health", true},
		{"/health/", true},
		{"/ping", true},
		{"/favicon.ico", true},
		{"/audit-logs", true},
		{"/api/users", false},
		{"/", false},
	}
	for _, tt := range tests {
		req := httptest.NewRequest("GET", tt.path, nil)
		got := shouldSkipLogging(req)
		if got != tt.expect {
			t.Errorf("shouldSkipLogging(%q) = %v, want %v", tt.path, got, tt.expect)
		}
	}
}

func TestSanitizeHeadersRemovesAuthorization(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer secret")
	h.Set("Content-Type", "application/json")
	sanitized := sanitizeHeaders(h)
	if _, ok := sanitized["Authorization"]; ok {
		t.Error("expected Authorization to be redacted")
	}
	if sanitized["Content-Type"] != "application/json" {
		t.Errorf("expected Content-Type preserved, got %v", sanitized)
	}
}

func TestSanitizeBodyRedactsPassword(t *testing.T) {
	body := map[string]interface{}{
		"username": "user",
		"password": "secret123",
	}
	sanitized := sanitizeBody(body).(map[string]interface{})
	if sanitized["password"] != "[REDACTED]" {
		t.Errorf("expected password redacted, got %v", sanitized["password"])
	}
	if sanitized["username"] != "user" {
		t.Errorf("expected username preserved, got %v", sanitized["username"])
	}
}

func TestGetClientIPUsesXForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	req.RemoteAddr = "192.168.1.1:12345"
	got := getClientIP(req)
	if got != "10.0.0.1" {
		t.Errorf("expected first X-Forwarded-For IP, got %s", got)
	}
}

func TestGetClientIPUsesXRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-IP", "203.0.113.1")
	req.RemoteAddr = "192.168.1.1:12345"
	got := getClientIP(req)
	if got != "203.0.113.1" {
		t.Errorf("expected X-Real-IP, got %s", got)
	}
}

func TestGetClientIPFallsBackToRemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	got := getClientIP(req)
	if !strings.HasPrefix(got, "192.168.1.1") {
		t.Errorf("expected RemoteAddr IP, got %s", got)
	}
}

func TestParseInt64(t *testing.T) {
	n, err := parseInt64("12345")
	if err != nil {
		t.Fatalf("parseInt64: %v", err)
	}
	if n != 12345 {
		t.Errorf("expected 12345, got %d", n)
	}
}

func TestAuditMiddlewareLogsRequestWithBodyAndErrorResponse(t *testing.T) {
	mw := NewAuditMiddleware()

	rec := httptest.NewRecorder()
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"bad request"}`))
	}))

	req := httptest.NewRequest("POST", "/api/users", strings.NewReader(`{"name":"test"}`))
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestSanitizeBodyHandlesNestedSensitiveFields(t *testing.T) {
	body := map[string]interface{}{
		"user": map[string]interface{}{
			"name":     "john",
			"password": "secret",
		},
	}
	sanitized := sanitizeBody(body).(map[string]interface{})
	nested := sanitized["user"].(map[string]interface{})
	if nested["password"] != "[REDACTED]" {
		t.Errorf("expected nested password redacted, got %v", nested["password"])
	}
}

func TestGetClientIPReturnsUnknownWhenEmpty(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ""
	got := getClientIP(req)
	if got != "unknown" {
		t.Errorf("expected unknown for empty RemoteAddr, got %s", got)
	}
}

func TestAuditMiddlewareHandlerWriteWithoutWriteHeader(t *testing.T) {
	mw := NewAuditMiddleware()
	rec := httptest.NewRecorder()
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("body-only")) // no WriteHeader - triggers default 200 in responseWriter.Write
	}))
	req := httptest.NewRequest("GET", "/api/users", nil)
	req.RemoteAddr = "10.0.0.1:80"
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestAuditMiddlewareLogsNonJSONBodyTruncated(t *testing.T) {
	mw := NewAuditMiddleware()
	rec := httptest.NewRecorder()
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	body := strings.Repeat("x", 1500)
	req := httptest.NewRequest("POST", "/api/upload", strings.NewReader(body))
	req.RemoteAddr = "10.0.0.1:80"
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestAuditMiddlewareLogsRequestWithTokenClaims(t *testing.T) {
	mw := NewAuditMiddleware()
	rec := httptest.NewRecorder()
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/users", nil)
	req.RemoteAddr = "10.0.0.1:80"
	claims := &auth.IntrospectionResponse{
		Active:      true,
		Username:    "alice",
		RealmAccess: auth.RealmAccess{Roles: []string{"admin"}},
	}
	req = req.WithContext(context.WithValue(req.Context(), TokenClaimsKey, claims))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}
