package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aveiga/archgate/internal/auth"
	"github.com/aveiga/archgate/internal/config"
)

func TestAuthMiddlewareRejectsRequestWithoutToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"active":true,"realm_access":{"roles":[]}}`))
	}))
	defer server.Close()

	cfg := &config.AuthzConfig{
		IntrospectionURL: server.URL,
		ClientID:         "gateway",
		ClientSecret:     "secret",
		Timeout:          0,
	}
	client := auth.NewClient(cfg, false, 0)
	mw := NewAuthMiddleware(client)

	rec := httptest.NewRecorder()
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest("GET", "/api/users", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
}

func TestAuthMiddlewareRejectsInvalidBearerFormat(t *testing.T) {
	client := auth.NewClient(&config.AuthzConfig{
		IntrospectionURL: "http://localhost/introspect",
		ClientID:         "x",
		ClientSecret:     "y",
		Timeout:          0,
	}, false, 0)
	mw := NewAuthMiddleware(client)

	rec := httptest.NewRecorder()
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "InvalidFormat token")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid bearer format, got %d", rec.Code)
	}
}

func TestAuthMiddlewarePassesValidTokenToNext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"active":true,"realm_access":{"roles":["admin"]},"username":"test"}`))
	}))
	defer server.Close()

	cfg := &config.AuthzConfig{
		IntrospectionURL: server.URL,
		ClientID:         "gateway",
		ClientSecret:     "secret",
		Timeout:          0,
	}
	client := auth.NewClient(cfg, false, 0)
	mw := NewAuthMiddleware(client)

	rec := httptest.NewRecorder()
	nextCalled := false
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		claims := GetTokenClaims(r)
		if claims == nil || claims.Username != "test" {
			t.Error("expected claims in context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	handler.ServeHTTP(rec, req)

	if !nextCalled || rec.Code != http.StatusNoContent {
		t.Fatalf("expected request to pass, status=%d nextCalled=%v", rec.Code, nextCalled)
	}
}

func TestAuthMiddlewareRejectsInactiveToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"active":false,"realm_access":{"roles":[]}}`))
	}))
	defer server.Close()

	cfg := &config.AuthzConfig{
		IntrospectionURL: server.URL,
		ClientID:         "gateway",
		ClientSecret:     "secret",
		Timeout:          0,
	}
	client := auth.NewClient(cfg, false, 0)
	mw := NewAuthMiddleware(client)

	rec := httptest.NewRecorder()
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer expired-token")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for inactive token, got %d", rec.Code)
	}
}
