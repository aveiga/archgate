package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aveiga/archgate/internal/auth"
	"github.com/aveiga/archgate/internal/config"
	"github.com/aveiga/archgate/internal/middleware"
)

func TestNewProxyFailsWithInvalidUpstreamURL(t *testing.T) {
	route := &config.RouteConfig{
		Name:        "bad",
		Upstream:    "://invalid",
		StripPrefix: "",
	}
	_, err := NewProxy(route)
	if err == nil {
		t.Fatal("expected error for invalid upstream URL")
	}
}

func TestNewProxyStripsPrefix(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/1" {
			t.Errorf("expected path /users/1 after strip, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	route := &config.RouteConfig{
		Name:        "users",
		PathPattern: "^/api/users(/.*)?$",
		Upstream:    backend.URL,
		StripPrefix: "/api",
	}
	proxy, err := NewProxy(route)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}

	req := httptest.NewRequest("GET", "http://gateway/api/users/1", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestNewProxyProxiesRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	route := &config.RouteConfig{
		Name:        "health",
		PathPattern: "^/health$",
		Upstream:    backend.URL,
		StripPrefix: "",
	}
	proxy, err := NewProxy(route)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}

	req := httptest.NewRequest("GET", "http://gateway/health", nil)
	req.RemoteAddr = "10.0.0.1:45678"
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}
}

func TestProxyForwardHeadersUsesRemoteAddrWhenNoXForwardedFor(t *testing.T) {
	var capturedXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	route := &config.RouteConfig{
		Name:        "test",
		PathPattern: "^/",
		Upstream:    backend.URL,
		StripPrefix: "",
	}
	proxy, err := NewProxy(route)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}

	req := httptest.NewRequest("GET", "http://gateway/", nil)
	req.RemoteAddr = "192.168.1.100:54321"
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if !strings.Contains(capturedXFF, "192.168.1.100") {
		t.Errorf("expected X-Forwarded-For to contain client IP from RemoteAddr, got %q", capturedXFF)
	}
}

func TestProxyForwardHeadersFallbackWhenSplitHostPortFails(t *testing.T) {
	var capturedXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	route := &config.RouteConfig{
		Name:        "test",
		PathPattern: "^/",
		Upstream:    backend.URL,
		StripPrefix: "",
	}
	proxy, err := NewProxy(route)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}

	req := httptest.NewRequest("GET", "http://gateway/", nil)
	req.RemoteAddr = "192.168.1.100" // no port - SplitHostPort fails, fallback uses RemoteAddr as-is
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if !strings.Contains(capturedXFF, "192.168.1.100") {
		t.Errorf("expected X-Forwarded-For to contain client IP when RemoteAddr has no port, got %q", capturedXFF)
	}
}

func TestProxyForwardHeadersInjectsTrustedUsernameFromClaims(t *testing.T) {
	var capturedUsername string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUsername = r.Header.Get(trustedUsernameHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	route := &config.RouteConfig{
		Name:        "test",
		PathPattern: "^/",
		Upstream:    backend.URL,
		StripPrefix: "",
	}
	proxy, err := NewProxy(route)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}

	req := httptest.NewRequest("GET", "http://gateway/", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.TokenClaimsKey, &auth.IntrospectionResponse{
		Active:   true,
		Username: "gateway-user",
	}))
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if capturedUsername != "gateway-user" {
		t.Fatalf("expected trusted username header to be forwarded, got %q", capturedUsername)
	}
}

func TestProxyForwardHeadersOverwritesSpoofedUsernameHeader(t *testing.T) {
	var capturedUsername string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUsername = r.Header.Get(trustedUsernameHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	route := &config.RouteConfig{
		Name:        "test",
		PathPattern: "^/",
		Upstream:    backend.URL,
		StripPrefix: "",
	}
	proxy, err := NewProxy(route)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}

	req := httptest.NewRequest("GET", "http://gateway/", nil)
	req.Header.Set(trustedUsernameHeader, "spoofed-user")
	req = req.WithContext(context.WithValue(req.Context(), middleware.TokenClaimsKey, &auth.IntrospectionResponse{
		Active:   true,
		Username: "trusted-user",
	}))
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if capturedUsername != "trusted-user" {
		t.Fatalf("expected spoofed username header to be overwritten, got %q", capturedUsername)
	}
}
