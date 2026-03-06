package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aveiga/archgate/internal/config"
)

func TestGetAllRolesFromRealmAccess(t *testing.T) {
	ir := &IntrospectionResponse{
		Active:      true,
		RealmAccess: RealmAccess{Roles: []string{"admin", "user"}},
	}
	roles := ir.GetAllRoles()
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d: %v", len(roles), roles)
	}
	roleSet := make(map[string]bool)
	for _, r := range roles {
		roleSet[r] = true
	}
	if !roleSet["admin"] || !roleSet["user"] {
		t.Fatalf("expected admin and user roles, got %v", roles)
	}
}

func TestGetAllRolesDeduplicatesRealmAndResourceAccess(t *testing.T) {
	ir := &IntrospectionResponse{
		Active:      true,
		RealmAccess: RealmAccess{Roles: []string{"admin"}},
		ResourceAccess: map[string]RealmAccess{
			"app": {Roles: []string{"admin", "editor"}},
		},
	}
	roles := ir.GetAllRoles()
	if len(roles) != 2 {
		t.Fatalf("expected 2 unique roles (admin, editor), got %d: %v", len(roles), roles)
	}
}

func TestIntrospectTokenReturnsActiveToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"active":true,"realm_access":{"roles":["admin"]},"username":"test"}`))
	}))
	defer server.Close()

	cfg := &config.AuthzConfig{
		IntrospectionURL: server.URL,
		ClientID:         "gateway",
		ClientSecret:     "secret",
		Timeout:          5 * time.Second,
	}
	client := NewClient(cfg, false, 0)

	result, err := client.IntrospectToken(context.Background(), "token123")
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if !result.Active {
		t.Fatal("expected active token")
	}
	if len(result.RealmAccess.Roles) != 1 || result.RealmAccess.Roles[0] != "admin" {
		t.Fatalf("unexpected roles: %v", result.RealmAccess.Roles)
	}
}

func TestIntrospectTokenReturnsErrorOnNonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("invalid client"))
	}))
	defer server.Close()

	cfg := &config.AuthzConfig{
		IntrospectionURL: server.URL,
		ClientID:         "gateway",
		ClientSecret:     "secret",
		Timeout:          5 * time.Second,
	}
	client := NewClient(cfg, false, 0)

	_, err := client.IntrospectToken(context.Background(), "token123")
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
}

func TestNewClientCreatesClientWithConfig(t *testing.T) {
	cfg := &config.AuthzConfig{
		IntrospectionURL: "http://keycloak/introspect",
		ClientID:         "gateway",
		ClientSecret:     "secret",
		Timeout:          5 * time.Second,
	}
	client := NewClient(cfg, true, 60*time.Second)
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.config != cfg {
		t.Fatal("expected config to be stored")
	}
	if !client.cacheEnabled {
		t.Fatal("expected cache enabled")
	}
}

func TestIntrospectTokenUsesCacheWhenEnabled(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"active":true,"realm_access":{"roles":["admin"]},"exp":9999999999}`))
	}))
	defer server.Close()

	cfg := &config.AuthzConfig{
		IntrospectionURL: server.URL,
		ClientID:         "gateway",
		ClientSecret:     "secret",
		Timeout:          5 * time.Second,
	}
	client := NewClient(cfg, true, 60*time.Second)

	// First call hits server
	_, err := client.IntrospectToken(context.Background(), "cached-token")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 server call, got %d", callCount)
	}

	// Second call uses cache
	_, err = client.IntrospectToken(context.Background(), "cached-token")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected cache hit, got %d server calls", callCount)
	}
}

func TestIntrospectTokenReturnsErrorOnInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	cfg := &config.AuthzConfig{
		IntrospectionURL: server.URL,
		ClientID:         "gateway",
		ClientSecret:     "secret",
		Timeout:          5 * time.Second,
	}
	client := NewClient(cfg, false, 0)

	_, err := client.IntrospectToken(context.Background(), "token")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
