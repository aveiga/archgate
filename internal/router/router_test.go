package router

import (
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/aveiga/archgate/internal/config"
)

func TestMatchRouteProtectedUsesRuleMethods(t *testing.T) {
	r := NewRouter([]config.RouteConfig{
		{
			Name:            "users",
			PathPattern:     "^/api/users(/.*)?$",
			CompiledPattern: regexp.MustCompile(`(?i)^/api/users(/.*)?$`),
			Upstream:        "http://users:8080",
			Rules: []config.RouteRule{
				{Methods: []string{"GET"}, RequiredRoles: []string{"reader"}, RequireAllRoles: true},
				{Methods: []string{"POST"}, RequiredRoles: []string{"writer"}, RequireAllRoles: true},
			},
		},
	})

	req := httptest.NewRequest("POST", "/api/users", nil)
	route, rules := r.MatchRoute(req)
	if route == nil {
		t.Fatal("expected route to match")
	}
	if len(rules) != 1 || len(rules[0].RequiredRoles) != 1 || rules[0].RequiredRoles[0] != "writer" {
		t.Fatalf("unexpected matching rules: %+v", rules)
	}
}

func TestMatchRoutePublicUsesRuleMethods(t *testing.T) {
	r := NewRouter([]config.RouteConfig{
		{
			Name:            "health",
			PathPattern:     "^/health$",
			CompiledPattern: regexp.MustCompile(`(?i)^/health$`),
			Rules: []config.RouteRule{
				{Methods: []string{"GET"}, RequireAuth: boolPtr(false)},
			},
			Upstream: "http://health:8080",
		},
	})

	req := httptest.NewRequest("GET", "/health", nil)
	route, rules := r.MatchRoute(req)
	if route == nil {
		t.Fatal("expected public route to match")
	}
	if len(rules) != 1 {
		t.Fatalf("expected one matching rule for public route, got: %+v", rules)
	}

	req = httptest.NewRequest("POST", "/health", nil)
	route, _ = r.MatchRoute(req)
	if route != nil {
		t.Fatal("expected POST /health to be rejected by rule methods filter")
	}
}

func TestMatchRouteReturnsNilWhenNoMatch(t *testing.T) {
	r := NewRouter([]config.RouteConfig{
		{
			Name:            "users",
			PathPattern:     "^/api/users(/.*)?$",
			CompiledPattern: regexp.MustCompile(`(?i)^/api/users(/.*)?$`),
			Upstream:        "http://users:8080",
			Rules: []config.RouteRule{
				{Methods: []string{"GET"}, RequiredRoles: []string{"reader"}, RequireAllRoles: true},
			},
		},
	})

	req := httptest.NewRequest("GET", "/api/other", nil)
	route, rules := r.MatchRoute(req)
	if route != nil || rules != nil {
		t.Fatalf("expected no match for wrong path, got route=%v rules=%v", route, rules)
	}
}

func TestMatchRouteReturnsNilWhenMethodNotAllowed(t *testing.T) {
	r := NewRouter([]config.RouteConfig{
		{
			Name:            "health",
			PathPattern:     "^/health$",
			CompiledPattern: regexp.MustCompile(`(?i)^/health$`),
			Rules: []config.RouteRule{
				{Methods: []string{"GET"}, RequireAuth: boolPtr(false)},
			},
			Upstream: "http://health:8080",
		},
	})

	req := httptest.NewRequest("PUT", "/health", nil)
	route, rules := r.MatchRoute(req)
	if route != nil || rules != nil {
		t.Fatalf("expected no match for PUT when only GET allowed, got route=%v", route)
	}
}

func TestMatchRouteCaseInsensitivePath(t *testing.T) {
	r := NewRouter([]config.RouteConfig{
		{
			Name:            "health",
			PathPattern:     "^/health$",
			CompiledPattern: regexp.MustCompile(`(?i)^/health$`),
			Rules: []config.RouteRule{
				{Methods: []string{"GET"}, RequireAuth: boolPtr(false)},
			},
			Upstream: "http://health:8080",
		},
	})

	req := httptest.NewRequest("GET", "/HEALTH", nil)
	route, rules := r.MatchRoute(req)
	if route == nil || len(rules) != 1 {
		t.Fatalf("expected match for case-insensitive path, got route=%v rules=%v", route, rules)
	}
}

func boolPtr(v bool) *bool {
	return &v
}
