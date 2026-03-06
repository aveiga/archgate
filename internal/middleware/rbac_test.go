package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aveiga/archgate/internal/auth"
	"github.com/aveiga/archgate/internal/config"
)

func requestWithRoles(roles []string) *http.Request {
	req := httptest.NewRequest("GET", "/api/users", nil)
	claims := &auth.IntrospectionResponse{
		Active:      true,
		RealmAccess: auth.RealmAccess{Roles: roles},
	}
	ctx := context.WithValue(req.Context(), TokenClaimsKey, claims)
	return req.WithContext(ctx)
}

func TestRBACAllowsWhenAnyRuleMatches(t *testing.T) {
	mw := NewRBACMiddleware("users", []config.RouteRule{
		{Methods: []string{"GET"}, RequiredRoles: []string{"admin"}, RequireAllRoles: true},
		{Methods: []string{"GET"}, RequiredRoles: []string{"editor"}, RequireAllRoles: true},
	})

	rec := httptest.NewRecorder()
	nextCalled := false
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(rec, requestWithRoles([]string{"editor"}))

	if !nextCalled || rec.Code != http.StatusNoContent {
		t.Fatalf("expected request to pass, status=%d nextCalled=%v", rec.Code, nextCalled)
	}
}

func TestRBACDeniesWhenNoRuleMatches(t *testing.T) {
	mw := NewRBACMiddleware("users", []config.RouteRule{
		{Methods: []string{"GET"}, RequiredRoles: []string{"admin"}, RequireAllRoles: true},
		{Methods: []string{"GET"}, RequiredRoles: []string{"editor"}, RequireAllRoles: true},
	})

	rec := httptest.NewRecorder()
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(rec, requestWithRoles([]string{"viewer"}))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rec.Code)
	}
}

func TestRBACRequiresAuthenticatedClaims(t *testing.T) {
	mw := NewRBACMiddleware("users", []config.RouteRule{
		{Methods: []string{"GET"}, RequiredRoles: []string{"admin"}, RequireAllRoles: true},
	})

	rec := httptest.NewRecorder()
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest("GET", "/api/users", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestRBACAllowsWhenRequireAllRolesAndUserHasAll(t *testing.T) {
	mw := NewRBACMiddleware("users", []config.RouteRule{
		{Methods: []string{"GET"}, RequiredRoles: []string{"admin", "editor"}, RequireAllRoles: true},
	})

	rec := httptest.NewRecorder()
	nextCalled := false
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(rec, requestWithRoles([]string{"admin", "editor", "viewer"}))

	if !nextCalled || rec.Code != http.StatusNoContent {
		t.Fatalf("expected request to pass when user has all roles, status=%d nextCalled=%v", rec.Code, nextCalled)
	}
}

func TestRBACDeniesWhenRequireAllRolesAndUserMissingOne(t *testing.T) {
	mw := NewRBACMiddleware("users", []config.RouteRule{
		{Methods: []string{"GET"}, RequiredRoles: []string{"admin", "editor"}, RequireAllRoles: true},
	})

	rec := httptest.NewRecorder()
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(rec, requestWithRoles([]string{"admin"}))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 when missing required role, got %d", rec.Code)
	}
}

func TestRBACAllowsEmptyRequiredRoles(t *testing.T) {
	mw := NewRBACMiddleware("users", []config.RouteRule{
		{Methods: []string{"GET"}, RequiredRoles: []string{}, RequireAllRoles: true},
	})

	rec := httptest.NewRecorder()
	nextCalled := false
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(rec, requestWithRoles([]string{"any"}))

	if !nextCalled || rec.Code != http.StatusNoContent {
		t.Fatalf("expected request to pass with empty required roles, status=%d nextCalled=%v", rec.Code, nextCalled)
	}
}

func TestRBACAllowsWhenRequireAllFalseAndUserHasAnyRole(t *testing.T) {
	mw := NewRBACMiddleware("users", []config.RouteRule{
		{Methods: []string{"GET"}, RequiredRoles: []string{"admin", "editor"}, RequireAllRoles: false},
	})

	rec := httptest.NewRecorder()
	nextCalled := false
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(rec, requestWithRoles([]string{"editor"}))

	if !nextCalled || rec.Code != http.StatusNoContent {
		t.Fatalf("expected OR logic to allow when user has one role, status=%d nextCalled=%v", rec.Code, nextCalled)
	}
}

func TestRBACDeniesWhenRequireAllFalseAndUserHasNone(t *testing.T) {
	mw := NewRBACMiddleware("users", []config.RouteRule{
		{Methods: []string{"GET"}, RequiredRoles: []string{"admin", "editor"}, RequireAllRoles: false},
	})

	rec := httptest.NewRecorder()
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(rec, requestWithRoles([]string{"viewer"}))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when user has no required roles, got %d", rec.Code)
	}
}
