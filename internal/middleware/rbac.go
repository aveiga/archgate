package middleware

import (
	"log"
	"net/http"

	"github.com/aveiga/archgate/internal/config"
)

// RBACMiddleware checks if the authenticated user has the required roles
type RBACMiddleware struct {
	routeName string
	rules     []config.RouteRule
}

// NewRBACMiddleware creates a new RBAC middleware for a specific route.
func NewRBACMiddleware(routeName string, rules []config.RouteRule) *RBACMiddleware {
	return &RBACMiddleware{
		routeName: routeName,
		rules:     rules,
	}
}

// Handler returns an HTTP handler that checks role permissions
func (m *RBACMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get token claims from context
		claims := GetTokenClaims(r)
		if claims == nil {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		// Get all roles from token
		userRoles := claims.GetAllRoles()

		// OR semantics across rules: user is authorized when at least one rule passes.
		for _, rule := range m.rules {
			if m.checkRoles(userRoles, rule.RequiredRoles, rule.RequireAllRoles) {
				next.ServeHTTP(w, r)
				return
			}
		}

		log.Printf("Insufficient permissions for route %s", m.routeName)
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
	})
}

// checkRoles verifies if user roles satisfy the required roles
// If requireAll is true, user must have ALL required roles (AND logic)
// If requireAll is false, user must have ANY required role (OR logic)
func (m *RBACMiddleware) checkRoles(userRoles []string, requiredRoles []string, requireAll bool) bool {
	if len(requiredRoles) == 0 {
		return true
	}

	// Create a map for O(1) lookup
	roleMap := make(map[string]bool)
	for _, role := range userRoles {
		roleMap[role] = true
	}

	if requireAll {
		// AND logic: user must have all required roles
		for _, required := range requiredRoles {
			if !roleMap[required] {
				return false
			}
		}
		return true
	}

	// OR logic: user must have at least one required role
	for _, required := range requiredRoles {
		if roleMap[required] {
			return true
		}
	}
	return false
}
