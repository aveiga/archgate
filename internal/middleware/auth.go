package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/aveiga/archgate/internal/auth"
)

type contextKey string

const (
	// TokenClaimsKey is the context key for storing token introspection result
	TokenClaimsKey contextKey = "token_claims"
)

// AuthMiddleware handles JWT token extraction and validation
type AuthMiddleware struct {
	keycloakClient *auth.Client
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(keycloakClient *auth.Client) *AuthMiddleware {
	return &AuthMiddleware{
		keycloakClient: keycloakClient,
	}
}

// Handler returns an HTTP handler that validates tokens
func (m *AuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		token := extractToken(r)
		if token == "" {
			http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}

		// Introspect token via Keycloak
		introspectionResult, err := m.keycloakClient.IntrospectToken(r.Context(), token)
		if err != nil {
			http.Error(w, "Token validation failed: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Check if token is active
		if !introspectionResult.Active {
			http.Error(w, "Token is not active", http.StatusUnauthorized)
			return
		}

		// Store token claims in context
		ctx := context.WithValue(r.Context(), TokenClaimsKey, introspectionResult)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractToken extracts the Bearer token from the Authorization header
func extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	// Check for Bearer token format
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return parts[1]
}

// GetTokenClaims retrieves token claims from request context
func GetTokenClaims(r *http.Request) *auth.IntrospectionResponse {
	claims, ok := r.Context().Value(TokenClaimsKey).(*auth.IntrospectionResponse)
	if !ok {
		return nil
	}
	return claims
}

