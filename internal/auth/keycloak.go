package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/aveiga/archgate/internal/config"
)

// IntrospectionResponse represents the response from Keycloak token introspection
type IntrospectionResponse struct {
	Active       bool              `json:"active"`
	RealmAccess  RealmAccess      `json:"realm_access"`
	ResourceAccess map[string]RealmAccess `json:"resource_access"`
	Username     string           `json:"username"`
	ClientID     string           `json:"client_id"`
	Exp          int64            `json:"exp"`
}

// RealmAccess contains role information
type RealmAccess struct {
	Roles []string `json:"roles"`
}

// CachedToken stores token introspection result with expiration
type CachedToken struct {
	Result     *IntrospectionResponse
	ExpiresAt  time.Time
}

// Client handles Keycloak token introspection with caching
type Client struct {
	config      *config.AuthzConfig
	httpClient  *http.Client
	cache       *sync.Map // map[string]*CachedToken
	cacheEnabled bool
	cacheTTL    time.Duration
}

// NewClient creates a new Keycloak introspection client
func NewClient(cfg *config.AuthzConfig, cacheEnabled bool, cacheTTL time.Duration) *Client {
	// Create HTTP client with connection pooling
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}

	return &Client{
		config:       cfg,
		httpClient:   httpClient,
		cache:        &sync.Map{},
		cacheEnabled: cacheEnabled,
		cacheTTL:     cacheTTL,
	}
}

// IntrospectToken validates a token via Keycloak introspection endpoint
func (c *Client) IntrospectToken(ctx context.Context, token string) (*IntrospectionResponse, error) {
	// Check cache first if enabled
	if c.cacheEnabled {
		if cached, ok := c.cache.Load(token); ok {
			cachedToken := cached.(*CachedToken)
			if time.Now().Before(cachedToken.ExpiresAt) {
				return cachedToken.Result, nil
			}
			// Expired, remove from cache
			c.cache.Delete(token)
		}
	}

	// Prepare introspection request
	data := url.Values{}
	data.Set("token", token)
	data.Set("client_id", c.config.ClientID)
	data.Set("client_secret", c.config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", c.config.IntrospectionURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("introspection failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var result IntrospectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse introspection response: %w", err)
	}

	// Cache the result if enabled and token is active
	if c.cacheEnabled && result.Active {
		// Use token expiration if available, otherwise use configured TTL
		expiresAt := time.Now().Add(c.cacheTTL)
		if result.Exp > 0 {
			tokenExp := time.Unix(result.Exp, 0)
			if tokenExp.Before(expiresAt) {
				expiresAt = tokenExp
			}
		}

		c.cache.Store(token, &CachedToken{
			Result:    &result,
			ExpiresAt: expiresAt,
		})
	}

	return &result, nil
}

// GetAllRoles extracts all roles from the introspection response
func (ir *IntrospectionResponse) GetAllRoles() []string {
	roleSet := make(map[string]bool)
	
	// Add realm roles
	for _, role := range ir.RealmAccess.Roles {
		roleSet[role] = true
	}
	
	// Add resource access roles
	for _, access := range ir.ResourceAccess {
		for _, role := range access.Roles {
			roleSet[role] = true
		}
	}
	
	// Convert to slice
	roles := make([]string, 0, len(roleSet))
	for role := range roleSet {
		roles = append(roles, role)
	}
	
	return roles
}

