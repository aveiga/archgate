package router

import (
	"net/http"
	"strings"

	"github.com/aveiga/archgate/internal/config"
)

// Router matches incoming requests against configured routes
type Router struct {
	routes []*config.RouteConfig
}

// NewRouter creates a new router with the given routes
func NewRouter(routes []config.RouteConfig) *Router {
	// Convert slice of values to slice of pointers for efficient access
	routePtrs := make([]*config.RouteConfig, len(routes))
	for i := range routes {
		routePtrs[i] = &routes[i]
	}

	return &Router{
		routes: routePtrs,
	}
}

// MatchRoute finds the first route that matches request path and method.
// It returns the route and all method-matching rules for downstream auth decisions.
func (r *Router) MatchRoute(req *http.Request) (*config.RouteConfig, []config.RouteRule) {
	path := req.URL.Path
	method := strings.ToUpper(req.Method)

	for _, route := range r.routes {
		// Check if path matches regex pattern (case-insensitive matching via compiled pattern)
		if !route.CompiledPattern.MatchString(path) {
			continue
		}

		var matchingRules []config.RouteRule
		for _, rule := range route.Rules {
			if methodMatches(rule.Methods, method) {
				matchingRules = append(matchingRules, rule)
			}
		}
		if len(matchingRules) == 0 {
			continue
		}

		return route, matchingRules
	}

	return nil, nil
}

func methodMatches(allowed []string, method string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, m := range allowed {
		if m == method {
			return true
		}
	}
	return false
}
