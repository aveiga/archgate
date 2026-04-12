package proxy

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/aveiga/archgate/internal/config"
	"github.com/aveiga/archgate/internal/middleware"
)

const trustedUsernameHeader = "X-Username"

// Proxy handles reverse proxying to upstream services
type Proxy struct {
	proxy *httputil.ReverseProxy
	route *config.RouteConfig
}

// NewProxy creates a new reverse proxy for the given route
func NewProxy(route *config.RouteConfig) (*Proxy, error) {
	upstreamURL, err := url.Parse(route.Upstream)
	if err != nil {
		return nil, err
	}

	// Create reverse proxy
	reverseProxy := httputil.NewSingleHostReverseProxy(upstreamURL)

	// Configure transport with connection pooling
	reverseProxy.Transport = &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	// Customize director for path rewriting and header forwarding
	originalDirector := reverseProxy.Director
	reverseProxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Path rewriting: strip prefix if configured
		if route.StripPrefix != "" {
			originalPath := req.URL.Path
			if strings.HasPrefix(originalPath, route.StripPrefix) {
				newPath := strings.TrimPrefix(originalPath, route.StripPrefix)
				if newPath == "" {
					newPath = "/"
				}
				req.URL.Path = newPath
			}
		}

		// Forward relevant headers
		forwardHeaders(req)
	}

	return &Proxy{
		proxy: reverseProxy,
		route: route,
	}, nil
}

// ServeHTTP handles the proxy request
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.proxy.ServeHTTP(w, r)
}

// forwardHeaders forwards relevant headers from the original request
func forwardHeaders(req *http.Request) {
	// Forward X-Forwarded-* headers
	if req.Header.Get("X-Forwarded-For") == "" {
		if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil && clientIP != "" {
			// Only set if we successfully extracted IP (without port)
			req.Header.Set("X-Forwarded-For", clientIP)
		} else if req.RemoteAddr != "" {
			// Fallback: if SplitHostPort fails, try using RemoteAddr as-is
			// This handles cases where RemoteAddr might already be just an IP
			req.Header.Set("X-Forwarded-For", req.RemoteAddr)
		}
	}

	if req.Header.Get("X-Forwarded-Proto") == "" {
		if req.TLS != nil {
			req.Header.Set("X-Forwarded-Proto", "https")
		} else {
			req.Header.Set("X-Forwarded-Proto", "http")
		}
	}

	if req.Header.Get("X-Forwarded-Host") == "" {
		req.Header.Set("X-Forwarded-Host", req.Host)
	}

	// Only forward identity asserted by the gateway itself.
	req.Header.Del(trustedUsernameHeader)

	if claims := middleware.GetTokenClaims(req); claims != nil && claims.Username != "" {
		req.Header.Set(trustedUsernameHeader, claims.Username)
	}
}
