package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Skip logging for certain paths (health checks, static files, etc.)
var skipPaths = []string{
	"/health",
	"/ping",
	"/favicon.ico",
	"/audit-logs", // Prevent infinite logging loops
}

// Skip logging for certain methods
var skipMethods = []string{"OPTIONS"}

// responseWriter wraps http.ResponseWriter to capture response data
type responseWriter struct {
	http.ResponseWriter
	statusCode    int
	body          *bytes.Buffer
	headerWritten bool
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK, // Default status code
		body:           &bytes.Buffer{},
	}
}

func (rw *responseWriter) Header() http.Header {
	return rw.ResponseWriter.Header()
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.headerWritten {
		rw.statusCode = code
		rw.headerWritten = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.headerWritten {
		rw.WriteHeader(http.StatusOK)
	}
	rw.body.Write(b)
	return rw.ResponseWriter.Write(b)
}

// AuditLogEntry represents the audit log structure
type AuditLogEntry struct {
	Type           string              `json:"type"`
	Timestamp      string              `json:"timestamp"`
	Method         string              `json:"method"`
	URL            string              `json:"url"`
	Path           string              `json:"path"`
	Query          map[string][]string `json:"query"`
	Headers        map[string]string   `json:"headers"`
	Body           interface{}         `json:"body"`
	UserAgent      string              `json:"userAgent"`
	IPAddress      string              `json:"ipAddress"`
	UserID         *string             `json:"userId"`
	UserName       *string             `json:"userName"`
	Roles          []string            `json:"roles"`
	ResponseStatus int                 `json:"responseStatus"`
	ResponseTime   int64               `json:"responseTime"`
	RequestSize    int64               `json:"requestSize"`
	ResponseSize   int64               `json:"responseSize"`
	Error          *string             `json:"error"`
}

// AuditMiddleware handles audit logging for all requests
type AuditMiddleware struct{}

// NewAuditMiddleware creates a new audit logging middleware
func NewAuditMiddleware() *AuditMiddleware {
	return &AuditMiddleware{}
}

// Handler returns an HTTP handler that logs all requests and responses
func (m *AuditMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		// Skip logging for certain paths and methods
		if shouldSkipLogging(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Capture request body
		var requestBody interface{}
		var requestSize int64
		if r.Body != nil {
			bodyBytes, err := io.ReadAll(r.Body)
			if err == nil {
				requestSize = int64(len(bodyBytes))
				// Restore body for downstream handlers
				r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

				// Try to parse as JSON, otherwise keep as string
				var jsonBody interface{}
				if err := json.Unmarshal(bodyBytes, &jsonBody); err == nil {
					requestBody = sanitizeBody(jsonBody)
				} else if len(bodyBytes) > 0 {
					// If not JSON, store as string (truncated if too long)
					bodyStr := string(bodyBytes)
					if len(bodyStr) > 1000 {
						bodyStr = bodyStr[:1000] + "..."
					}
					requestBody = bodyStr
				}
			}
		}

		// Extract request data
		requestData := AuditLogEntry{
			Timestamp:   startTime.UTC().Format(time.RFC3339),
			Method:      r.Method,
			URL:         r.URL.String(),
			Path:        r.URL.Path,
			Query:       r.URL.Query(),
			Headers:     sanitizeHeaders(r.Header),
			Body:        requestBody,
			UserAgent:   r.UserAgent(),
			IPAddress:   getClientIP(r),
			RequestSize: requestSize,
		}

		// Extract user information from token claims if available
		claims := GetTokenClaims(r)
		if claims != nil {
			if claims.Username != "" {
				requestData.UserID = &claims.Username
				requestData.UserName = &claims.Username
			}
			roles := claims.GetAllRoles()
			if len(roles) > 0 {
				requestData.Roles = roles
			}
		}

		// Wrap response writer to capture response
		rw := newResponseWriter(w)

		// Call next handler
		next.ServeHTTP(rw, r)

		// Calculate response time
		endTime := time.Now()
		responseTime := endTime.Sub(startTime).Milliseconds()

		// Capture response data
		responseSize := int64(rw.body.Len())
		if contentLength := rw.Header().Get("Content-Length"); contentLength != "" {
			if size, err := parseInt64(contentLength); err == nil {
				responseSize = size
			}
		}

		// Build complete audit log entry
		auditData := requestData
		auditData.Type = "audit_log"
		auditData.ResponseStatus = rw.statusCode
		auditData.ResponseTime = responseTime
		auditData.ResponseSize = responseSize

		// Set error if status code indicates error
		if rw.statusCode >= 400 {
			errorMsg := fmt.Sprintf("HTTP %d", rw.statusCode)
			auditData.Error = &errorMsg
		}

		// Set null fields explicitly
		if auditData.UserID == nil {
			auditData.UserID = nil
		}
		if auditData.UserName == nil {
			auditData.UserName = nil
		}
		if len(auditData.Roles) == 0 {
			auditData.Roles = nil
		}

		// Log to stdout in JSON format
		logJSON, err := json.Marshal(auditData)
		if err != nil {
			// Fallback: log error message if JSON marshaling fails
			fmt.Printf(`{"type":"audit_log_error","error":"failed to marshal audit log: %s"}`+"\n", err.Error())
		} else {
			fmt.Println(string(logJSON))
		}
	})
}

// shouldSkipLogging checks if the request should be skipped
func shouldSkipLogging(r *http.Request) bool {
	path := r.URL.Path
	method := r.Method

	// Check skip paths
	for _, skipPath := range skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}

	// Check skip methods
	for _, skipMethod := range skipMethods {
		if method == skipMethod {
			return true
		}
	}

	return false
}

// sanitizeHeaders removes sensitive headers
func sanitizeHeaders(headers http.Header) map[string]string {
	sanitized := make(map[string]string)
	sensitiveHeaders := map[string]bool{
		"authorization": true,
		"cookie":        true,
		"x-api-key":     true,
	}

	for key, values := range headers {
		lowerKey := strings.ToLower(key)
		if lowerKey == "referer" {
			if referer := sanitizeReferer(values); referer != "" {
				sanitized[key] = referer
			}
			continue
		}
		if !sensitiveHeaders[lowerKey] {
			// Join multiple values with comma
			sanitized[key] = strings.Join(values, ", ")
		}
	}

	return sanitized
}

func sanitizeReferer(values []string) string {
	if len(values) == 0 {
		return ""
	}

	parsed, err := url.Parse(values[0])
	if err != nil {
		return ""
	}

	return parsed.Hostname()
}

// sanitizeBody redacts sensitive fields from request/response body
func sanitizeBody(body interface{}) interface{} {
	if body == nil {
		return nil
	}

	bodyMap, ok := body.(map[string]interface{})
	if !ok {
		return body
	}

	sanitized := make(map[string]interface{})
	sensitiveFields := []string{"password", "token", "secret", "key", "auth"}

	for key, value := range bodyMap {
		lowerKey := strings.ToLower(key)
		isSensitive := false
		for _, sensitiveField := range sensitiveFields {
			if strings.Contains(lowerKey, sensitiveField) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			sanitized[key] = "[REDACTED]"
		} else {
			// Recursively sanitize nested objects
			if nestedMap, ok := value.(map[string]interface{}); ok {
				sanitized[key] = sanitizeBody(nestedMap)
			} else {
				sanitized[key] = value
			}
		}
	}

	return sanitized
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	if r.RemoteAddr != "" {
		// RemoteAddr is typically "IP:port", extract just the IP
		host, _, found := strings.Cut(r.RemoteAddr, ":")
		if found {
			return host
		}
		return r.RemoteAddr
	}

	return "unknown"
}

// parseInt64 parses a string to int64
func parseInt64(s string) (int64, error) {
	var result int64
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}
