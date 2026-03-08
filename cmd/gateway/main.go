package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aveiga/archgate/internal/auth"
	"github.com/aveiga/archgate/internal/config"
	"github.com/aveiga/archgate/internal/middleware"
	"github.com/aveiga/archgate/internal/proxy"
	"github.com/aveiga/archgate/internal/router"
)

const defaultRoutesDir = "/routes"

// loadEnvFile reads a .env file and sets variables in the process environment.
// If the file does not exist, it returns without error. Skips empty lines and
// lines starting with #. Handles KEY=value and basic quoted values.
func loadEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		if key == "" {
			continue
		}
		if len(value) >= 2 && (value[0] == '"' && value[len(value)-1] == '"' || value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}
		os.Setenv(key, value)
	}
}

func splitRulesByAuth(rules []config.RouteRule) (publicRules []config.RouteRule, protectedRules []config.RouteRule) {
	for _, rule := range rules {
		if rule.RequiresAuth() {
			protectedRules = append(protectedRules, rule)
			continue
		}
		publicRules = append(publicRules, rule)
	}
	return publicRules, protectedRules
}

func resolveRoutesDir() string {
	routesDir := os.Getenv("ROUTES_DIR_PATH")
	if routesDir == "" {
		return defaultRoutesDir
	}
	return routesDir
}

func main() {
	loadEnvFile(".env")

	// Parse command line flags
	configPath := flag.String("config", "", "Path to configuration file (or set CONFIG_PATH env var)")
	flag.Parse()

	// Use environment variable if flag not provided
	if *configPath == "" {
		*configPath = os.Getenv("CONFIG_PATH")
	}

	if *configPath == "" {
		log.Fatal("Configuration file path required (use -config flag or CONFIG_PATH env var)")
	}

	// Load configuration
	cfg, err := config.LoadWithRoutesDir(*configPath, resolveRoutesDir())
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize components
	keycloakClient := auth.NewClient(&cfg.Authz, cfg.Cache.Enabled, cfg.Cache.TTL)
	routeRouter := router.NewRouter(cfg.Routes)
	authMW := middleware.NewAuthMiddleware(keycloakClient)
	auditMW := middleware.NewAuditMiddleware()

	// Create HTTP handler
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Match route
		matchedRoute, matchingRules := routeRouter.MatchRoute(r)
		if matchedRoute == nil {
			http.Error(w, "Route not found", http.StatusNotFound)
			return
		}

		// Create proxy for this route
		routeProxy, err := proxy.NewProxy(matchedRoute)
		if err != nil {
			log.Printf("Failed to create proxy for route %s: %v", matchedRoute.Name, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Compose middleware chain from matched rules.
		// Public routes skip auth, while protected routes run auth before audit so
		// audit logging can read the authenticated request context.
		var chain http.Handler = auditMW.Handler(routeProxy)

		publicRules, protectedRules := splitRulesByAuth(matchingRules)
		if len(publicRules) == 0 {
			rbacMW := middleware.NewRBACMiddleware(matchedRoute.Name, protectedRules)
			chain = authMW.Handler(auditMW.Handler(rbacMW.Handler(routeProxy)))
		}

		chain.ServeHTTP(w, r)
	})

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      handler,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting API Gateway on port %d", cfg.Server.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown server gracefully
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}
