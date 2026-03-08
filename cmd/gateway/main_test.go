package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aveiga/archgate/internal/config"
)

func boolPtr(v bool) *bool {
	return &v
}

func TestSplitRulesByAuth(t *testing.T) {
	rules := []config.RouteRule{
		{Methods: []string{"GET"}, RequireAuth: boolPtr(false)},
		{Methods: []string{"POST"}},
		{Methods: []string{"DELETE"}, RequireAuth: boolPtr(true)},
	}

	publicRules, protectedRules := splitRulesByAuth(rules)
	if len(publicRules) != 1 {
		t.Fatalf("expected 1 public rule, got %d", len(publicRules))
	}
	if len(protectedRules) != 2 {
		t.Fatalf("expected 2 protected rules, got %d", len(protectedRules))
	}
}

func TestLoadEnvFileSetsVariables(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("TEST_KEY=test_value\n# comment\nANOTHER=val2\n"), 0644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	os.Unsetenv("TEST_KEY")
	os.Unsetenv("ANOTHER")
	defer func() {
		os.Unsetenv("TEST_KEY")
		os.Unsetenv("ANOTHER")
	}()

	loadEnvFile(envPath)

	if os.Getenv("TEST_KEY") != "test_value" {
		t.Errorf("expected TEST_KEY=test_value, got %q", os.Getenv("TEST_KEY"))
	}
	if os.Getenv("ANOTHER") != "val2" {
		t.Errorf("expected ANOTHER=val2, got %q", os.Getenv("ANOTHER"))
	}
}

func TestLoadEnvFileNoErrorWhenMissing(t *testing.T) {
	loadEnvFile("/nonexistent/.env")
	// Should not panic or fail
}

func TestLoadEnvFileStripsQuotes(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte(`QUOTED="value with spaces"`), 0644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	os.Unsetenv("QUOTED")
	defer os.Unsetenv("QUOTED")

	loadEnvFile(envPath)

	if os.Getenv("QUOTED") != "value with spaces" {
		t.Errorf("expected stripped quotes, got %q", os.Getenv("QUOTED"))
	}
}

func TestResolveRoutesDirDefaultsToRoutes(t *testing.T) {
	os.Unsetenv("ROUTES_DIR")

	if got := resolveRoutesDir(); got != defaultRoutesDir {
		t.Fatalf("expected default routes dir %q, got %q", defaultRoutesDir, got)
	}
}

func TestResolveRoutesDirUsesOverride(t *testing.T) {
	os.Setenv("ROUTES_DIR", "/custom-routes")
	defer os.Unsetenv("ROUTES_DIR")

	if got := resolveRoutesDir(); got != "/custom-routes" {
		t.Fatalf("expected ROUTES_DIR override, got %q", got)
	}
}
