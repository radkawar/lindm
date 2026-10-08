package devlab

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TestIntegration runs the real Keycloak fresh-authorization smoke followed by
// PostgreSQL regressions against private per-test schemas. Credentials are passed
// only in-process or in the child environment, never command arguments.
func TestIntegration(ctx context.Context, repoRoot string) error {
	return locked(ctx, repoRoot, func(root string) error {
		dir := FixturePath(root)
		if err := validateFixture(dir); err != nil {
			return err
		}
		if err := databaseReady(ctx, dir); err != nil {
			return fmt.Errorf("integration database is not ready; run make dev-up: %w", err)
		}
		if err := checkFreshAuthorization(ctx, root, os.Stdout); err != nil {
			return fmt.Errorf("real fresh-authorization smoke: %w", err)
		}
		dsn, err := os.ReadFile(filepath.Join(dir, "migration-database-url"))
		if err != nil {
			return err
		}
		env := make([]string, 0, len(os.Environ())+1)
		for _, value := range os.Environ() {
			if !strings.HasPrefix(value, "LINDM_TEST_DATABASE_URL=") {
				env = append(env, value)
			}
		}
		env = append(env, "LINDM_TEST_DATABASE_URL="+strings.TrimSpace(string(dsn)))
		return command(ctx, root, env, "go", "test", "-race", "-tags=integration", "-count=1", "-timeout=3m", "./internal/...")
	})
}
