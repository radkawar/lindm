package devlab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// integrationServerRelease stamps the lindmd binary that native-server
// integration tests drive; release fixtures require a real x.y.z stamp.
const integrationServerRelease = "0.1.0"

// TestIntegration runs the real Keycloak fresh-authorization smoke followed by
// PostgreSQL regressions against private per-test schemas. Native-server
// regressions drive a freshly built, release-stamped lindmd against the
// initialized fixture. Credentials are passed only in-process or in the child
// environment, never command arguments.
//
// fixtureRoot is the checkout owning the running .cache/dev fixture; codeRoot
// is the checkout whose lindmd is built and whose packages are tested. They
// differ when a clean worktree is qualified against the shared fixture.
//
// The fixture lock covers only the preflight. Native-server fixtures acquire it
// themselves while they mutate shared trust material, so holding it across the
// test run would deadlock them.
func TestIntegration(ctx context.Context, fixtureRoot, codeRoot string) (resultErr error) {
	var root string
	var dsn []byte
	if err := locked(ctx, fixtureRoot, func(lockedRoot string) error {
		root = lockedRoot
		dir := FixturePath(root)
		if err := validateFixture(dir); err != nil {
			return err
		}
		if err := databaseReady(ctx, dir); err != nil {
			return fmt.Errorf("integration database is not ready; run make dev-up: %w", err)
		}
		local, err := localFixture(dir)
		if err != nil {
			return err
		}
		if !local {
			if err := checkFreshAuthorization(ctx, root, os.Stdout); err != nil {
				return fmt.Errorf("real fresh-authorization smoke: %w", err)
			}
		}
		dsn, err = os.ReadFile(filepath.Join(dir, "migration-database-url"))
		return err
	}); err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "lindm-integration-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(work)) }()
	server := filepath.Join(work, "lindmd")
	if err := command(ctx, codeRoot, append(os.Environ(), "CGO_ENABLED=0"), "go", "build", "-trimpath", "-ldflags", "-X lindm/internal/agent/buildinfo.Version="+integrationServerRelease, "-o", server, "./cmd/lindmd"); err != nil {
		return fmt.Errorf("build native integration server: %w", err)
	}
	env := make([]string, 0, len(os.Environ())+3)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "LINDM_TEST_DATABASE_URL=") && !strings.HasPrefix(value, "LINDM_NATIVE_SERVER_BINARY=") && !strings.HasPrefix(value, "LINDM_NATIVE_REPOSITORY=") {
			env = append(env, value)
		}
	}
	env = append(env, "LINDM_TEST_DATABASE_URL="+strings.TrimSpace(string(dsn)), "LINDM_NATIVE_SERVER_BINARY="+server, "LINDM_NATIVE_REPOSITORY="+root)
	// The device suite runs six to fifteen minutes under -race against real
	// PostgreSQL, depending on concurrent package and host load; a per-binary
	// deadline near that reports false timeouts. The command deadline is 40m.
	return command(ctx, codeRoot, env, "go", "test", "-race", "-tags=integration", "-count=1", "-timeout=30m", "./internal/...")
}
