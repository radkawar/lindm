// Package devlab provisions real, loopback-only development dependencies.
// Explicit disposable authority fixtures may start an isolated lindmd; no
// development authorization bypasses are imported into the server.
package devlab

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Init creates a protected fixture atomically, or validates the existing one.
// It does not contact Docker or alter an existing fixture.
func Init(ctx context.Context, repoRoot, authentication string) error {
	return locked(ctx, repoRoot, func(root string) error { return initialize(root, authentication) })
}

// Up starts real dependencies, waits for authenticated TLS readiness, then runs
// the server's explicit migrate command. Keycloak bootstraps the fixed owner;
// local enrollment is an explicit one-shot operator command.
func Up(ctx context.Context, repoRoot, authentication string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	return locked(ctx, repoRoot, func(root string) error {
		if err := initialize(root, authentication); err != nil {
			return err
		}
		services := []string{"up", "--detach", "postgres"}
		if authentication == "keycloak" {
			services = append(services, "keycloak")
		}
		if err := compose(ctx, root, services...); err != nil {
			return err
		}
		dir := FixturePath(root)
		if err := awaitReady(ctx, dir); err != nil {
			return err
		}
		return migrateAndBootstrap(ctx, root, authentication == "local")
	})
}

func migrateAndBootstrap(ctx context.Context, root string, local bool) error {
	dir := FixturePath(root)
	config := filepath.Join(dir, "server.json")
	if err := command(ctx, root, nil, "go", "run", "./cmd/lindmd", "migrate", "-config", config); err != nil {
		return err
	}
	if err := restrictMigrationMetadata(ctx, dir); err != nil {
		return fmt.Errorf("restrict runtime migration metadata access: %w", err)
	}
	if local {
		_, err := fmt.Fprintf(os.Stdout, "Claim the local owner once: go run ./cmd/lindmd bootstrap-owner -config %s -username owner\n", config)
		return err
	}
	return command(ctx, root, nil, "go", "run", "./cmd/lindmd", "bootstrap-owner", "-config", config, "-issuer", issuer, "-subject", ownerSubject)
}

// Check inspects existing services using actual runtime and directory logins;
// it neither starts services nor creates files other than the lifecycle lock.
func Check(ctx context.Context, repoRoot string) error {
	return locked(ctx, repoRoot, func(root string) error {
		dir := FixturePath(root)
		if err := validateFixture(dir); err != nil {
			return err
		}
		return awaitReady(ctx, dir)
	})
}

// Down stops only this checkout's Compose project, preserving all data.
func Down(ctx context.Context, repoRoot string) error {
	return locked(ctx, repoRoot, func(root string) error { return compose(ctx, root, "down") })
}

// Reset destroys this checkout's dependency volumes and fixture. The caller
// must obtain explicit destructive consent; the CLI requires -confirm-delete.
func Reset(ctx context.Context, repoRoot string) error {
	return locked(ctx, repoRoot, func(root string) error {
		dir := FixturePath(root)
		if _, err := os.Lstat(dir); err == nil {
			m, err := readManifest(dir)
			if err != nil {
				return fmt.Errorf("refusing to remove an unrecognized fixture: %w", err)
			}
			if m.Directory != dir || m.Version < 1 || m.Version > fixtureVersion {
				return fmt.Errorf("refusing to remove a fixture not owned by this checkout/version")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := compose(ctx, root, "down", "--volumes"); err != nil {
			return err
		}
		return os.RemoveAll(dir)
	})
}

// ProjectName isolates Docker resources belonging to different checkouts.
func ProjectName(repoRoot string) string {
	digest := sha256.Sum256([]byte(repoRoot))
	return fmt.Sprintf("lindm-dev-%x", digest[:6])
}

func locked(ctx context.Context, repoRoot string, operation func(string) error) (err error) {
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		return err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	info, err := os.Stat(filepath.Join(root, "deploy", "dev", "compose.yml"))
	if err != nil {
		return fmt.Errorf("repository development Compose file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("development Compose file is not regular")
	}
	cache := filepath.Join(root, ".cache")
	if err := os.Mkdir(cache, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err = os.Lstat(cache)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("%s must be an owned directory without group/other write permissions", cache)
	}
	lockPath := filepath.Join(cache, "dev.lock")
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	defer func() { err = errors.Join(err, lock.Close()) }()
	if err := protected(lockPath, false); err != nil {
		return err
	}
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	defer func() { err = errors.Join(err, syscall.Flock(fd, syscall.LOCK_UN)) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	return operation(root)
}

func compose(ctx context.Context, root string, args ...string) error {
	env := make([]string, 0, len(os.Environ())+2)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "LINDM_DEV_DIR=") && !strings.HasPrefix(value, "LINDM_DEV_UID=") {
			env = append(env, value)
		}
	}
	env = append(env, "LINDM_DEV_DIR="+FixturePath(root), "LINDM_DEV_UID="+strconv.Itoa(os.Geteuid()))
	base := []string{"compose", "--project-name", ProjectName(root), "--file", filepath.Join(root, "deploy", "dev", "compose.yml")}
	return command(ctx, root, env, "docker", append(base, args...)...)
}

func command(ctx context.Context, root string, env []string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir, cmd.Env = root, env
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	// go run and Compose may spawn children. Cancellation must not leave a
	// migration/bootstrap process running after its caller has reported failure.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s failed: %w", name, strings.Join(args, " "), err)
	}
	return nil
}
