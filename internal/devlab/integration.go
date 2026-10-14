// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"lindm/internal/devlab/project"
)

// integrationServerRelease stamps the lindmd binary that native-server
// integration tests drive; release fixtures require a real x.y.z stamp.
const integrationServerRelease = "0.1.0"

// TestIntegration runs the real Keycloak fresh-authorization smoke followed by
// PostgreSQL regressions against private per-test schemas. Native-server
// regressions drive a freshly built, release-stamped lindmd against the
// initialized fixture. Credentials stay in the owner-only fixture files: the
// child receives only their paths, never a secret in argv or the environment.
//
// fixtureRoot is the checkout owning the running .cache/dev fixture; codeRoot
// is the checkout whose lindmd is built and whose packages are tested. They
// differ when a clean worktree is qualified against the shared fixture.
//
// The fixture lock covers only the preflight. Native-server fixtures acquire it
// themselves while they mutate shared trust material, so holding it across the
// test run would deadlock them.
//
// Each package result is printed as it completes ("[n/total] ok pkg 12.3s"),
// with the output of failing packages, and passed to progress when non-nil.
func TestIntegration(ctx context.Context, fixtureRoot, codeRoot, packages, jsonOutput string, progress func(line string)) (resultErr error) {
	var root string
	if err := locked(ctx, fixtureRoot, func(lockedRoot string) error {
		root = lockedRoot
		dir := FixturePath(root)
		if err := validateFixture(dir); err != nil {
			return err
		}
		if err := databaseReady(ctx, dir); err != nil {
			return fmt.Errorf("integration database is not ready; run make dev-up: %w", err)
		}
		if err := verifyRunningPostgres(ctx, root); err != nil {
			return err
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
		return nil
	}); err != nil {
		return err
	}
	// Native-server regressions need checkout-owned execution/release roots too.
	// Trust validates existing custody and bindings, or creates development-only
	// material for a fresh clone. It takes the fixture lock itself.
	if err := Trust(ctx, root); err != nil {
		return fmt.Errorf("prepare development integration trust: %w", err)
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
		if !strings.HasPrefix(value, "LINDM_TEST_DATABASE_") && !strings.HasPrefix(value, "LINDM_NATIVE_SERVER_BINARY=") && !strings.HasPrefix(value, "LINDM_NATIVE_REPOSITORY=") {
			env = append(env, value)
		}
	}
	env = append(env, "LINDM_TEST_DATABASE_URL_FILE="+filepath.Join(FixturePath(root), "migration-database-url"), "LINDM_TEST_DATABASE_TEMPLATE_CONTAINER="+project.ComposeName(root)+"-postgres-1", "LINDM_NATIVE_SERVER_BINARY="+server, "LINDM_NATIVE_REPOSITORY="+root)
	events := io.Discard
	if jsonOutput != "" {
		file, err := os.OpenFile(jsonOutput, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
		events = file
	}
	// Preserve the per-binary deadline: slower suites need optimization or
	// sharding, not a longer hold of the shared integration fixture.
	return testWithProgress(ctx, codeRoot, env, progress, events, "-race", "-tags=integration", "-count=1", "-timeout=30m", packages)
}

// testEvent is the subset of go test -json (test2json) events used here.
type testEvent struct {
	Action, Package, Test, Output, ImportPath string
	Elapsed                                   float64
}

// maxFailureOutput bounds the output retained per package for failure reports.
const maxFailureOutput = 256 << 10

// testWithProgress runs go test -json and reports package results as they
// complete, printing a failing package's retained output. Cancellation kills
// the whole process group, like command.
func testWithProgress(ctx context.Context, root string, env []string, progress func(string), events io.Writer, args ...string) (resultErr error) {
	total := 0
	list := exec.CommandContext(ctx, "go", "list", "-tags=integration", args[len(args)-1])
	list.Dir, list.Env = root, env
	if listing, err := list.Output(); err == nil {
		total = len(strings.Fields(string(listing)))
	}
	cmd := exec.CommandContext(ctx, "go", append([]string{"test", "-json"}, args...)...)
	cmd.Dir, cmd.Env, cmd.Stderr = root, env, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 5 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	output := map[string]*strings.Builder{}
	done, failed := 0, 0
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	for scanner.Scan() {
		if _, err := fmt.Fprintln(events, scanner.Text()); err != nil {
			// Stop and join the entire process group on recording failure.
			return errors.Join(err, cmd.Cancel(), cmd.Wait())
		}
		var event testEvent
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			fmt.Println(scanner.Text())
			continue
		}
		switch {
		case event.Action == "build-output":
			fmt.Print(event.Output)
		case event.Action == "output":
			buffer := output[event.Package]
			if buffer == nil {
				buffer = new(strings.Builder)
				output[event.Package] = buffer
			}
			if buffer.Len()+len(event.Output) <= maxFailureOutput {
				buffer.WriteString(event.Output)
			}
		case event.Test == "" && (event.Action == "pass" || event.Action == "fail" || event.Action == "skip"):
			done++
			status := map[string]string{"pass": "ok", "fail": "FAIL", "skip": "skip"}[event.Action]
			if event.Action == "fail" {
				failed++
				if buffer := output[event.Package]; buffer != nil {
					fmt.Print(buffer.String())
				}
			}
			delete(output, event.Package)
			line := fmt.Sprintf("[%d/%d] %s %s %.1fs", done, total, status, event.Package, event.Elapsed)
			fmt.Println(line)
			if progress != nil {
				progress(line)
			}
		}
	}
	scanErr := scanner.Err()
	if err := cmd.Wait(); err != nil {
		return errors.Join(fmt.Errorf("go test: %d of %d packages failed: %w", failed, done, err), scanErr)
	}
	return scanErr
}
