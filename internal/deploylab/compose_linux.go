// SPDX-License-Identifier: Apache-2.0

// Package deploylab owns isolated single-host deployment proofs. It never uses
// or resets shared devlab services, stores production credentials, or qualifies
// local browser/WebAuthn authentication merely from an HTTPS readiness probe.
package deploylab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
)

// ComposeResult contains only nonsecret observations of this disposable run.
// Cleaned means the owned containers, network, volume, image tag and fixture
// files were removed, not that any shared Docker cache was purged.
type ComposeResult struct {
	Project                  string    `json:"project"`
	StartedAt                time.Time `json:"started_at"`
	ImageID                  string    `json:"image_id,omitempty"`
	BinarySHA256             string    `json:"binary_sha256,omitempty"`
	DockerVersion            string    `json:"docker_version"`
	ComposeVersion           string    `json:"compose_version"`
	CgroupVersion            string    `json:"cgroup_version"`
	ExplicitMigration        bool      `json:"explicit_migration"`
	OwnerBootstrapped        bool      `json:"owner_bootstrapped"`
	HTTPSHealth              bool      `json:"https_health"`
	HTTPSReady               bool      `json:"https_ready"`
	EmbeddedConsole          bool      `json:"embedded_console"`
	ProtectedRPCDenied       bool      `json:"protected_rpc_denied"`
	RuntimeIsolationVerified bool      `json:"runtime_isolation_verified"`
	DatabaseTLSAndRoles      bool      `json:"database_tls_and_roles"`
	Cleaned                  bool      `json:"cleaned"`
	Passed                   bool      `json:"passed"`
}

type composeRun struct {
	root    string
	project string
	image   string
	env     []string
}

// RunCompose builds the executable with the checkout's already-built embedded
// console and the pinned minimal image, then exercises the production manifest
// against newly created LOCAL fixtures. It requires Linux, Go, built web assets
// and a local Docker daemon with Compose v2. Subprocess output stays private:
// bootstrap-owner emits a one-time enrollment secret, even on this lab path.
func RunCompose(ctx context.Context, repo string) (result ComposeResult, err error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	root, err := filepath.Abs(repo)
	if err != nil {
		return result, err
	}
	dir, err := os.MkdirTemp("", "lindm-compose-")
	if err != nil {
		return result, err
	}
	project := "lindm-proof-" + uuid.NewString()
	run := &composeRun{root: root, project: project, image: project + ":proof"}
	result.Project, result.StartedAt = project, time.Now().UTC()
	uid, gid := os.Geteuid(), os.Getegid()
	if uid == 0 {
		uid, gid = 65532, 65532
	}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "PG") || strings.HasPrefix(name, "LINDM_") || strings.HasPrefix(name, "COMPOSE_") {
			continue
		}
		run.env = append(run.env, entry)
	}
	run.env = append(run.env,
		"COMPOSE_DISABLE_ENV_FILE=1", "LINDM_CONFIG_DIR="+dir,
		"LINDM_IMAGE="+run.image, "LINDM_UID="+strconv.Itoa(uid), "LINDM_GID="+strconv.Itoa(gid),
		"LINDM_BIND_IP=127.0.0.1", "LINDM_OWNER=owner", "CGO_ENABLED=0", "GOOS=linux", "GOTOOLCHAIN=go1.26.9",
		"GOARCH="+runtime.GOARCH,
	)
	var imageBuilt, composeStarted bool
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer stop()
		var cleanupErr error
		if composeStarted {
			cleanupErr = run.compose(cleanup, "remove owned compose project", nil, "down", "--volumes", "--remove-orphans", "--timeout", "40")
		}
		if cleanupErr == nil && imageBuilt {
			cleanupErr = run.command(cleanup, "remove owned image tag", nil, "docker", "image", "rm", run.image)
		}
		if cleanupErr == nil {
			cleanupErr = os.RemoveAll(dir)
		}
		result.Cleaned = cleanupErr == nil
		if cleanupErr != nil {
			cleanupErr = fmt.Errorf("cleanup project %s; protected fixture retained at %s: %w", project, dir, cleanupErr)
		}
		err = errors.Join(err, cleanupErr)
		result.Passed = err == nil
	}()
	var listen net.ListenConfig
	admin, err := listen.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return result, err
	}
	adminOpen := true
	defer func() {
		if adminOpen {
			err = errors.Join(err, admin.Close())
		}
	}()
	device, err := listen.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return result, err
	}
	deviceOpen := true
	defer func() {
		if deviceOpen {
			err = errors.Join(err, device.Close())
		}
	}()
	_, adminPort, err := net.SplitHostPort(admin.Addr().String())
	if err != nil {
		return result, err
	}
	_, devicePort, err := net.SplitHostPort(device.Addr().String())
	if err != nil {
		return result, err
	}
	port, err := strconv.Atoi(adminPort)
	if err != nil {
		return result, err
	}
	run.env = append(run.env, "LINDM_ADMIN_PORT="+adminPort, "LINDM_DEVICE_PORT="+devicePort)
	ca, err := writeFixture(dir, port, uid, gid)
	if err != nil {
		return result, err
	}
	version := newCommandOutput()
	if err := run.compose(ctx, "check Compose prerequisite", version, "version", "--short"); err != nil {
		return result, err
	}
	result.ComposeVersion = strings.TrimSpace(version.String())
	version = newCommandOutput()
	if err := run.command(ctx, "record Docker engine", version, "docker", "version", "--format", "{{.Server.Version}}"); err != nil {
		return result, err
	}
	result.DockerVersion = strings.TrimSpace(version.String())
	version = newCommandOutput()
	if err := run.command(ctx, "check cgroup v2 isolation", version, "docker", "info", "--format", "{{.CgroupVersion}}"); err != nil {
		return result, err
	}
	result.CgroupVersion = strings.TrimSpace(version.String())
	if result.CgroupVersion != "2" {
		return result, errors.New("server deployment requires cgroup v2 for swap isolation")
	}
	buildDir := filepath.Join(dir, "image")
	if err := os.Mkdir(buildDir, 0700); err != nil {
		return result, err
	}
	binary := filepath.Join(buildDir, "lindmd")
	if err := run.command(ctx, "build static Linux lindmd", nil, "go", "build", "-trimpath", "-o", binary, "./cmd/lindmd"); err != nil {
		return result, err
	}
	result.BinarySHA256, err = fileSHA256(binary)
	if err != nil {
		return result, err
	}
	if err := run.command(ctx, "build pinned distroless image", nil, "docker", "build", "--file", filepath.Join(root, "deploy", "server", "Dockerfile"), "--tag", run.image, buildDir); err != nil {
		return result, err
	}
	imageBuilt = true
	imageID := newCommandOutput()
	if err := run.command(ctx, "record image identity", imageID, "docker", "image", "inspect", "--format", "{{.Id}}", run.image); err != nil {
		return result, err
	}
	result.ImageID = strings.TrimSpace(imageID.String())
	composeStarted = true
	if err := run.compose(ctx, "start isolated TLS database", nil, "up", "--detach", "--wait", "--wait-timeout", "150", "postgres"); err != nil {
		return result, err
	}
	if err := run.compose(ctx, "explicit database migration", nil, "run", "--rm", "--no-deps", "-T", "migrate"); err != nil {
		return result, err
	}
	result.ExplicitMigration = true
	if err := run.compose(ctx, "restrict runtime migration metadata", nil, "exec", "-T", "--user", "postgres", "postgres", "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "lindm", "-c", RestrictRuntimeMigrationMetadataSQL); err != nil {
		return result, err
	}
	if err := run.compose(ctx, "bootstrap LOCAL owner once", nil, "run", "--rm", "--no-deps", "-T", "bootstrap"); err != nil {
		return result, err
	}
	result.OwnerBootstrapped = true
	adminOpen, deviceOpen = false, false
	if err := errors.Join(admin.Close(), device.Close()); err != nil {
		return result, err
	}
	if err := run.compose(ctx, "start nonroot server", nil, "up", "--detach", "--no-deps", "lindmd"); err != nil {
		return result, err
	}
	if err := proveHTTPS(ctx, "https://localhost:"+adminPort, ca, &result); err != nil {
		return result, err
	}
	if err := run.proveIsolation(ctx, uid, gid); err != nil {
		return result, err
	}
	result.RuntimeIsolationVerified = true
	if err := run.proveDatabase(ctx); err != nil {
		return result, err
	}
	result.DatabaseTLSAndRoles = true
	return result, nil
}

func (r *composeRun) compose(ctx context.Context, stage string, output *nativeexec.Buffer, args ...string) error {
	base := []string{"compose", "--env-file", "/dev/null", "--project-name", r.project, "--file", filepath.Join(r.root, "deploy", "server", "compose.yml")}
	return r.command(ctx, stage, output, "docker", append(base, args...)...)
}

// newCommandOutput bounds a captured deployment command's stdout.
func newCommandOutput() *nativeexec.Buffer { return nativeexec.NewBuffer(64 << 10) }

// command discards stderr and captures stdout only into output, if any.
func (r *composeRun) command(ctx context.Context, stage string, output *nativeexec.Buffer, name string, args ...string) error {
	c := labexec.Command{Path: name, Args: args, Env: r.env, Dir: r.root}
	if output != nil {
		c.Stdout = output
	}
	err := labexec.Run(ctx, c)
	if err == nil && output != nil && output.Truncated() {
		err = errors.New("deployment command output exceeds 64 KiB")
	}
	if err != nil {
		return fmt.Errorf("deploylab %s (subprocess output withheld to protect credentials): %w", stage, err)
	}
	return nil
}

func fileSHA256(path string) (_ string, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
