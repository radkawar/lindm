package devlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
)

// AirgapAuthorityOptions configures an isolated site server for offline-bundle
// qualification. Every authority is supplied by the station out of band; the
// fixture generates no TUF keys and holds no offline release custody.
type AirgapAuthorityOptions struct {
	// NetworkContainer is an exact Docker container ID whose network namespace
	// (loopback only, no routes) this process already shares. The dedicated
	// PostgreSQL joins it instead of publishing a host port.
	NetworkContainer string
	// ReleaseRoot is the station's authenticated TUF root JSON.
	ReleaseRoot []byte
	// ReleaseOnlineCustody holds only rollout.pem, snapshot.pem and timestamp.pem.
	ReleaseOnlineCustody string
	// OfflineBundles names absolute key files; Directory is replaced by a
	// fixture-owned private directory.
	OfflineBundles *configv1.OfflineBundleConfig
	Advisories     *configv1.AdvisoryConfig
	// BeforeStart runs after migration and owner bootstrap, before serve. The
	// runner executes this fixture's lindmd with the private configuration
	// appended as -config and returns its stdout.
	BeforeStart func(ctx context.Context, run func(ctx context.Context, args ...string) ([]byte, error)) error
}

// OpenAirgapAuthorityFixture opens a local-auth control plane on a dedicated
// tmpfs PostgreSQL inside the caller's network namespace. Its release
// repository starts empty and is initialized only by a verified bundle import.
func OpenAirgapAuthorityFixture(ctx context.Context, repository, binary string, options AirgapAuthorityOptions) (*AuthorityFixture, error) {
	if !loadContainerIDPattern.MatchString(options.NetworkContainer) || len(options.ReleaseRoot) == 0 || options.ReleaseOnlineCustody == "" || options.OfflineBundles == nil || options.BeforeStart == nil {
		return nil, errors.New("air-gap fixture requires a network container, release root, online custody, offline bundle authority and an import hook")
	}
	load := LoadAuthorityOptions{DatabaseStorage: "tmpfs", networkContainer: options.NetworkContainer, airgap: &options}
	if err := load.validate(); err != nil {
		return nil, err
	}
	return openAuthorityFixtureWithOptions(ctx, repository, binary, authorityAirgap, load)
}

// configureAirgap replaces the generated release repository with the station
// authority. Only the three online role keys are copied into server custody.
func (f *AuthorityFixture) configureAirgap(ctx context.Context, cfg *configv1.ServerConfig, material *AgentFixture, options *AirgapAuthorityOptions) error {
	directory := filepath.Join(f.directory, "release-repository")
	online := filepath.Join(f.directory, "release-online-custody")
	bundles := filepath.Join(f.directory, "offline-bundles")
	for _, path := range []string{directory, online, bundles} {
		if err := os.Mkdir(path, 0700); err != nil {
			return err
		}
	}
	for _, name := range []string{"rollout.pem", "snapshot.pem", "timestamp.pem"} {
		key, err := os.ReadFile(filepath.Join(options.ReleaseOnlineCustody, name))
		if err != nil {
			return err
		}
		err = os.WriteFile(filepath.Join(online, name), key, 0600)
		clear(key)
		if err != nil {
			return err
		}
	}
	envelope, err := f.releaseBootstrap(ctx, material, options.ReleaseRoot)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(f.directory, "bootstrap.dsse.json"), envelope, 0600); err != nil {
		return err
	}
	cfg.ReleaseRepository = &configv1.ReleaseRepositoryConfig{Directory: directory, Signing: &configv1.ReleaseRepositorySigning{Directory: online}, VerificationStateDirectory: proto.String(filepath.Join(f.directory, "release-verification"))}
	offline := proto.CloneOf(options.OfflineBundles)
	offline.Directory = bundles
	cfg.OfflineBundles = offline
	cfg.Advisories = proto.CloneOf(options.Advisories)
	return nil
}

// runServerCommand executes one maintained lindmd operator command against
// this fixture's private configuration, inside the same network namespace.
// A failure carries lindmd's own structured error text, never configuration.
func (f *AuthorityFixture) runServerCommand(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	command := exec.CommandContext(ctx, f.binary, append(append([]string{}, args...), "-config", f.configPath())...)
	var stdout bytes.Buffer
	stderr := &tailBuffer{limit: 64 << 10}
	command.Stdout, command.Stderr, command.WaitDelay = &boundedBuffer{buffer: &stdout, limit: 1 << 20}, io.MultiWriter(f.log, stderr), 5*time.Second
	if err := command.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("lindmd %s failed: %s: %w", args[0], commandFailure(stderr.data), err)
	}
	return stdout.Bytes(), nil
}

// commandFailure extracts the final "command failed" error from lindmd's JSON log.
func commandFailure(log []byte) string {
	lines := bytes.Split(bytes.TrimSpace(log), []byte("\n"))
	for index := len(lines) - 1; index >= 0; index-- {
		var entry struct {
			Message string `json:"msg"`
			Error   string `json:"error"`
		}
		if json.Unmarshal(lines[index], &entry) == nil && entry.Message == "command failed" {
			return entry.Error
		}
	}
	return "no structured failure reported"
}

type tailBuffer struct {
	data  []byte
	limit int
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	if len(b.data) > b.limit {
		b.data = append([]byte(nil), b.data[len(b.data)-b.limit:]...)
	}
	return len(p), nil
}

// RunServerCommand is the post-start counterpart of the BeforeStart runner.
func (f *AuthorityFixture) RunServerCommand(ctx context.Context, args ...string) ([]byte, error) {
	if f.closed {
		return nil, errors.New("isolated authority fixture is closed")
	}
	return f.runServerCommand(ctx, args...)
}

type boundedBuffer struct {
	buffer *bytes.Buffer
	limit  int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > b.limit {
		return 0, errors.New("command output exceeded bound")
	}
	return b.buffer.Write(p)
}
