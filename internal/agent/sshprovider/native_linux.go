//go:build linux

package sshprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/inventory"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/agent/nativefile"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/custody"
	"lindm/internal/platform"
	"lindm/internal/resource"
)

const sshConfigPath = "/etc/ssh/sshd_config"
const bannerDirective = "# Managed by lindm. Release the SSH profile to restore ownership.\nBanner /etc/issue.net\n"

type commandRunner func(context.Context, string, ...string) ([]byte, error)

func runNative(ctx context.Context, path string, args ...string) ([]byte, error) {
	result, err := nativeexec.Run(ctx, nativeexec.Command{Path: path, Args: args, Timeout: 15 * time.Second, StdoutLimit: 128 << 10, StderrLimit: 32 << 10})
	if err != nil {
		return nil, fmt.Errorf("SSH native %s: %w", filepath.Base(path), err)
	}
	if path == "/usr/sbin/sshd" && len(args) == 1 && args[0] == "-V" {
		return result.Stderr, nil
	}
	return result.Stdout, nil
}

func nativeContext(ctx context.Context, product *resourcev1.PlatformProduct, incarnation string) (*Provider, error) {
	if ctx == nil || os.Geteuid() != 0 || platform.Of(product).Quirks.SSHBannerUnit == "" {
		return nil, ErrUnsupported
	}
	actual, err := inventory.HostPlatform(ctx)
	if err != nil {
		return nil, err
	}
	if !proto.Equal(actual, product) {
		return nil, ErrConflict
	}
	version, err := runNative(ctx, "/usr/sbin/sshd", "-V")
	if err != nil {
		return nil, errors.Join(ErrUnsupported, err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	backend := &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_OPENSSH, NativeVersion: strings.TrimSpace(string(version)), ProviderVersion: "1", Product: proto.CloneOf(product)}
	if err := validateMessage(backend); err != nil {
		return nil, err
	}
	return &Provider{config: Config{Platform: proto.CloneOf(product), ExecutorIncarnation: incarnation}, backend: backend, boot: strings.TrimSpace(string(boot)), unit: platform.Of(product).Quirks.SSHBannerUnit, run: runNative, capture: nativefile.CaptureReadOnly, creation: nativefile.CreationMetadata, witness: bannerWitness, resolve: resolveInclude, glob: globIncludes}, nil
}

func resolveInclude(path string) (string, error) {
	// Protect the source spelling too: checking only EvalSymlinks' result
	// admits an untrusted alias switched just for sshd's reload.
	file, resolved, _, err := custody.OpenResolvedRoot(path, 32<<10, unix.PathMax, 40)
	if err != nil {
		return "", fmt.Errorf("%w: unsafe or unreadable SSH Include: %w", ErrConflict, err)
	}
	return resolved, file.Close()
}

func globIncludes(pattern string) ([]string, error) {
	if !filepath.IsAbs(pattern) || filepath.Clean(pattern) != pattern {
		return nil, fmt.Errorf("%w: non-canonical SSH Include pattern", ErrUnsupported)
	}
	directory := filepath.Dir(pattern)
	if strings.ContainsAny(directory, "*?[\\") {
		return nil, fmt.Errorf("%w: SSH Include directory patterns are not supported", ErrUnsupported)
	}
	// An empty match set is still a dependency: a writable search directory
	// could introduce a temporary include during reload and remove it before
	// the next snapshot. Keep filename globs, but require an existing plain
	// root-protected directory and ancestry, even when nothing matches.
	parent, _, err := custody.OpenRoot(directory, unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return nil, fmt.Errorf("%w: unsafe SSH Include search directory: %w", ErrConflict, err)
	}
	matches, err := filepath.Glob(pattern)
	return matches, errors.Join(err, parent.Close())
}

func receipt(passed bool, evidence []byte, reason string) *resourcev1.ProbeReceipt {
	digest := sha256.Sum256(evidence)
	return &resourcev1.ProbeReceipt{ProbeId: uuid.NewString(), ObservedAt: timestamppb.Now(), Passed: passed, EvidenceSha256: digest[:], Reason: reason}
}

func digestMessage(m proto.Message) ([]byte, error) {
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	return digest[:], nil
}

func fileState(capture *agentv1.ResourceOwnershipSnapshot, continuity *agentv1.NativeFileContinuity) *agentv1.SSHNativeFileSnapshot {
	return &agentv1.SSHNativeFileSnapshot{State: capture.GetObservation().GetManagedFile(), Content: capture.ManagedFileContent, Xattrs: capture.ManagedFileXattrs, Continuity: continuity}
}

func (p *Provider) snapshot(ctx context.Context) (*agentv1.ResourceOwnershipSnapshot, error) {
	if p.config.ObserveNative != nil {
		return p.config.ObserveNative(ctx)
	}
	observation := &resourcev1.ResourceObservation{Ref: sshRef(), Metadata: &resourcev1.ObservationMetadata{BootId: p.boot, ExecutorIncarnation: p.config.ExecutorIncarnation, ObservedAt: timestamppb.Now(), Backend: proto.CloneOf(p.backend), NativeRevision: make([]byte, 32), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}}
	directive, directiveContinuity, err := nativefile.CaptureWithContinuity(resource.SSHBannerDirectivePath, observation)
	if err != nil {
		return nil, err
	}
	banner, bannerContinuity, err := nativefile.CaptureWithContinuity(resource.SSHBannerPath, observation)
	if err != nil {
		return nil, err
	}
	graph, edges, err := p.includeGraph(observation)
	if err != nil {
		return nil, err
	}
	syntax, err := p.run(ctx, "/usr/sbin/sshd", "-t", "-f", sshConfigPath)
	if err != nil {
		return nil, errors.Join(ErrConflict, err)
	}
	effective, err := p.run(ctx, "/usr/sbin/sshd", "-T", "-f", sshConfigPath, "-C", "user=lindm-banner-probe,host=localhost,addr=127.0.0.1")
	if err != nil {
		return nil, err
	}
	port, bannerPath, err := parseEffective(effective)
	if err != nil {
		return nil, err
	}
	active, err := p.run(ctx, "/usr/bin/systemctl", "is-active", p.unit)
	if err != nil || strings.TrimSpace(string(active)) != "active" {
		return nil, errors.Join(ErrConflict, err)
	}
	connection, received, err := p.witness(ctx, port, observation)
	if err != nil {
		return nil, err
	}
	public := &resourcev1.SSHServerObservation{Includes: edges, IncludeGraphSha256: graph, EffectiveConfigurationSha256: sum(effective), Effective: &resourcev1.SSHServerDesired{Port: proto.Uint32(port)}, ServiceUnit: p.unit, BannerPath: bannerPath, BannerFile: banner.GetObservation().GetManagedFile(), DirectiveFile: directive.GetObservation().GetManagedFile(), Syntax: receipt(true, syntax, "sshd -t"), Connection: connection, ReceivedBannerSha256: sum(received)}
	observation.Observed = &resourcev1.ResourceObservation_SshServer{SshServer: public}
	revision := sha256.New()
	for _, part := range [][]byte{graph, sum(effective), directive.GetObservation().GetMetadata().GetNativeRevision(), banner.GetObservation().GetMetadata().GetNativeRevision(), directiveContinuity.GetInodeGenerationSha256(), directiveContinuity.GetAncestryGenerationSha256(), bannerContinuity.GetInodeGenerationSha256(), bannerContinuity.GetAncestryGenerationSha256()} {
		revision.Write(part)
	}
	observation.Metadata.NativeRevision = revision.Sum(nil)
	result := &agentv1.ResourceOwnershipSnapshot{Observation: observation, SshServer: &agentv1.SSHServerOwnership{Directive: fileState(directive, directiveContinuity), Banner: fileState(banner, bannerContinuity)}}
	if err := validateMessage(result); err != nil {
		return nil, err
	}
	if err := resource.ValidateObservation(observation); err != nil {
		return nil, err
	}
	return result, nil
}

func sum(data []byte) []byte { digest := sha256.Sum256(data); return digest[:] }

func parseEffective(data []byte) (uint32, string, error) {
	var port uint64
	var banner string
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "port":
			if port != 0 {
				return 0, "", fmt.Errorf("%w: multiple SSH listeners", ErrUnsupported)
			}
			var err error
			port, err = strconv.ParseUint(fields[1], 10, 16)
			if err != nil || port == 0 {
				return 0, "", ErrUnsupported
			}
		case "banner":
			banner = fields[1]
		}
	}
	if port == 0 || banner == "" {
		return 0, "", ErrUnsupported
	}
	if banner != "none" && banner != resource.SSHBannerPath {
		return 0, "", fmt.Errorf("%w: foreign Banner directive", ErrConflict)
	}
	return uint32(port), banner, nil
}

// includeGraph follows every Include, including inactive Match blocks. A Banner
// anywhere outside the owned drop-in is a collision: a synthetic Match context
// cannot establish that some other user's login would not override it.
func (p *Provider) includeGraph(template *resourcev1.ResourceObservation) ([]byte, []*resourcev1.SSHIncludeEdge, error) {
	hash := sha256.New()
	var edges []*resourcev1.SSHIncludeEdge
	visiting := map[string]bool{}
	global, included, count := true, false, 0
	var visit func(string) error
	visit = func(path string) error {
		count++
		if count > 128 || visiting[path] {
			return ErrUnsupported
		}
		if path == resource.SSHBannerDirectivePath {
			if !global {
				return fmt.Errorf("%w: banner Include is inside Match", ErrConflict)
			}
			included = true
		}
		visiting[path] = true
		defer delete(visiting, path)
		resolved, err := p.resolve(path)
		if errors.Is(err, os.ErrNotExist) && path == resource.SSHBannerDirectivePath {
			return nil
		}
		if err != nil {
			return err
		}
		capture, err := p.capture(resolved, template)
		if err != nil {
			return fmt.Errorf("inspect SSH include %s: %w", path, err)
		}
		if !capture.GetObservation().GetManagedFile().GetExists() {
			return ErrConflict
		}
		hash.Write([]byte(path + "\x00" + resolved + "\x00"))
		hash.Write(capture.GetObservation().GetMetadata().GetNativeRevision())
		for line := range strings.SplitSeq(string(capture.GetManagedFileContent()), "\n") {
			key, values, err := configLine(line)
			if err != nil {
				return err
			}
			switch key {
			case "banner":
				if path != resource.SSHBannerDirectivePath || !global {
					return fmt.Errorf("%w: non-global or foreign Banner in %s", ErrConflict, path)
				}
			case "match":
				global = false
			case "include":
				for _, pattern := range values {
					if !filepath.IsAbs(pattern) {
						pattern = "/etc/ssh/" + pattern
					}
					matches, err := p.glob(pattern)
					if err != nil {
						return err
					}
					// Include the future drop-in's sorted position when absent,
					// so an earlier Match cannot turn a global notice conditional.
					admits, err := filepath.Match(pattern, resource.SSHBannerDirectivePath)
					if err != nil {
						return err
					}
					synthetic := admits && !slices.Contains(matches, resource.SSHBannerDirectivePath)
					if synthetic {
						matches = append(matches, resource.SSHBannerDirectivePath)
						slices.Sort(matches)
					}
					for _, target := range matches {
						if !synthetic || target != resource.SSHBannerDirectivePath {
							if len(edges) == 128 {
								return ErrUnsupported
							}
							edges = append(edges, &resourcev1.SSHIncludeEdge{Source: path, Target: target, Precedence: uint32(len(edges))})
						}
						if err := visit(target); err != nil {
							return err
						}
					}
				}
			}
		}
		return nil
	}
	if err := visit(sshConfigPath); err != nil {
		return nil, nil, err
	}
	if !included {
		return nil, nil, fmt.Errorf("%w: global sshd drop-in Include missing", ErrUnsupported)
	}
	return hash.Sum(nil), edges, nil
}

// OpenSSH keywords accept whitespace or '='. Include paths with escapes or
// whitespace are deliberately unsupported rather than interpreted differently
// from sshd. Other directives are left to sshd's own parser.
func configLine(line string) (string, []string, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil, nil
	}
	if strings.ContainsAny(strings.Fields(line)[0], "\\\"'") {
		return "", nil, ErrUnsupported
	}
	end := strings.IndexAny(line, " \t=")
	if end < 0 {
		if strings.EqualFold(line, "include") {
			return "", nil, ErrUnsupported
		}
		return strings.ToLower(line), nil, nil
	}
	key := strings.ToLower(line[:end])
	if key != "include" {
		return key, nil, nil
	}
	value := strings.TrimSpace(strings.TrimLeft(line[end:], " \t="))
	value, _, _ = strings.Cut(value, "#")
	var paths []string
	for _, path := range strings.Fields(value) {
		if strings.HasPrefix(path, "\"") || strings.HasSuffix(path, "\"") {
			if len(path) < 2 || !strings.HasPrefix(path, "\"") || !strings.HasSuffix(path, "\"") {
				return "", nil, ErrUnsupported
			}
			path = path[1 : len(path)-1]
		}
		if path == "" || strings.ContainsAny(path, "\\\"'") {
			return "", nil, ErrUnsupported
		}
		paths = append(paths, path)
	}
	if len(paths) == 0 {
		return "", nil, ErrUnsupported
	}
	return key, paths, nil
}

// bannerWitness opens a new loopback SSH connection, pins the installed host
// public key, and receives the actual pre-authentication message. It never
// submits a password/key or creates an account. Auth failure is expected; lack
// of a completed transport/userauth exchange is not success.
func bannerWitness(ctx context.Context, port uint32, template *resourcev1.ResourceObservation) (*resourcev1.ProbeReceipt, []byte, error) {
	keyFile, err := nativefile.Capture("/etc/ssh/ssh_host_ed25519_key.pub", template)
	if err != nil {
		return nil, nil, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(keyFile.GetManagedFileContent())
	if err != nil {
		return nil, nil, err
	}
	address := net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(port), 10))
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, nil, err
	}
	var banner []byte
	verified := false
	config := &ssh.ClientConfig{User: "lindm-banner-probe", HostKeyAlgorithms: []string{key.Type()}, HostKeyCallback: func(host string, remote net.Addr, actual ssh.PublicKey) error {
		if err := ssh.FixedHostKey(key)(host, remote, actual); err != nil {
			return err
		}
		verified = true
		return nil
	}, BannerCallback: func(message string) error {
		if len(message) > 32768 {
			return ErrUnsupported
		}
		banner = []byte(message)
		return nil
	}}
	client, _, _, err := ssh.NewClientConn(conn, address, config)
	if client != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("%w: unauthenticated account accepted", ErrConflict)
	}
	// x/crypto's client exposes the completed userauth rejection as this error.
	// A transport disconnect, timeout or host-key rejection is never accepted.
	if !verified || err == nil || !strings.Contains(err.Error(), "unable to authenticate, attempted methods [none]") {
		return nil, nil, fmt.Errorf("SSH banner witness: %w", err)
	}
	evidence := append(bytes.Clone(key.Marshal()), banner...)
	return receipt(true, evidence, "fresh host-key-verified SSH userauth exchange"), banner, nil
}

// ObserveNative runs in the read-only helper with network access, not in the
// resident executor's isolated network namespace.
func ObserveNative(ctx context.Context, _ resourceprovider.NativeEnv, request *agentv1.NativeResourceObservationRequest) (result *agentv1.ResourceOwnershipSnapshot, err error) {
	if err := validateDesired(request.GetDesired()); err != nil {
		return nil, err
	}
	p, err := nativeContext(ctx, request.GetPlatform(), request.GetExecutorIncarnation())
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, p.Close()) }()
	return p.snapshot(ctx)
}
