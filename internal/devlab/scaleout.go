// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/config"
	"lindm/internal/labexec"
)

// ScaleOutOptions adds one SSH/direct-link replica and optionally one local
// replica to a running disposable load fixture. RemoteBinary must be an absolute
// path to the identical lindmd build. SSH requires existing verified host trust,
// Python 3.11+, and Linux pidfds. Configure pool/profiling before scale-out.
type ScaleOutOptions struct {
	SSHHost          string
	SSHConfig        string
	RemoteBinary     string
	RemoteAddress    string
	RemoteCPUs       string
	LocalReplicaCPUs string
	Replicas         int
}

func (o ScaleOutOptions) validate() error {
	if o.Replicas != 0 && o.Replicas != 2 && o.Replicas != 3 {
		return errors.New("scale-out requires two or three replicas")
	}
	if o.SSHHost == "" || strings.HasPrefix(o.SSHHost, "-") || strings.ContainsAny(o.SSHHost, " \t\r\n\x00") {
		return errors.New("scale-out requires one SSH host, not SSH arguments")
	}
	if !filepath.IsAbs(o.RemoteBinary) || strings.ContainsAny(o.RemoteBinary, "\r\n\x00") {
		return errors.New("scale-out requires an absolute remote lindmd binary path")
	}
	// The DGX direct link is IPv4 link-local (169.254.0.0/16); any specific
	// unicast IPv4 address is admitted, never a wildcard or loopback.
	address, err := netip.ParseAddr(o.RemoteAddress)
	if err != nil || !address.Is4() || address.String() != o.RemoteAddress || !address.IsGlobalUnicast() && !address.IsLinkLocalUnicast() {
		return errors.New("scale-out requires a specific remote direct-link IPv4 address")
	}
	if o.LocalReplicaCPUs != "" && o.Replicas != 3 {
		return errors.New("local replica CPUs require three replicas")
	}
	return errors.Join(validateLoadCPUList(o.RemoteCPUs), validateLoadCPUList(o.LocalReplicaCPUs))
}

// ScaleOutReplica identifies actual processes, not logical pool slots.
type ScaleOutReplica struct {
	Name          string `json:"name"`
	Host          string `json:"host"`
	PID           int    `json:"pid"`
	BinarySHA256  string `json:"binary_sha256"`
	AdminAddress  string `json:"admin_address"`
	DeviceAddress string `json:"device_address"`
	RequestedCPUs string `json:"requested_cpus,omitempty"`
}

// ScaleOutEnvironment contains no keys, credentials or database URLs.
type ScaleOutEnvironment struct {
	Replicas         []ScaleOutReplica `json:"replicas"`
	ProxyContainerID string            `json:"proxy_container_id"`
	ProxyImage       string            `json:"proxy_image"`
	ProxyVersion     string            `json:"proxy_version"`
	BalancerAdmin    string            `json:"balancer_admin"`
	BalancerDevice   string            `json:"balancer_device"`
}

type scaleOutTopology struct {
	options       ScaleOutOptions
	proxy         *haTopology
	localAdmin    string
	remoteDir     string
	token         string
	remoteAttempt bool
	remote        *labexec.Process
	remoteDone    chan error
	remoteInput   *os.File
	third         *haInstance
	environment   ScaleOutEnvironment
	forwards      []string
}

//go:embed scaleout_remote.py
var scaleOutRemoteScript string

// ConfigureScaleOut preserves public origins and listener addresses: replica1
// moves to private backend ports and HAProxy takes over its former listeners.
// No migrations, leader-job overrides or alternate database endpoints are used.
// On startup failure Close retains ownership and retries any failed cleanup.
func (f *AuthorityFixture) ConfigureScaleOut(ctx context.Context, options ScaleOutOptions) (resultErr error) {
	if err := options.validate(); err != nil {
		return err
	}
	if f == nil || f.closed || f.process == nil || f.scaleOut != nil || f.ha != nil || f.persistent || f.connected != nil || f.cluster == nil || f.cluster.storage == nil || f.cluster.listenAddress == "" {
		return errors.New("scale-out requires a running disposable load fixture with an owned direct-bound durable PostgreSQL cluster")
	}
	if options.RemoteAddress == f.cluster.listenAddress {
		return errors.New("scale-out requires a different remote host address")
	}
	document, err := config.Load(f.configPath())
	if err != nil {
		return err
	}
	base := document.Proto
	if base.GetReleaseRepository() != nil || base.GetOfflineBundles() != nil {
		return errors.New("scale-out load fixture does not own replicated repository directories")
	}
	if base.AdminListener.Address != base.DeviceListener.Address {
		return errors.New("scale-out requires one local balancer address")
	}
	if err := validateLoadListenAddress(base.AdminListener.Address); err != nil {
		return err
	}
	digest, err := scaleOutBinaryDigest(f.binary)
	if err != nil {
		return err
	}
	t := &scaleOutTopology{options: options, token: uuid.NewString()}
	t.remoteDir = "/tmp/lindm-scaleout-" + t.token
	directory, err := os.MkdirTemp(f.directory, "scaleout-")
	if err != nil {
		return err
	}
	t.proxy = &haTopology{directory: directory, shared: FixturePath(f.repository), label: "lindm.scaleout.owned=" + t.token,
		lbAdmin: int(base.AdminListener.Port), lbDevice: int(base.DeviceListener.Port),
		proxyBindAddress: base.AdminListener.Address, reservations: make(map[int]net.Listener)}
	// Attach before the first remote resource attempt, including cancellation.
	f.scaleOut = t
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, f.Close())
		}
	}()
	if t.proxy.statsPort, err = t.proxy.reserve(); err != nil {
		return err
	}
	local := proto.CloneOf(base)
	admin, err := t.proxy.reserve()
	if err != nil {
		return err
	}
	device, err := t.proxy.reserve()
	if err != nil {
		return err
	}
	local.AdminListener = &configv1.ListenerConfig{Address: "127.0.0.1", Port: uint32(admin)}
	local.DeviceListener = &configv1.ListenerConfig{Address: "127.0.0.1", Port: uint32(device)}
	t.localAdmin = net.JoinHostPort("127.0.0.1", strconv.Itoa(admin))
	t.environment = ScaleOutEnvironment{ProxyImage: haProxyImage, BalancerAdmin: f.AdminAddress, BalancerDevice: f.DeviceAddress,
		Replicas: []ScaleOutReplica{{Name: "replica1", Host: "local", BinarySHA256: digest, AdminAddress: t.localAdmin,
			DeviceAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(device)), RequestedCPUs: f.serverCPUs}}}
	remoteConfig := proto.CloneOf(base)
	remoteConfig.AdminListener.Address, remoteConfig.DeviceListener.Address = options.RemoteAddress, options.RemoteAddress
	files, err := scaleOutFiles(remoteConfig, f.directory, t.remoteDir)
	if err != nil {
		return err
	}
	defer func() {
		for _, data := range files {
			clear(data)
		}
	}()
	if keycloak := base.GetAuthentication().GetKeycloak(); keycloak != nil {
		issuerURL, err := url.Parse(keycloak.Issuer)
		if err != nil || issuerURL.Hostname() != "localhost" || issuerURL.Port() == "" {
			return errors.New("scale-out requires the maintained localhost Keycloak fixture")
		}
		// Preserve the real issuer and leader-only directory jobs. Failure to
		// reserve this remote loopback port aborts startup; no trust override.
		t.forwards = []string{"-R", "127.0.0.1:" + issuerURL.Port() + ":127.0.0.1:" + issuerURL.Port()}
	}
	payload, err := json.Marshal(struct {
		Files  map[string][]byte `json:"files"`
		Binary string            `json:"binary"`
		Digest string            `json:"digest"`
	}{files, options.RemoteBinary, digest})
	if err != nil {
		return err
	}
	defer clear(payload)
	t.remoteAttempt = true
	output, err := t.remoteCommand(ctx, "prepare", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("prepare remote replica: %w", err)
	}
	var ports struct{ Admin, Device int }
	if err := json.Unmarshal(output, &ports); err != nil || ports.Admin < 1 || ports.Admin > 65535 || ports.Device < 1 || ports.Device > 65535 || ports.Admin == ports.Device {
		return errors.New("remote replica returned invalid listener reservations")
	}
	t.environment.Replicas = append(t.environment.Replicas, ScaleOutReplica{Name: "replica2", Host: options.SSHHost, BinarySHA256: digest,
		AdminAddress: net.JoinHostPort(options.RemoteAddress, strconv.Itoa(ports.Admin)), DeviceAddress: net.JoinHostPort(options.RemoteAddress, strconv.Itoa(ports.Device)), RequestedCPUs: options.RemoteCPUs})
	if err := f.stopLocal(); err != nil {
		return err
	}
	encoded, err := protojson.Marshal(local)
	if err != nil {
		return err
	}
	if err := writePersistentFile(f.configPath(), encoded); err != nil {
		return err
	}
	if err := errors.Join(t.proxy.release(admin), t.proxy.release(device)); err != nil {
		return err
	}
	if err := f.start(ctx); err != nil {
		return err
	}
	t.environment.Replicas[0].PID = f.ProcessID()
	if err := t.startRemote(ctx); err != nil {
		return err
	}
	if err := f.scaleOutReady(ctx, t.environment.Replicas[1].AdminAddress); err != nil {
		return fmt.Errorf("remote replica readiness: %w", err)
	}
	remoteSample, err := t.sampleRemote(ctx)
	if err != nil {
		return err
	}
	t.environment.Replicas[1].PID = remoteSample.PID
	if options.Replicas == 3 {
		if err := f.startThirdReplica(ctx, local, digest); err != nil {
			return err
		}
	}
	for _, replica := range t.environment.Replicas {
		t.proxy.proxyBackends = append(t.proxy.proxyBackends, haProxyBackend{name: replica.Name, admin: replica.AdminAddress, device: replica.DeviceAddress})
	}
	if err := t.proxy.startProxy(ctx); err != nil {
		return err
	}
	if err := pollUntil(ctx, time.Minute, func(ctx context.Context) (bool, error) {
		states, err := t.proxy.serverStates(ctx)
		if err != nil {
			return false, nil
		}
		for _, replica := range t.environment.Replicas {
			if states["admin/"+replica.Name] != "UP" || states["device/"+replica.Name] != "UP" {
				return false, nil
			}
		}
		return true, nil
	}); err != nil {
		return fmt.Errorf("scale-out balancer readiness: %w", err)
	}
	t.environment.ProxyContainerID, t.environment.ProxyVersion = t.proxy.proxyID, t.proxy.proxyVersion
	return f.scaleOutReady(ctx, f.AdminAddress)
}

func scaleOutBinaryDigest(path string) (_ string, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Copy only runtime file references, never a whole fixture or offline CA keys.
// Database trust paths are relocated but its verified direct endpoint is intact.
func scaleOutFiles(cfg *configv1.ServerConfig, source, remote string) (_ map[string][]byte, resultErr error) {
	files := make(map[string][]byte)
	defer func() {
		if resultErr != nil {
			for _, data := range files {
				clear(data)
			}
		}
	}()
	paths := make(map[string]string)
	copyFile := func(path string) (string, error) {
		if !filepath.IsAbs(path) {
			path = filepath.Join(source, path)
		}
		if name, ok := paths[path]; ok {
			return name, nil
		}
		data, err := readOwned(path)
		if err != nil {
			return "", err
		}
		name := fmt.Sprintf("resource-%d", len(paths))
		paths[path], files[name] = name, data
		return name, nil
	}
	var visit func(protoreflect.Message) error
	visit = func(message protoreflect.Message) error {
		var resultErr error
		message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
			if field.IsList() || field.IsMap() {
				return true // Load's repeated feeds and bindings contain no custody files.
			}
			if field.Message() != nil {
				resultErr = visit(value.Message())
			} else if field.Kind() == protoreflect.StringKind && strings.HasSuffix(string(field.Name()), "_file") && value.String() != "" {
				var name string
				name, resultErr = copyFile(value.String())
				if resultErr == nil {
					message.Set(field, protoreflect.ValueOfString(filepath.Join(remote, name)))
				}
			}
			return resultErr == nil
		})
		return resultErr
	}
	if err := visit(cfg.ProtoReflect()); err != nil {
		return nil, err
	}
	for _, path := range []string{cfg.Database.UrlFile, cfg.Database.GetMigrationUrlFile()} {
		if path == "" {
			continue
		}
		name := filepath.Base(path)
		dsn, err := url.Parse(strings.TrimSpace(string(files[name])))
		if err != nil || dsn.Scheme != "postgresql" || dsn.Query().Get("sslmode") != "verify-full" {
			return nil, errors.New("scale-out database must retain verified fixture TLS")
		}
		query := dsn.Query()
		for _, key := range []string{"sslrootcert", "sslcert", "sslkey"} {
			path := query.Get(key)
			if path == "" || strings.HasPrefix(path, remote+"/") {
				continue
			}
			resource, err := copyFile(path)
			if err != nil {
				return nil, err
			}
			query.Set(key, filepath.Join(remote, resource))
		}
		dsn.RawQuery = query.Encode()
		clear(files[name])
		files[name] = []byte(dsn.String())
	}
	encoded, err := protojson.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	files["server.json"] = encoded
	return files, nil
}

func scaleOutQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func (t *scaleOutTopology) sshArgs(operation string) []string {
	args := []string{"-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3", "-o", "ExitOnForwardFailure=yes"}
	if t.options.SSHConfig != "" {
		args = append(args, "-F", t.options.SSHConfig)
	}
	if operation == "run" {
		args = append(args, t.forwards...)
	}
	command := "python3 -c " + scaleOutQuote(scaleOutRemoteScript) + " " + scaleOutQuote(operation) + " " + scaleOutQuote(t.remoteDir) + " " + scaleOutQuote(t.token) + " " + scaleOutQuote(t.options.RemoteCPUs)
	return append(args, "--", t.options.SSHHost, command)
}

func (t *scaleOutTopology) remoteCommand(ctx context.Context, operation string, input io.Reader) ([]byte, error) {
	output, diagnostics := nativeexec.NewBuffer(1<<20), nativeexec.NewBuffer(4<<10)
	err := labexec.Run(ctx, labexec.Command{Path: "ssh", Args: t.sshArgs(operation), Stdin: input, Stdout: output, Stderr: diagnostics, Timeout: time.Minute})
	if err != nil {
		// The supervisor writes only owned paths and Python exceptions here.
		return nil, fmt.Errorf("remote scale-out %s: %w: %s", operation, err, strings.TrimSpace(string(diagnostics.Bytes())))
	}
	if output.Truncated() {
		return nil, errors.New("remote scale-out output exceeded bound")
	}
	return output.Bytes(), nil
}

func (t *scaleOutTopology) startRemote(ctx context.Context) error {
	reader, writer, err := os.Pipe()
	if err != nil {
		return err
	}
	t.remoteInput = writer
	process, startErr := labexec.Start(context.WithoutCancel(ctx), labexec.Command{Path: "ssh", Args: t.sshArgs("run"), Stdin: reader})
	closeErr := reader.Close()
	if startErr != nil {
		return errors.Join(startErr, closeErr)
	}
	t.remote, t.remoteDone = process, make(chan error, 1)
	go func() { t.remoteDone <- process.Wait() }()
	return closeErr
}

func (f *AuthorityFixture) scaleOutReady(ctx context.Context, address string) error {
	tlsConfig, err := f.localTLSConfig()
	if err != nil {
		return err
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return pollUntil(ctx, 45*time.Second, func(ctx context.Context) (bool, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost/readyz", nil)
		if err != nil {
			return false, err
		}
		response, err := client.Do(request)
		if err != nil {
			return false, nil
		}
		closeErr := response.Body.Close()
		return response.StatusCode == http.StatusNoContent && closeErr == nil, nil
	})
}

func (f *AuthorityFixture) startThirdReplica(ctx context.Context, base *configv1.ServerConfig, digest string) error {
	t := f.scaleOut
	admin, err := t.proxy.reserve()
	if err != nil {
		return err
	}
	device, err := t.proxy.reserve()
	if err != nil {
		return err
	}
	cfg := proto.CloneOf(base)
	cfg.AdminListener.Port, cfg.DeviceListener.Port = uint32(admin), uint32(device)
	if cfg.Profiling != nil {
		port, err := t.proxy.reserve()
		if err != nil {
			return err
		}
		cfg.Profiling.Listener.Port = uint32(port)
		if err := t.proxy.release(port); err != nil {
			return err
		}
	}
	encoded, err := protojson.Marshal(cfg)
	if err != nil {
		return err
	}
	instance := &haInstance{name: "replica3", admin: admin, device: device, config: filepath.Join(f.directory, "replica3.json"), binaryDigestByPath: map[string]string{f.binary: digest}}
	t.third = instance
	if err := os.WriteFile(instance.config, encoded, 0600); err != nil {
		return err
	}
	instance.logPath = filepath.Join(f.directory, "replica3.log")
	instance.log, err = os.OpenFile(instance.logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := errors.Join(t.proxy.release(admin), t.proxy.release(device)); err != nil {
		return err
	}
	command, err := newServerCommand(f.binary, instance.config, t.options.LocalReplicaCPUs)
	if err != nil {
		return err
	}
	command.Stdout, command.Stderr = instance.log, instance.log
	process, err := labexec.Start(context.WithoutCancel(ctx), command)
	if err != nil {
		return err
	}
	instance.process, instance.done = process, make(chan error, 1)
	go func() { instance.done <- process.Wait() }()
	replica := ScaleOutReplica{Name: "replica3", Host: "local", PID: process.Pid(), BinarySHA256: digest,
		AdminAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(admin)), DeviceAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(device)), RequestedCPUs: t.options.LocalReplicaCPUs}
	t.environment.Replicas = append(t.environment.Replicas, replica)
	return f.scaleOutReady(ctx, replica.AdminAddress)
}

func (t *scaleOutTopology) stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	var err error
	if t.third != nil {
		err = t.proxy.signalInstance(t.third, syscall.SIGTERM)
	}
	if t.remoteAttempt {
		if _, cleanupErr := t.remoteCommand(ctx, "cleanup", nil); cleanupErr != nil {
			return errors.Join(err, fmt.Errorf("remote scale-out custody retained at %s: %w", t.remoteDir, cleanupErr))
		}
		t.remoteAttempt = false
	}
	if t.remoteInput != nil {
		err = errors.Join(err, t.remoteInput.Close())
		t.remoteInput = nil
	}
	if t.remote != nil {
		select {
		case waitErr := <-t.remoteDone:
			err = errors.Join(err, waitErr)
			t.remote = nil
		case <-ctx.Done():
			t.remote.Signal(syscall.SIGKILL)
			return errors.Join(err, errors.New("remote supervisor cleanup deadline"))
		}
	}
	return err
}

func (t *scaleOutTopology) close() error {
	if t.remoteAttempt || t.remote != nil || t.third != nil && t.third.process != nil {
		return errors.New("scale-out processes remain; retaining owned database and credentials")
	}
	if t.third != nil && t.third.log != nil {
		if err := t.third.log.Close(); err != nil {
			return err
		}
		t.third.log = nil
	}
	return t.proxy.close()
}

func (f *AuthorityFixture) ScaleOutEnvironment() *ScaleOutEnvironment {
	if f == nil || f.scaleOut == nil {
		return nil
	}
	environment := f.scaleOut.environment
	environment.Replicas = append([]ScaleOutReplica(nil), environment.Replicas...)
	return &environment
}
