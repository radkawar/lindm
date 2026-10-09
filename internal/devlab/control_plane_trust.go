package devlab

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
)

// AuthorityFixture owns a real lindmd process and a disposable PostgreSQL database.
// Shared development trust and IdP resources are read-only. Logical origins stay
// pinned: only the private owner's dialer and guest reverse tunnels are rerouted.
// The development offline keys are never part of this server's configuration.
type AuthorityFixture struct {
	AdminAddress  string
	DeviceAddress string
	DatabaseName  string
	repository    string
	binary        string
	directory     string
	database      *authorityDatabase
	log           *os.File
	process       *exec.Cmd
	done          chan error
	closed        bool
}

func OpenAuthorityFixture(ctx context.Context, repository, binary string) (_ *AuthorityFixture, resultErr error) {
	root, err := filepath.Abs(repository)
	if err != nil {
		return nil, err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return nil, errors.New("control-plane trust requires an executable prebuilt lindmd binary")
	}
	material, err := ReadAgentFixture(ctx, root)
	if err != nil {
		return nil, err
	}
	shared := FixturePath(root)
	document, err := config.Load(filepath.Join(shared, "server.json"))
	if err != nil {
		return nil, err
	}
	f := &AuthorityFixture{repository: root, binary: binary}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, f.Close())
		}
	}()
	f.directory, err = os.MkdirTemp("", "lindm-authority-")
	if err != nil {
		return nil, err
	}
	f.log, err = os.OpenFile(filepath.Join(f.directory, "server.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	dsnBytes, err := os.ReadFile(filepath.Join(shared, "migration-database-url"))
	if err != nil {
		return nil, err
	}
	defer clear(dsnBytes)
	dsn, err := url.Parse(strings.TrimSpace(string(dsnBytes)))
	if err != nil || dsn.Scheme != "postgresql" {
		return nil, errors.New("invalid development migration database URL")
	}
	setup, cancel := context.WithTimeout(ctx, 2*time.Minute)
	f.database, err = newAuthorityDatabase(setup, document, shared)
	cancel()
	if err != nil {
		return nil, err
	}
	f.DatabaseName = f.database.name
	dsn.Path, dsn.RawPath = "/"+f.DatabaseName, ""
	for name, data := range map[string][]byte{
		"database-url": []byte(dsn.String()), "execution-root.json": material.ExecutionRootJSON,
		"bootstrap.dsse.json": material.BootstrapEnvelope,
	} {
		if err := os.WriteFile(filepath.Join(f.directory, name), data, 0600); err != nil {
			return nil, err
		}
	}
	admin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer func() {
		if admin != nil {
			resultErr = errors.Join(resultErr, admin.Close())
		}
	}()
	device, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer func() {
		if device != nil {
			resultErr = errors.Join(resultErr, device.Close())
		}
	}()
	f.AdminAddress, f.DeviceAddress = admin.Addr().String(), device.Addr().String()
	adminAddress, adminOK := admin.Addr().(*net.TCPAddr)
	deviceAddress, deviceOK := device.Addr().(*net.TCPAddr)
	if !adminOK || !deviceOK {
		return nil, errors.New("isolated authority listeners did not reserve TCP addresses")
	}
	cfg := proto.CloneOf(document.Proto)
	cfg.AdminListener = &configv1.ListenerConfig{Address: "127.0.0.1", Port: uint32(adminAddress.Port)}
	cfg.DeviceListener = &configv1.ListenerConfig{Address: "127.0.0.1", Port: uint32(deviceAddress.Port)}
	cfg.Database = &configv1.DatabaseConfig{UrlFile: "database-url", MigrationUrlFile: proto.String("database-url"), MaxConnections: 8}
	cfg.Tls.CertificateFile = filepath.Join(shared, "server.crt")
	cfg.Tls.PrivateKeyFile = filepath.Join(shared, "server.key")
	cfg.DeviceCa.CertificateFile = filepath.Join(shared, "device-ca.crt")
	cfg.DeviceCa.PrivateKeyFile = filepath.Join(shared, "device-ca.key")
	cfg.Oidc.ClientSecretFile = filepath.Join(shared, "console-secret")
	cfg.Oidc.DirectoryClientSecretFile = filepath.Join(shared, "directory-secret")
	cfg.TrustedCaFile = filepath.Join(shared, "transport-ca.crt")
	cfg.DevicePublicUrl = proto.String("https://localhost:18445")
	cfg.ExecutionBootstrap = &configv1.ExecutionBootstrapConfig{RootFile: "execution-root.json", BootstrapFile: "bootstrap.dsse.json"}
	encoded, err := protojson.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(f.configPath(), encoded, 0600); err != nil {
		return nil, err
	}
	privateDocument, err := config.Load(f.configPath())
	if err != nil {
		return nil, err
	}
	resolved, err := privateDocument.Resolve()
	if err != nil {
		return nil, fmt.Errorf("resolve isolated authority server: %w", err)
	}
	resolved.HTTPClient.CloseIdleConnections()
	migration, migrationCancel := context.WithTimeout(ctx, time.Minute)
	migrate := exec.CommandContext(migration, f.binary, "migrate", "-config", f.configPath())
	migrate.Stdout, migrate.Stderr, migrate.WaitDelay = f.log, f.log, 5*time.Second
	err = migrate.Run()
	migrationCancel()
	if err != nil {
		return nil, errors.New("migrate isolated authority database failed")
	}
	bootstrap, stop := context.WithTimeout(ctx, time.Minute)
	cmd := exec.CommandContext(bootstrap, f.binary, "bootstrap-owner", "-config", f.configPath(), "-issuer", issuer, "-subject", ownerSubject)
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = f.log, f.log, 5*time.Second
	err = cmd.Run()
	stop()
	if err != nil {
		return nil, errors.New("bootstrap owner in isolated authority database failed")
	}
	err = errors.Join(admin.Close(), device.Close())
	admin, device = nil, nil
	if err != nil {
		return nil, err
	}
	if err := f.start(ctx); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *AuthorityFixture) configPath() string { return filepath.Join(f.directory, "server.json") }

func (f *AuthorityFixture) OpenOwnerSession(ctx context.Context) (*OwnerSession, error) {
	if f.closed {
		return nil, errors.New("isolated authority fixture is closed")
	}
	return openOwnerSession(ctx, f.repository, f.AdminAddress)
}

func (f *AuthorityFixture) start(ctx context.Context) error {
	if f.closed || f.process != nil {
		return errors.New("isolated authority process lifecycle conflict")
	}
	cmd := exec.Command(f.binary, "serve", "-config", f.configPath())
	cmd.Stdout, cmd.Stderr = f.log, f.log
	if err := cmd.Start(); err != nil {
		return errors.New("start isolated lindmd failed")
	}
	f.process, f.done = cmd, make(chan error, 1)
	done := f.done
	go func() { done <- cmd.Wait() }()
	tlsConfig, err := trustClient(FixturePath(f.repository))
	if err != nil {
		return err
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DialContext: ownerDialContext(f.AdminAddress), ResponseHeaderTimeout: 3 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ready, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-f.done:
			f.process, f.done = nil, nil
			return errors.New("isolated lindmd exited before readiness")
		default:
		}
		req, err := http.NewRequestWithContext(ready, http.MethodGet, consoleOrigin+"/readyz", nil)
		if err != nil {
			return err
		}
		response, err := client.Do(req)
		if err == nil {
			closeErr := response.Body.Close()
			if response.StatusCode == http.StatusNoContent && closeErr == nil {
				return nil
			}
		}
		select {
		case <-ready.Done():
			return fmt.Errorf("isolated lindmd readiness: %w", ready.Err())
		case <-ticker.C:
		}
	}
}

func (f *AuthorityFixture) stop() error {
	if f.process == nil {
		return nil
	}
	process, done := f.process, f.done
	err := process.Process.Signal(syscall.SIGTERM)
	if err != nil && !errors.Is(err, os.ErrProcessDone) {
		_ = process.Process.Kill()
	}
	select {
	case waitErr := <-done:
		f.process, f.done = nil, nil
		return waitErr
	case <-time.After(15 * time.Second):
		_ = process.Process.Kill()
		select {
		case <-done:
			f.process, f.done = nil, nil
			return errors.New("isolated lindmd required forced shutdown")
		case <-time.After(5 * time.Second):
			return errors.New("isolated lindmd cleanup deadline")
		}
	}
}

// Restart preserves the exact private database, config and listener addresses.
func (f *AuthorityFixture) Restart(ctx context.Context) error {
	if f.closed {
		return errors.New("isolated authority fixture is closed")
	}
	if err := f.stop(); err != nil {
		return err
	}
	return f.start(ctx)
}

func (f *AuthorityFixture) Close() error {
	if f.closed && f.process == nil {
		return nil
	}
	f.closed = true
	err := f.stop()
	if f.process != nil {
		// Never drop a database or unlink credentials still used by a live child.
		return errors.Join(err, fmt.Errorf("isolated lindmd has not exited; owned database %s and resources %s retained", f.DatabaseName, f.directory))
	}
	if f.database != nil {
		err = errors.Join(err, f.database.Close())
	}
	if f.log != nil {
		err = errors.Join(err, f.log.Close())
	}
	if f.directory != "" {
		err = errors.Join(err, os.RemoveAll(f.directory))
	}
	return err
}
