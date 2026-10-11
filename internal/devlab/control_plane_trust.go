package devlab

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
	"lindm/internal/labexec"
	"lindm/internal/releaseupdate"
)

// AuthorityFixture owns a real lindmd process and a disposable PostgreSQL database.
// Shared development trust and IdP resources are read-only. Ordinary native lanes
// keep pinned logical origins; browser and action lanes sign their allocated ports.
// The development offline keys are never part of this server's configuration.
type AuthorityFixture struct {
	AdminAddress  string
	DeviceAddress string
	ConsoleOrigin string
	// DeviceOrigin is the signed bootstrap bundle's device origin; guests reach
	// DeviceAddress through this origin's loopback port.
	DeviceOrigin     string
	DatabaseName     string
	repository       string
	binary           string
	directory        string
	database         *authorityDatabase
	cluster          *loadPostgres
	environment      LoadExperimentEnvironment
	serverCPUs       string
	processPID       atomic.Int64
	log              *os.File
	process          *labexec.Process
	done             chan error
	closed           bool
	local            *localAuthority
	releasePublisher *releaseupdate.Publisher
	ha               *haTopology
	demo             *consoleDemoOrigin
}

type authorityFixtureMode uint8

const (
	authorityKeycloak authorityFixtureMode = iota
	authorityKeycloakConsole
	authorityLocal
	authorityLocalConsole
	authorityDeviceActions
	authorityReleaseUpdates
	authorityHA
	authorityAirgap
)

func OpenAuthorityFixture(ctx context.Context, repository, binary string) (_ *AuthorityFixture, resultErr error) {
	return OpenLoadAuthorityFixture(ctx, repository, binary, LoadAuthorityOptions{})
}

// OpenConsoleAuthorityFixture reserves the normal development admin origin for
// an interactive disposable run. It never evicts another listener on that port.
func OpenConsoleAuthorityFixture(ctx context.Context, repository, binary string) (*AuthorityFixture, error) {
	return openAuthorityFixture(ctx, repository, binary, authorityKeycloakConsole)
}

func openAuthorityFixture(ctx context.Context, repository, binary string, mode authorityFixtureMode) (_ *AuthorityFixture, resultErr error) {
	return openAuthorityFixtureWithOptions(ctx, repository, binary, mode, LoadAuthorityOptions{})
}

func openAuthorityFixtureWithOptions(ctx context.Context, repository, binary string, mode authorityFixtureMode, options LoadAuthorityOptions) (_ *AuthorityFixture, resultErr error) {
	local := mode == authorityLocal || mode == authorityLocalConsole || mode == authorityDeviceActions || mode == authorityReleaseUpdates || mode == authorityHA || mode == authorityAirgap
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
	material, err := ReadPublicAgentFixture(ctx, root)
	if err != nil {
		return nil, err
	}
	shared := FixturePath(root)
	f := &AuthorityFixture{
		repository: root, binary: binary, ConsoleOrigin: consoleOrigin, serverCPUs: options.ServerCPUs,
		environment: LoadExperimentEnvironment{Storage: "storage: shared development PostgreSQL", ServerCPUs: options.ServerCPUs},
	}
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
	databaseResources := shared
	if options.DatabaseStorage == "nvme" || options.DatabaseStorage == "tmpfs" {
		f.cluster, err = openLoadPostgres(ctx, root, shared, options)
		if err != nil {
			return nil, err
		}
		databaseResources = f.cluster.directory
		f.environment = f.cluster.environment
	}
	if mode == authorityHA {
		f.ha, err = openHATopology(ctx, shared)
		if err != nil {
			return nil, err
		}
		databaseResources = f.ha.directory
	}
	document, err := authorityDocument(ctx, f.configPath(), shared, material)
	if err != nil {
		return nil, err
	}
	// Override only generated configuration, never read the shared server.json.
	document.Proto.Database.MigrationUrlFile = proto.String(filepath.Join(databaseResources, "migration-database-url"))
	var dsn *url.URL
	if f.ha == nil {
		dsnBytes, err := os.ReadFile(filepath.Join(databaseResources, "migration-database-url"))
		if err != nil {
			return nil, err
		}
		dsn, err = url.Parse(strings.TrimSpace(string(dsnBytes)))
		clear(dsnBytes)
		if err != nil || dsn.Scheme != "postgresql" {
			return nil, errors.New("invalid development migration database URL")
		}
	}
	setup, cancel := context.WithTimeout(ctx, 2*time.Minute)
	f.database, err = newAuthorityDatabase(setup, document, databaseResources)
	cancel()
	if err != nil {
		return nil, err
	}
	f.DatabaseName = f.database.name
	var runtimeURL string
	if f.ha != nil {
		runtimeURL = f.ha.databaseURL(f.DatabaseName)
	} else {
		dsn.Path, dsn.RawPath = "/"+f.DatabaseName, ""
		runtimeURL = dsn.String()
	}
	for name, data := range map[string][]byte{
		"database-url": []byte(runtimeURL), "execution-root.json": material.ExecutionRootJSON,
		"bootstrap.dsse.json": material.BootstrapEnvelope,
	} {
		if err := os.WriteFile(filepath.Join(f.directory, name), data, 0600); err != nil {
			return nil, err
		}
	}
	listen := "127.0.0.1"
	if options.ListenAddress != "" {
		listen = options.ListenAddress
	}
	adminAddressToReserve := net.JoinHostPort(listen, "0")
	if mode == authorityKeycloakConsole {
		adminAddressToReserve = "127.0.0.1:18444"
	}
	admin, err := net.Listen("tcp4", adminAddressToReserve)
	if err != nil {
		return nil, err
	}
	defer func() {
		if admin != nil {
			resultErr = errors.Join(resultErr, admin.Close())
		}
	}()
	device, err := net.Listen("tcp4", net.JoinHostPort(listen, "0"))
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
	cfg.AdminListener = &configv1.ListenerConfig{Address: listen, Port: uint32(adminAddress.Port)}
	cfg.DeviceListener = &configv1.ListenerConfig{Address: listen, Port: uint32(deviceAddress.Port)}
	if options.Advisories != nil {
		cfg.Advisories = proto.CloneOf(options.Advisories)
	}
	deviceOrigin := "https://localhost:18445"
	if mode == authorityLocalConsole || mode == authorityDeviceActions || mode == authorityHA {
		f.ConsoleOrigin = fmt.Sprintf("https://localhost:%d", adminAddress.Port)
		cfg.PublicUrl = f.ConsoleOrigin
		if mode == authorityDeviceActions || mode == authorityHA {
			deviceOrigin = fmt.Sprintf("https://localhost:%d", deviceAddress.Port)
		}
		material, err = f.originAgentFixture(ctx, material, deviceOrigin)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(f.directory, "bootstrap.dsse.json"), material.BootstrapEnvelope, 0600); err != nil {
			return nil, err
		}
	}
	f.DeviceOrigin = deviceOrigin
	cfg.Database = &configv1.DatabaseConfig{UrlFile: "database-url", MigrationUrlFile: proto.String("database-url"), MaxConnections: 8}
	cfg.Tls.CertificateFile = filepath.Join(shared, "server.crt")
	cfg.Tls.PrivateKeyFile = filepath.Join(shared, "server.key")
	cfg.DeviceCa.CertificateFile = filepath.Join(shared, "device-ca.crt")
	cfg.DeviceCa.PrivateKeyFile = filepath.Join(shared, "device-ca.key")
	if local {
		cfg.Authentication = &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Local{Local: &configv1.LocalAuthentication{}}}
		cfg.Authorization.GroupBindings = nil
	} else {
		keycloak := cfg.GetAuthentication().GetKeycloak()
		if keycloak == nil {
			return nil, errors.New("isolated control-plane checks require the Keycloak development fixture")
		}
		keycloak.ClientSecretFile = filepath.Join(shared, "console-secret")
		keycloak.DirectoryClientSecretFile = filepath.Join(shared, "directory-secret")
	}
	cfg.TrustedCaFile = filepath.Join(shared, "transport-ca.crt")
	cfg.DevicePublicUrl = proto.String(deviceOrigin)
	cfg.ExecutionBootstrap = &configv1.ExecutionBootstrapConfig{RootFile: "execution-root.json", BootstrapFile: "bootstrap.dsse.json"}
	if mode == authorityLocalConsole || mode == authorityHA {
		if err := f.configureConsoleIntegrations(cfg); err != nil {
			return nil, err
		}
	}
	if mode == authorityLocalConsole {
		if err := f.configureConsoleEscrow(cfg); err != nil {
			return nil, err
		}
	}
	if mode == authorityReleaseUpdates || mode == authorityDeviceActions {
		if err := f.configureReleaseRepository(ctx, cfg, material); err != nil {
			return nil, err
		}
	}
	if mode == authorityAirgap {
		if err := f.configureAirgap(ctx, cfg, material, options.airgap); err != nil {
			return nil, err
		}
	}
	encoded, err := protojson.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(f.configPath(), encoded, 0600); err != nil {
		return nil, err
	}
	if f.ha != nil {
		f.ha.lbAdmin, f.ha.lbDevice = adminAddress.Port, deviceAddress.Port
		if err := f.ha.writeInstanceConfigs(cfg, f.directory); err != nil {
			return nil, err
		}
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
	err = labexec.Run(ctx, labexec.Command{Path: f.binary, Args: []string{"migrate", "-config", f.configPath()}, Stdout: f.log, Stderr: f.log, Timeout: time.Minute})
	if err != nil {
		return nil, errors.New("migrate isolated authority database failed")
	}
	var enrollmentSecret string
	if local {
		enrollmentSecret, err = f.bootstrapLocalOwner(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		err = labexec.Run(ctx, labexec.Command{Path: f.binary, Args: []string{"bootstrap-owner", "-config", f.configPath(), "-issuer", issuer, "-subject", ownerSubject}, Stdout: f.log, Stderr: f.log, Timeout: time.Minute})
		if err != nil {
			return nil, errors.New("bootstrap owner in isolated authority database failed")
		}
	}
	if options.airgap != nil {
		if err := options.airgap.BeforeStart(ctx, f.runServerCommand); err != nil {
			return nil, fmt.Errorf("air-gap pre-start import: %w", err)
		}
	}
	err = errors.Join(admin.Close(), device.Close())
	admin, device = nil, nil
	if err != nil {
		return nil, err
	}
	if err := f.start(ctx); err != nil {
		return nil, err
	}
	if local {
		if err := f.enrollLocalOwners(ctx, enrollmentSecret); err != nil {
			return nil, err
		}
	}
	if err := f.RegisterRelease(ctx, ""); err != nil {
		return nil, fmt.Errorf("register isolated server release: %w", err)
	}
	return f, nil
}

func (f *AuthorityFixture) configPath() string { return filepath.Join(f.directory, "server.json") }

func (f *AuthorityFixture) OpenOwnerSession(ctx context.Context) (*OwnerSession, error) {
	if f.closed {
		return nil, errors.New("isolated authority fixture is closed")
	}
	if f.local != nil {
		return f.openLocalSession(ctx, f.local.owner)
	}
	return openOwnerSession(ctx, f.repository, f.AdminAddress)
}

func (f *AuthorityFixture) start(ctx context.Context) error {
	if f.closed || f.process != nil {
		return errors.New("isolated authority process lifecycle conflict")
	}
	if f.ha != nil {
		return f.startHA(ctx)
	}
	command, err := newServerCommand(f.binary, f.configPath(), f.serverCPUs)
	if err != nil {
		return err
	}
	command.Stdout, command.Stderr = f.log, f.log
	// The server outlives this call; stop and Close own its lifetime.
	process, err := labexec.Start(context.WithoutCancel(ctx), command)
	if err != nil {
		return errors.New("start isolated lindmd failed")
	}
	f.processPID.Store(int64(process.Pid()))
	f.process, f.done = process, make(chan error, 1)
	done := f.done
	go func() { done <- process.Wait() }()
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
			f.processPID.Store(0)
			return errors.New("isolated lindmd exited before readiness")
		default:
		}
		req, err := http.NewRequestWithContext(ready, http.MethodGet, f.ConsoleOrigin+"/readyz", nil)
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
	if f.ha != nil {
		return f.ha.stopInstances()
	}
	if f.process == nil {
		return nil
	}
	process, done := f.process, f.done
	process.Signal(syscall.SIGTERM)
	select {
	case waitErr := <-done:
		f.process, f.done = nil, nil
		f.processPID.Store(0)
		return waitErr
	case <-time.After(15 * time.Second):
		process.Signal(syscall.SIGKILL)
		select {
		case <-done:
			f.process, f.done = nil, nil
			f.processPID.Store(0)
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
	if f.closed && f.process == nil && f.cluster == nil && f.ha == nil {
		return nil
	}
	f.closed = true
	err := f.stop()
	if f.demo != nil {
		err = errors.Join(err, f.demo.close())
		f.demo = nil
	}
	if f.process != nil || f.ha != nil && f.ha.running() {
		// Never drop a database or unlink credentials still used by a live child.
		return errors.Join(err, fmt.Errorf("isolated lindmd has not exited; owned database %s and resources %s retained", f.DatabaseName, f.directory))
	}
	if f.local != nil {
		f.local.close()
	}
	if f.database != nil {
		err = errors.Join(err, f.database.Close())
	}
	if f.cluster != nil {
		if cleanupErr := f.cluster.Close(); cleanupErr != nil {
			return errors.Join(err, cleanupErr)
		}
		f.cluster = nil
	}
	if f.ha != nil {
		if cleanupErr := f.ha.close(); cleanupErr != nil {
			return errors.Join(err, cleanupErr)
		}
		f.ha = nil
	}
	if f.log != nil {
		err = errors.Join(err, f.log.Close())
	}
	if f.directory != "" {
		err = errors.Join(err, os.RemoveAll(f.directory))
	}
	return err
}
