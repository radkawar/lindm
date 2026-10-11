package devlab

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/labexec"
)

// brokerUpstreamProxy is a real, uncached TLS transport to the upstream Admin API.
// Its fault switch severs only this check's upstream connector, while the real
// broker remains available. It never synthesizes a successful directory response.
type brokerUpstreamProxy struct {
	issuer string
	failed atomic.Bool
	server *http.Server
	done   chan error
}

func openBrokerUpstreamProxy(shared string, transport *http.Transport) (*brokerUpstreamProxy, error) {
	certificate, err := tls.LoadX509KeyPair(filepath.Join(shared, "server.crt"), filepath.Join(shared, "server.key"))
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return nil, errors.Join(errors.New("broker proxy listener is not TCP"), listener.Close())
	}
	origin := "https://localhost:" + fmt.Sprint(address.Port)
	p := &brokerUpstreamProxy{issuer: origin + "/realms/" + brokerUpstreamRealm, done: make(chan error, 1)}
	proxy := &httputil.ReverseProxy{Transport: transport, Rewrite: func(r *httputil.ProxyRequest) {
		r.Out.URL.Scheme, r.Out.URL.Host, r.Out.Host = "https", "localhost:18443", "localhost:18443"
	}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(http.StatusServiceUnavailable) }}
	p.server = &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 15 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p.failed.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			allowed := r.Method == http.MethodPost && r.URL.Path == "/realms/"+brokerUpstreamRealm+"/protocol/openid-connect/token"
			allowed = allowed || (r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/admin/realms/"+brokerUpstreamRealm+"/users/"))
			if !allowed {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			proxy.ServeHTTP(w, r)
		})}
	go func() {
		p.done <- p.server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}))
	}()
	return p, nil
}

func (p *brokerUpstreamProxy) close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := p.server.Shutdown(ctx)
	if err != nil {
		err = errors.Join(err, p.server.Close())
	}
	serveErr := <-p.done
	if !errors.Is(serveErr, http.ErrServerClosed) {
		err = errors.Join(err, serveErr)
	}
	return err
}

// openBrokerServer runs a prebuilt real lindmd with a dedicated database and two
// dynamically reserved listeners. No request or listener uses the shared :18444.
func openBrokerServer(ctx context.Context, root, binary, clientID, clientSecret, group, upstream string, register func(string) error) (*AuthorityFixture, string, error) {
	shared := FixturePath(root)
	return openDirectoryServer(ctx, root, binary, directoryServerOptions{
		authentication: &configv1.AuthenticationConfig{Primary: &configv1.AuthenticationConfig_Keycloak{Keycloak: &configv1.KeycloakDirectory{
			Issuer: brokerIssuer, ClientId: clientID, ClientSecretFile: "client-secret", DirectoryClientId: "lindm-directory", DirectoryClientSecretFile: filepath.Join(shared, "broker-directory-secret"),
			Upstream: &configv1.KeycloakBrokerUpstream{Alias: brokerAlias, ConnectorId: "owned-broker-upstream", Issuer: upstream, DirectoryClientId: "lindm-directory", DirectoryClientSecretFile: filepath.Join(shared, "broker-upstream-directory-secret")},
		}}},
		group: "/" + group, secrets: map[string]string{"client-secret": clientSecret}, register: register,
	})
}

type directoryServerOptions struct {
	authentication  *configv1.AuthenticationConfig
	group           string
	secrets         map[string]string
	register        func(string) error
	bootstrap       []string
	environment     []string
	parentDirectory string
}

// openDirectoryServer shares the owned database/process lifecycle, never provider
// credentials or policy, between the live external-directory qualification lanes.
func openDirectoryServer(ctx context.Context, root, binary string, options directoryServerOptions) (_ *AuthorityFixture, _ string, resultErr error) {
	binary, err := filepath.Abs(binary)
	if err != nil {
		return nil, "", err
	}
	info, err := os.Stat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return nil, "", errors.New("broker check requires an executable prebuilt lindmd")
	}
	shared := FixturePath(root)
	material, err := ReadPublicAgentFixture(ctx, root)
	if err != nil {
		return nil, "", err
	}
	f := &AuthorityFixture{repository: root, binary: binary}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, f.Close())
		}
	}()
	f.directory, err = os.MkdirTemp(options.parentDirectory, "lindm-directory-server-")
	if err != nil {
		return nil, "", err
	}
	f.log, err = os.OpenFile(filepath.Join(f.directory, "server.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, "", err
	}
	document, err := authorityDocument(ctx, f.configPath(), shared, material)
	if err != nil {
		return nil, "", err
	}
	f.database, err = newAuthorityDatabase(ctx, document, shared)
	if err != nil {
		return nil, "", err
	}
	f.DatabaseName = f.database.name
	dsnBytes, err := os.ReadFile(filepath.Join(shared, "migration-database-url"))
	if err != nil {
		return nil, "", err
	}
	defer clear(dsnBytes)
	dsn, err := url.Parse(strings.TrimSpace(string(dsnBytes)))
	if err != nil {
		return nil, "", err
	}
	dsn.Path, dsn.RawPath = "/"+f.DatabaseName, ""
	for name, body := range map[string][]byte{"database-url": []byte(dsn.String()), "execution-root.json": material.ExecutionRootJSON, "bootstrap.dsse.json": material.BootstrapEnvelope} {
		if err := os.WriteFile(filepath.Join(f.directory, name), body, 0600); err != nil {
			return nil, "", err
		}
	}
	for name, secret := range options.secrets {
		if err := os.WriteFile(filepath.Join(f.directory, name), []byte(secret), 0600); err != nil {
			return nil, "", err
		}
	}
	admin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	defer func() {
		if admin != nil {
			resultErr = errors.Join(resultErr, admin.Close())
		}
	}()
	device, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	defer func() {
		if device != nil {
			resultErr = errors.Join(resultErr, device.Close())
		}
	}()
	adminAddress, adminTCP := admin.Addr().(*net.TCPAddr)
	deviceAddress, deviceTCP := device.Addr().(*net.TCPAddr)
	if !adminTCP || !deviceTCP {
		return nil, "", errors.New("broker fixture listener is not TCP")
	}
	adminPort, devicePort := adminAddress.Port, deviceAddress.Port
	if adminPort == 18444 || devicePort == 18444 {
		return nil, "", errors.New("broker check refuses the shared console port")
	}
	origin := "https://localhost:" + fmt.Sprint(adminPort)
	deviceOrigin := "https://localhost:" + fmt.Sprint(devicePort)
	f.AdminAddress, f.DeviceAddress = admin.Addr().String(), device.Addr().String()
	f.ConsoleOrigin = origin
	material, err = f.originAgentFixture(ctx, material, deviceOrigin)
	if err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(filepath.Join(f.directory, "bootstrap.dsse.json"), material.BootstrapEnvelope, 0600); err != nil {
		return nil, "", err
	}
	cfg := proto.CloneOf(document.Proto)
	cfg.PublicUrl = origin
	cfg.AdminListener = &configv1.ListenerConfig{Address: "127.0.0.1", Port: uint32(adminPort)}
	cfg.DeviceListener = &configv1.ListenerConfig{Address: "127.0.0.1", Port: uint32(devicePort)}
	cfg.DevicePublicUrl = proto.String(deviceOrigin)
	cfg.Database = &configv1.DatabaseConfig{UrlFile: "database-url", MigrationUrlFile: proto.String("database-url"), MaxConnections: 8}
	cfg.Authentication = options.authentication
	cfg.Authorization = &authv1.AuthorizationPolicy{GroupBindings: []*authv1.GroupBinding{{Group: options.group, Role: "admin"}}}
	cfg.ExecutionBootstrap = &configv1.ExecutionBootstrapConfig{RootFile: "execution-root.json", BootstrapFile: "bootstrap.dsse.json"}
	encoded, err := protojson.Marshal(cfg)
	if err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(f.configPath(), encoded, 0600); err != nil {
		return nil, "", err
	}
	if err := options.register(origin); err != nil {
		return nil, "", err
	}
	err = labexec.Run(ctx, labexec.Command{Path: binary, Args: []string{"migrate", "-config", f.configPath()}, Stdout: f.log, Stderr: f.log, Timeout: time.Minute})
	if err != nil {
		return nil, "", errors.New("migrate isolated broker database failed")
	}
	if len(options.bootstrap) != 0 {
		args := append([]string{"bootstrap-owner", "-config", f.configPath()}, options.bootstrap...)
		err = labexec.Run(ctx, labexec.Command{Path: binary, Args: args, Env: options.environment, Stdout: f.log, Stderr: f.log, Timeout: time.Minute})
		if err != nil {
			secrets := []string{dsn.String()}
			for _, secret := range options.secrets {
				secrets = append(secrets, secret)
			}
			return nil, "", fmt.Errorf("bootstrap isolated directory owner: %w", brokerStartupError(filepath.Join(f.directory, "server.log"), secrets...))
		}
	}
	err = errors.Join(admin.Close(), device.Close())
	admin, device = nil, nil
	if err != nil {
		return nil, "", err
	}
	cmd := exec.Command(binary, "serve", "-config", f.configPath())
	cmd.Stdout, cmd.Stderr = f.log, f.log
	cmd.Env = options.environment
	if err := cmd.Start(); err != nil {
		return nil, "", errors.New("start isolated broker lindmd failed")
	}
	f.process, f.done = cmd, make(chan error, 1)
	done := f.done
	go func() { done <- cmd.Wait() }()
	tlsConfig, err := trustClient(shared)
	if err != nil {
		return nil, "", err
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	ready, stop := context.WithTimeout(ctx, 45*time.Second)
	defer stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-f.done:
			f.process, f.done = nil, nil
			secrets := []string{dsn.String()}
			for _, secret := range options.secrets {
				secrets = append(secrets, secret)
			}
			return nil, "", brokerStartupError(filepath.Join(f.directory, "server.log"), secrets...)
		default:
		}
		req, err := http.NewRequestWithContext(ready, http.MethodGet, origin+"/readyz", nil)
		if err != nil {
			return nil, "", err
		}
		resp, err := client.Do(req)
		if err == nil {
			closeErr := resp.Body.Close()
			if resp.StatusCode == http.StatusNoContent && closeErr == nil {
				return f, origin, nil
			}
		}
		select {
		case <-ready.Done():
			return nil, "", errors.New("isolated broker lindmd readiness deadline")
		case <-ticker.C:
		}
	}
}

func brokerStartupError(path string, secrets ...string) (resultErr error) {
	log, err := os.Open(path)
	if err != nil {
		return errors.Join(errors.New("isolated broker lindmd exited before readiness"), err)
	}
	defer func() { resultErr = errors.Join(resultErr, log.Close()) }()
	body, err := io.ReadAll(io.LimitReader(log, 64*1024))
	if err != nil {
		return errors.Join(errors.New("read isolated broker startup log"), err)
	}
	detail := string(body)
	for _, secret := range secrets {
		if secret != "" {
			detail = strings.ReplaceAll(detail, secret, "[redacted]")
		}
	}
	return fmt.Errorf("isolated broker lindmd exited before readiness: %s", strings.TrimSpace(detail))
}
