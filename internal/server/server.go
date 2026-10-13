// Package server composes the control plane and owns its process lifetime.
package server

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/db"
	"lindm/internal/advisory"
	"lindm/internal/agent/buildinfo"
	"lindm/internal/assistrelay"
	"lindm/internal/config"
	"lindm/internal/device"
	devicecore "lindm/internal/device/core"
	"lindm/internal/device/dispatch"
	"lindm/internal/executionauthority"
	"lindm/internal/identity"
	"lindm/internal/integrations"
	"lindm/internal/jobs"
	"lindm/internal/offlinebundle"
	"lindm/internal/reports"
	"lindm/internal/targeting"
	"lindm/web"
)

// NewIdentity composes the configured primary identity source and independent
// emergency policy for both serving and explicit owner bootstrap.
func NewIdentity(ctx context.Context, pool *pgxpool.Pool, resources *config.Resources) (*identity.Service, error) {
	authentication := resources.Proto.GetAuthentication()
	keycloak := authentication.GetKeycloak()
	cfg := identity.Config{
		Local:                       authentication.GetLocal() != nil,
		BreakGlass:                  resources.Proto.GetBreakGlass(),
		Issuer:                      keycloak.GetIssuer(),
		ClientID:                    keycloak.GetClientId(),
		ClientSecret:                resources.ClientSecret,
		DirectoryClientID:           keycloak.GetDirectoryClientId(),
		DirectoryClientSecret:       resources.DirectoryClientSecret,
		PublicURL:                   resources.Proto.GetPublicUrl(),
		Policy:                      resources.Proto.GetAuthorization(),
		HTTPClient:                  resources.HTTPClient,
		Okta:                        authentication.GetOkta(),
		Google:                      authentication.GetGoogle(),
		DirectoryPrivateKeyPEM:      resources.DirectoryPrivateKeyPEM,
		SCIM:                        authentication.GetScim(),
		Broker:                      keycloak.GetUpstream(),
		BrokerDirectoryClientSecret: resources.BrokerDirectoryClientSecret,
	}
	if entra := authentication.GetEntra(); entra != nil {
		issuer, err := identity.EntraIssuer(entra.GetTenantId())
		if err != nil {
			return nil, err
		}
		cfg.Issuer = issuer
		cfg.EntraTenantID = entra.GetTenantId()
		cfg.ClientID = entra.GetClientId()
		cfg.DirectoryClientID = entra.GetDirectoryClientId()
	}
	if okta := authentication.GetOkta(); okta != nil {
		cfg.Issuer = okta.GetIssuer()
		cfg.ClientID = okta.GetClientId()
		cfg.DirectoryClientID = okta.GetDirectoryClientId()
	}
	if google := authentication.GetGoogle(); google != nil {
		cfg.Issuer = "https://accounts.google.com"
		cfg.ClientID = google.GetClientId()
	}
	return identity.New(ctx, pool, cfg)
}

// Run checks the schema, initializes authenticated services, then binds both TLS
// listeners before serving either. Cancellation drains requests before closing the
// pool; startup and unexpected listener failures are returned to the supervisor.
func Run(ctx context.Context, resources *config.Resources) error {
	defer resources.HTTPClient.CloseIdleConnections()
	pool, err := pgxpool.NewWithConfig(ctx, resources.Database)
	if err != nil {
		return fmt.Errorf("initialize database pool: %w", err)
	}
	defer pool.Close()
	// The console/identity pool is separate so device traffic saturating the
	// device pool cannot queue operators' session checks and admin reads.
	adminPool, err := pgxpool.NewWithConfig(ctx, resources.AdminDatabase)
	if err != nil {
		return fmt.Errorf("initialize console database pool: %w", err)
	}
	defer adminPool.Close()
	startup, cancelStartup := context.WithTimeout(ctx, 30*time.Second)
	defer cancelStartup()
	if err := db.Check(startup, pool); err != nil {
		return err
	}
	plane, err := newControlPlane(startup, pool, adminPool, resources)
	if err != nil {
		return err
	}
	adminMux, err := plane.adminMux(pool, resources)
	if err != nil {
		return err
	}
	deviceMux, err := plane.deviceMux(resources)
	if err != nil {
		return err
	}

	requestContext, cancelRequests := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelRequests()
	admin, deviceServer := tlsServers(requestContext, resources, adminMux, deviceMux)
	listenerConfig := new(net.ListenConfig)
	adminListener, err := listenerConfig.Listen(ctx, "tcp", admin.Addr)
	if err != nil {
		return fmt.Errorf("bind administrative listener: %w", err)
	}
	deviceListener, err := listenerConfig.Listen(ctx, "tcp", deviceServer.Addr)
	if err != nil {
		return errors.Join(fmt.Errorf("bind device listener: %w", err), adminListener.Close())
	}
	var relayServer *assistrelay.Server
	if plane.relay != nil {
		relayServer, err = plane.relay.Listen(ctx)
		if err != nil {
			return errors.Join(err, adminListener.Close(), deviceListener.Close())
		}
	}
	profiling, err := newProfiler(ctx, resources.Proto.GetProfiling())
	if err != nil {
		err = errors.Join(err, adminListener.Close(), deviceListener.Close())
		if relayServer != nil {
			err = errors.Join(err, relayServer.Close())
		}
		return err
	}

	workerContext, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()
	stopped := make(chan error, 4)
	go func() { stopped <- serve(admin, adminListener) }()
	go func() { stopped <- serve(deviceServer, deviceListener) }()
	slog.Info("control plane ready", "admin", admin.Addr, "device", deviceServer.Addr)
	remaining := 2
	if profiling != nil {
		remaining++
		go func() { stopped <- profiling.run(workerContext) }()
	}
	if relayServer != nil {
		// The relay serves until shutdown; closing it ends every allocation.
		remaining++
		go func() {
			<-workerContext.Done()
			stopped <- relayServer.Close()
		}()
	}
	// Background jobs never stop the process: the supervisor retries failures
	// and is joined before the pool closes.
	jobsDone := make(chan struct{})
	go func() {
		defer close(jobsDone)
		plane.supervisor.Run(workerContext)
	}()
	defer func() {
		cancelWorkers()
		<-jobsDone
	}()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-stopped:
		remaining--
	}
	cancelWorkers()
	shutdownErr := shutdown(admin, deviceServer)
	cancelRequests()
	for range remaining {
		serveErr = errors.Join(serveErr, <-stopped)
	}
	return errors.Join(serveErr, shutdownErr)
}

// controlPlane holds the domain services one Run composes and serves.
type controlPlane struct {
	auth    *identity.Service
	devices *device.Service
	// consoleDevices is the device domain on the console pool (admin RPCs).
	consoleDevices     *device.Service
	deliveries         *integrations.Service
	reporting          *reports.Service
	releaseHandler     http.Handler
	nativeRepositories *nativeRepositories
	relay              *assistrelay.Relay
	supervisor         *jobs.Supervisor
	console            http.Handler
}

// newControlPlane initializes every configured domain service against a checked
// schema. It binds no listener.
func newControlPlane(ctx context.Context, pool, adminPool *pgxpool.Pool, resources *config.Resources) (*controlPlane, error) {
	auth, err := NewIdentity(ctx, adminPool, resources)
	if err != nil {
		return nil, fmt.Errorf("initialize identity service: %w", err)
	}
	execution, err := newExecutionAuthority(ctx, pool, resources)
	if err != nil {
		return nil, fmt.Errorf("initialize execution authority: %w", err)
	}
	advisories, err := advisory.New(ctx, pool, resources.Proto.GetAdvisories(), resources.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("initialize advisories: %w", err)
	}
	releaseHandler, releasePublisher, err := newReleaseRepository(resources)
	if err != nil {
		return nil, fmt.Errorf("initialize release repository: %w", err)
	}
	recoveryArtifacts, err := newRecoveryArtifacts(resources)
	if err != nil {
		return nil, fmt.Errorf("initialize recovery artifact verification: %w", err)
	}
	var relay *assistrelay.Relay
	if assistance := resources.Proto.GetAssistance(); assistance != nil {
		relay, err = assistrelay.New(assistance, time.Now, slog.Default())
		if err != nil {
			return nil, fmt.Errorf("initialize assistance relay: %w", err)
		}
	}
	native := loadNativeRepositories(ctx, resources)
	deviceConfig := devicecore.Config{
		DeploymentID:                 resources.Proto.GetDeploymentId(),
		CACertificate:                resources.DeviceCACertificate,
		CAKey:                        resources.DeviceCAKey,
		InventoryBudgetBytes:         resources.InventoryBudgetBytes,
		ExecutionAuthority:           execution,
		Identity:                     auth,
		ExecutionSigning:             resources.ExecutionSigning,
		Advisories:                   advisories,
		Escrow:                       resources.Escrow,
		EscrowRevealApprovalRequired: resources.EscrowRevealApprovalRequired,
		ReleasePublisher:             releasePublisher,
		RecoveryArtifacts:            recoveryArtifacts,
		ServerRelease:                buildinfo.Current().Version,
		ServerProtocol:               buildinfo.ProtocolVersion,
		RequireReleaseCompatibility:  true,
		EnrollmentInstructions:       enrollmentInstructions(resources, native),
		Assistance:                   relay,
	}
	devices, err := device.New(pool, deviceConfig)
	if err != nil {
		return nil, fmt.Errorf("initialize device service: %w", err)
	}
	// The same domain service on the console pool serves only admin handlers
	// and the console's fleet population.
	consoleDevices, err := device.New(adminPool, deviceConfig)
	if err != nil {
		return nil, fmt.Errorf("initialize console device service: %w", err)
	}
	deliveries, reporting, err := newIntegrations(pool, auth, resources)
	if err != nil {
		return nil, err
	}
	promoter, err := targeting.NewPromoter(pool, auth, devices.Targeting, devices.RolloutHooks())
	if err != nil {
		return nil, fmt.Errorf("initialize rollout promoter: %w", err)
	}
	supervisor, err := jobs.New(jobs.Config{Connection: pool.Config().ConnConfig, Jobs: backgroundJobs(devices, consoleDevices, advisories, deliveries, reporting, promoter)})
	if err != nil {
		return nil, fmt.Errorf("initialize background jobs: %w", err)
	}
	console, err := web.Handler()
	if err != nil {
		return nil, err
	}
	return &controlPlane{
		auth: auth, devices: devices, consoleDevices: consoleDevices, deliveries: deliveries, reporting: reporting,
		releaseHandler: releaseHandler, relay: relay, supervisor: supervisor, console: console,
		nativeRepositories: native,
	}, nil
}

// newExecutionAuthority opens the configured quorum trust store, or proves that
// an unconfigured deployment has none persisted.
func newExecutionAuthority(ctx context.Context, pool *pgxpool.Pool, resources *config.Resources) (*executionauthority.Store, error) {
	bootstrap := resources.ExecutionBootstrap
	if bootstrap == nil {
		return nil, executionauthority.CheckUnconfigured(ctx, pool)
	}
	return executionauthority.New(ctx, pool, executionauthority.Config{
		RootJSON: bootstrap.RootJSON, BootstrapEnvelope: bootstrap.Envelope,
		TLSPublicKey: resources.ServerCertificate.Leaf.PublicKey,
	})
}

// newIntegrations composes outbound deliveries and signed reports, which are
// configured together; both are nil when integrations are not configured.
func newIntegrations(pool *pgxpool.Pool, auth *identity.Service, resources *config.Resources) (*integrations.Service, *reports.Service, error) {
	if resources.Proto.GetIntegrations() == nil {
		return nil, nil, nil
	}
	deliveries, err := integrations.New(pool, auth, resources.IntegrationEncryptionKey, time.Now)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize integrations: %w", err)
	}
	signer, ok := resources.ServerCertificate.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("server TLS key cannot sign report manifests")
	}
	reporting, err := reports.New(pool, auth, signer, resources.ServerCertificate.Certificate)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize reports: %w", err)
	}
	return deliveries, reporting, nil
}

// adminMux routes the administrative listener: sessions, SCIM, public
// installation material, session-guarded admin APIs, health and the console.
func (p *controlPlane) adminMux(pool *pgxpool.Pool, resources *config.Resources) (*http.ServeMux, error) {
	mux := http.NewServeMux()
	identityHandler := p.auth.Handler()
	mux.Handle("/auth/", identityHandler)
	mux.Handle("/scim/v2/", identityHandler)
	organization, err := organizationHandler(p.auth, p.consoleDevices)
	if err != nil {
		return nil, fmt.Errorf("initialize organization apply: %w", err)
	}
	mux.Handle("POST /auth/organization/apply", organization)
	// Initial installations have no session or device certificate. Only verified
	// public installation documents are exposed here, never a filesystem tree.
	mux.Handle("/bootstrap/", bootstrapMaterialHandler(resources.ExecutionBootstrap))
	// Native publication files are authenticated before admission; serving
	// never requires an admin session, device certificate or signing key.
	if p.nativeRepositories != nil {
		mux.Handle("/repo/apt/", http.StripPrefix("/repo/apt/", p.nativeRepositories.apt))
		mux.Handle("/repo/rpm/", http.StripPrefix("/repo/rpm/", p.nativeRepositories.rpm))
		mux.Handle("/repo/arch/", http.StripPrefix("/repo/arch/", p.nativeRepositories.arch))
	}
	path, handler := p.consoleDevices.AdminHandler()
	mux.Handle(path, p.auth.RequireSession(handler))
	path, handler = p.consoleDevices.ReleaseManagementHandler()
	mux.Handle(path, p.auth.RequireSession(handler))
	if p.releaseHandler != nil {
		mux.Handle("/updates/", http.StripPrefix("/updates/", p.releaseHandler))
	}
	if resources.OfflineBundleDirectory != "" {
		offlineHandler, err := offlinebundle.NewRepositoryHandler(resources.OfflineBundleDirectory)
		if err != nil {
			return nil, fmt.Errorf("initialize offline repository handler: %w", err)
		}
		// Signed native repositories and release artifacts from verified
		// imports; packages authenticate natively with client-pinned keys.
		mux.Handle("/offline/", http.StripPrefix("/offline/", offlineHandler))
	}
	if p.deliveries != nil {
		path, handler = p.deliveries.AdminHandler()
		mux.Handle(path, p.auth.RequireSession(handler))
		path, handler = p.reporting.AdminHandler()
		mux.Handle(path, p.auth.RequireSession(handler))
	}
	path, handler = p.devices.EnrollmentHandler()
	mux.Handle(path, handler)
	path, handler = p.devices.RecoveryHandler()
	mux.Handle(path, handler)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		probe, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(probe); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("/", p.console)
	return mux, nil
}

// deviceMux routes the mTLS device listener.
func (p *controlPlane) deviceMux(resources *config.Resources) (*http.ServeMux, error) {
	mux := http.NewServeMux()
	path, handler := p.devices.DeviceHandler()
	mux.Handle(path, handler)
	if len(resources.Proto.GetConnectivityProbes()) != 0 {
		confirmation, err := p.devices.ConnectivityConfirmationHandler(resources.Proto.GetConnectivityProbes())
		if err != nil {
			return nil, fmt.Errorf("configure native connectivity confirmation: %w", err)
		}
		mux.Handle(dispatch.ConnectivityConfirmationPath, confirmation)
	}
	return mux, nil
}

// tlsServers configures the TLS 1.3 administrative server and the device server,
// which requires a client certificate issued by the device CA.
func tlsServers(requestContext context.Context, resources *config.Resources, adminMux, deviceMux http.Handler) (admin, deviceServer *http.Server) {
	admin = httpServer(config.Address(resources.Proto.GetAdminListener()), adminMux, requestContext)
	admin.TLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{resources.ServerCertificate},
	}
	deviceServer = httpServer(config.Address(resources.Proto.GetDeviceListener()), deviceMux, requestContext)
	deviceRoots := x509.NewCertPool()
	deviceRoots.AddCert(resources.DeviceCACertificate)
	deviceServer.TLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{resources.ServerCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    deviceRoots,
	}
	return admin, deviceServer
}

func httpServer(address string, handler http.Handler, ctx context.Context) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           guard(handler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
}

func serve(server *http.Server, listener net.Listener) error {
	err := server.ServeTLS(listener, "", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("serve %s: %w", server.Addr, err)
}

func shutdown(servers ...*http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	results := make(chan error, len(servers))
	for _, server := range servers {
		go func() { results <- server.Shutdown(ctx) }()
	}
	var err error
	for range servers {
		err = errors.Join(err, <-results)
	}
	if err != nil {
		for _, server := range servers {
			err = errors.Join(err, server.Close())
		}
	}
	return err
}

func guard(next http.Handler) http.Handler {
	slots := make(chan struct{}, 256)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// same-origin, not no-referrer: under no-referrer the Fetch standard makes
		// browsers (Safari) send `Origin: null` on same-origin POSTs, which the
		// authentication endpoints' exact-origin CSRF check correctly rejects.
		// Cross-origin requests still receive no referrer.
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "service capacity exceeded", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
