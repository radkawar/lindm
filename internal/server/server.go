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
	"lindm/internal/config"
	"lindm/internal/device"
	"lindm/internal/executionauthority"
	"lindm/internal/identity"
	"lindm/internal/integrations"
	"lindm/internal/reports"
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
	startup, cancelStartup := context.WithTimeout(ctx, 30*time.Second)
	defer cancelStartup()
	if err := db.Check(startup, pool); err != nil {
		return err
	}
	auth, err := NewIdentity(startup, pool, resources)
	if err != nil {
		return fmt.Errorf("initialize identity service: %w", err)
	}
	var execution *executionauthority.Store
	if bootstrap := resources.ExecutionBootstrap; bootstrap != nil {
		execution, err = executionauthority.New(startup, pool, executionauthority.Config{
			RootJSON: bootstrap.RootJSON, BootstrapEnvelope: bootstrap.Envelope,
			TLSPublicKey: resources.ServerCertificate.Leaf.PublicKey,
		})
	} else {
		err = executionauthority.CheckUnconfigured(startup, pool)
	}
	if err != nil {
		return fmt.Errorf("initialize execution authority: %w", err)
	}
	advisories, err := advisory.New(startup, pool, resources.Proto.GetAdvisories(), resources.HTTPClient)
	if err != nil {
		return fmt.Errorf("initialize advisories: %w", err)
	}
	releaseHandler, releasePublisher, err := newReleaseRepository(resources)
	if err != nil {
		return fmt.Errorf("initialize release repository: %w", err)
	}
	devices, err := device.New(pool, device.Config{
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
		ServerRelease:                buildinfo.Current().Version,
		ServerProtocol:               buildinfo.ProtocolVersion,
		RequireReleaseCompatibility:  true,
	})
	if err != nil {
		return fmt.Errorf("initialize device service: %w", err)
	}
	var deliveries *integrations.Service
	var reporting *reports.Service
	if resources.Proto.GetIntegrations() != nil {
		deliveries, err = integrations.New(pool, auth, resources.IntegrationEncryptionKey, time.Now)
		if err != nil {
			return fmt.Errorf("initialize integrations: %w", err)
		}
		signer, ok := resources.ServerCertificate.PrivateKey.(crypto.Signer)
		if !ok {
			return errors.New("server TLS key cannot sign report manifests")
		}
		reporting, err = reports.New(pool, auth, signer, resources.ServerCertificate.Certificate)
		if err != nil {
			return fmt.Errorf("initialize reports: %w", err)
		}
	}
	cleanupCtx, cancelCleanup := context.WithCancel(ctx)
	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		devices.RunSnapshotCleanup(cleanupCtx)
	}()
	defer func() {
		cancelCleanup()
		<-cleanupDone
	}()
	advisoryCtx, cancelAdvisories := context.WithCancel(ctx)
	advisoryDone := make(chan struct{})
	go func() {
		defer close(advisoryDone)
		advisories.Run(advisoryCtx)
	}()
	defer func() {
		cancelAdvisories()
		<-advisoryDone
	}()
	console, err := web.Handler()
	if err != nil {
		return err
	}

	adminMux := http.NewServeMux()
	identityHandler := auth.Handler()
	adminMux.Handle("/auth/", identityHandler)
	adminMux.Handle("/scim/v2/", identityHandler)
	path, handler := devices.AdminHandler()
	adminMux.Handle(path, auth.RequireSession(handler))
	path, handler = devices.ReleaseManagementHandler()
	adminMux.Handle(path, auth.RequireSession(handler))
	if releaseHandler != nil {
		adminMux.Handle("/updates/", http.StripPrefix("/updates/", releaseHandler))
	}
	if deliveries != nil {
		path, handler = deliveries.AdminHandler()
		adminMux.Handle(path, auth.RequireSession(handler))
		path, handler = reporting.AdminHandler()
		adminMux.Handle(path, auth.RequireSession(handler))
	}
	path, handler = devices.EnrollmentHandler()
	adminMux.Handle(path, handler)
	adminMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	adminMux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		probe, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(probe); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	adminMux.Handle("/", console)
	deviceMux := http.NewServeMux()
	path, handler = devices.DeviceHandler()
	deviceMux.Handle(path, handler)

	requestContext, cancelRequests := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelRequests()
	admin := httpServer(config.Address(resources.Proto.GetAdminListener()), adminMux, requestContext)
	admin.TLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{resources.ServerCertificate},
	}
	deviceServer := httpServer(config.Address(resources.Proto.GetDeviceListener()), deviceMux, requestContext)
	deviceRoots := x509.NewCertPool()
	deviceRoots.AddCert(resources.DeviceCACertificate)
	deviceServer.TLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{resources.ServerCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    deviceRoots,
	}
	listenerConfig := new(net.ListenConfig)
	adminListener, err := listenerConfig.Listen(ctx, "tcp", admin.Addr)
	if err != nil {
		return fmt.Errorf("bind administrative listener: %w", err)
	}
	deviceListener, err := listenerConfig.Listen(ctx, "tcp", deviceServer.Addr)
	if err != nil {
		return errors.Join(fmt.Errorf("bind device listener: %w", err), adminListener.Close())
	}
	profiling, err := newProfiler(ctx, resources.Proto.GetProfiling())
	if err != nil {
		return errors.Join(err, adminListener.Close(), deviceListener.Close())
	}

	workerContext, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()
	stopped := make(chan error, 5)
	go func() { stopped <- serve(admin, adminListener) }()
	go func() { stopped <- serve(deviceServer, deviceListener) }()
	slog.Info("control plane ready", "admin", admin.Addr, "device", deviceServer.Addr)
	remaining := 2
	if profiling != nil {
		remaining++
		go func() { stopped <- profiling.run(workerContext) }()
	}
	if deliveries != nil {
		remaining += 2
		go func() { stopped <- deliveries.Run(workerContext) }()
		go func() { stopped <- reporting.Run(workerContext) }()
	}
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
		w.Header().Set("Referrer-Policy", "no-referrer")
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
