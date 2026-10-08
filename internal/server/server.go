// Package server composes the control plane and owns its process lifetime.
package server

import (
	"context"
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
	"lindm/internal/config"
	"lindm/internal/device"
	"lindm/internal/identity"
	"lindm/web"
)

// NewIdentity composes the same configured identity service for serving and local
// owner bootstrap. Neither path can bypass upstream directory authorization.
func NewIdentity(ctx context.Context, pool *pgxpool.Pool, resources *config.Resources) (*identity.Service, error) {
	oidc := resources.Proto.GetOidc()
	return identity.New(ctx, pool, identity.Config{
		Issuer:                oidc.GetIssuer(),
		ClientID:              oidc.GetClientId(),
		ClientSecret:          resources.ClientSecret,
		DirectoryClientID:     oidc.GetDirectoryClientId(),
		DirectoryClientSecret: resources.DirectoryClientSecret,
		PublicURL:             resources.Proto.GetPublicUrl(),
		AdminGroups:           oidc.GetAdministratorGroups(),
		HTTPClient:            resources.HTTPClient,
	})
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
	devices, err := device.New(pool, device.Config{
		DeploymentID:  resources.Proto.GetDeploymentId(),
		CACertificate: resources.DeviceCACertificate,
		CAKey:         resources.DeviceCAKey,
	})
	if err != nil {
		return fmt.Errorf("initialize device service: %w", err)
	}
	console, err := web.Handler()
	if err != nil {
		return err
	}

	adminMux := http.NewServeMux()
	adminMux.Handle("/auth/", auth.Handler())
	path, handler := devices.AdminHandler()
	adminMux.Handle(path, auth.RequireSession(handler))
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

	stopped := make(chan error, 2)
	go func() { stopped <- serve(admin, adminListener) }()
	go func() { stopped <- serve(deviceServer, deviceListener) }()
	slog.Info("control plane ready", "admin", admin.Addr, "device", deviceServer.Addr)
	remaining := 2
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-stopped:
		remaining--
	}
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
