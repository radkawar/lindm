// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/net/netutil"

	"lindm/internal/agent/config"
	"lindm/internal/agent/connectivityguard"
)

// serveConnectivityProbe is an explicit dedicated external-peer command, not
// part of lindmd or the ordinary executor. It takes no URLs, paths, or secrets
// from argv. All native packet targets and TLS/proof keys are root provisioned.
func serveConnectivityProbe(ctx context.Context, args []string) (err error) {
	if len(args) != 0 || os.Geteuid() != 0 {
		return errors.New("connectivity-probe requires root and accepts no arguments")
	}
	document, err := config.Load(config.ExecutorConfigPath)
	if err != nil {
		return err
	}
	cfg := document.Proto.GetConnectivityProbe()
	if cfg == nil {
		return errors.New("connectivity-probe is not provisioned on this host")
	}
	tlsConfig, key, err := document.ConnectivityProbeTLS()
	if err != nil {
		return err
	}
	defer clear(key)
	witness, err := connectivityguard.NewProbeServer(ctx, cfg.GetOrigin(), cfg.GetDeploymentId(), cfg.GetTargets(), key)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, witness.Close()) }()
	listener, err := net.Listen("tcp", net.JoinHostPort(cfg.GetListenAddress(), strconv.FormatUint(uint64(cfg.GetListenPort()), 10)))
	if err != nil {
		return err
	}
	server := &http.Server{Handler: witness, TLSConfig: tlsConfig, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192, BaseContext: func(net.Listener) context.Context { return ctx }}
	stopped := make(chan error, 1)
	go func() { stopped <- server.Serve(tls.NewListener(netutil.LimitListener(listener, 64), tlsConfig)) }()
	select {
	case serveErr := <-stopped:
		if errors.Is(serveErr, http.ErrServerClosed) {
			return nil
		}
		return serveErr
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr := server.Shutdown(shutdown)
		closeErr := server.Close()
		serveErr := <-stopped
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		return errors.Join(shutdownErr, closeErr, serveErr)
	}
}
