// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// entraGraphProxy tunnels TLS unchanged. The failure switch closes existing Graph
// tunnels as well as rejecting new ones; login.microsoftonline.com stays reachable.
// There is no TLS interception, cached response, host firewall or production seam.
type entraGraphProxy struct {
	origin         string
	server         *http.Server
	done           chan error
	mu             sync.Mutex
	failed, closed bool
	tunnels        map[net.Conn]bool
	workers        sync.WaitGroup
}

func openEntraGraphProxy() (*entraGraphProxy, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &entraGraphProxy{origin: "http://" + listener.Addr().String(), done: make(chan error, 1), tunnels: make(map[net.Conn]bool)}
	p.server = &http.Server{Handler: http.HandlerFunc(p.serve), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second}
	go func() { p.done <- p.server.Serve(listener) }()
	return p, nil
}

func (p *entraGraphProxy) serve(w http.ResponseWriter, r *http.Request) {
	graph := r.Host == "graph.microsoft.com:443"
	if r.Method != http.MethodConnect || (!graph && r.Host != "login.microsoftonline.com:443") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	p.mu.Lock()
	blocked := p.closed || (graph && p.failed)
	if !blocked {
		p.workers.Add(1)
	}
	p.mu.Unlock()
	if blocked {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer p.workers.Done()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	upstream, err := (&net.Dialer{}).DialContext(ctx, "tcp", r.Host)
	cancel()
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer func() { _ = upstream.Close() }()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	downstream, buffer, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = downstream.Close() }()
	p.mu.Lock()
	if p.closed || (graph && p.failed) {
		p.mu.Unlock()
		return
	}
	p.tunnels[upstream], p.tunnels[downstream] = graph, graph
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.tunnels, upstream); delete(p.tunnels, downstream); p.mu.Unlock() }()
	if _, err := buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffer.Flush(); err != nil {
		return
	}
	// Bound all tunnels independently of normal process cleanup.
	if err := upstream.SetDeadline(time.Now().Add(20 * time.Minute)); err != nil {
		return
	}
	if err := downstream.SetDeadline(time.Now().Add(20 * time.Minute)); err != nil {
		return
	}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = io.Copy(upstream, buffer); _ = upstream.Close() }()
	_, _ = io.Copy(downstream, upstream)
	_ = downstream.Close()
	<-done
}

func (p *entraGraphProxy) fail() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failed = true
	var err error
	for connection, graph := range p.tunnels {
		if graph {
			closeErr := connection.Close()
			if !errors.Is(closeErr, net.ErrClosed) {
				err = errors.Join(err, closeErr)
			}
		}
	}
	return err
}

func (p *entraGraphProxy) close() error {
	p.mu.Lock()
	p.closed = true
	for connection := range p.tunnels {
		_ = connection.Close()
	}
	p.mu.Unlock()
	err := p.server.Close()
	serveErr := <-p.done
	if !errors.Is(serveErr, http.ErrServerClosed) {
		err = errors.Join(err, serveErr)
	}
	p.workers.Wait()
	return err
}

func (p *entraGraphProxy) environment() []string {
	environment := make([]string, 0, len(os.Environ())+6)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(name) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
			continue
		}
		environment = append(environment, entry)
	}
	return append(environment, "HTTPS_PROXY="+p.origin, "HTTP_PROXY="+p.origin, "NO_PROXY=localhost,127.0.0.1,::1")
}
