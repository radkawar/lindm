// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestDeployReadinessWaitsOnlyOnReadOnlyStartup(t *testing.T) {
	for _, reset := range []bool{false, true} {
		var calls atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/readyz" {
				t.Error("readiness issued another operation")
			}
			if calls.Add(1) == 1 {
				if reset {
					hijacker, ok := w.(http.Hijacker)
					if !ok {
						t.Error("TLS fixture cannot close the startup connection")
						return
					}
					connection, _, err := hijacker.Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					if err = connection.Close(); err != nil {
						t.Error(err)
					}
					return
				}
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		roots := x509.NewCertPool()
		roots.AddCert(server.Certificate())
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		err := waitDeployReadiness(ctx, server.URL, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots})
		cancel()
		server.Close()
		if err != nil || calls.Load() != 2 {
			t.Fatalf("startup observation: calls=%d err=%v", calls.Load(), err)
		}
	}
}

func TestDeployReadinessRefusesTrustAndUnexpectedHTTPWithoutRetry(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusFound, http.StatusInternalServerError} {
		var calls atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.Header().Set("Location", "/must-not-follow")
			w.WriteHeader(status)
		}))
		roots := x509.NewCertPool()
		roots.AddCert(server.Certificate())
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		err := waitDeployReadiness(ctx, server.URL, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots})
		if err == nil || calls.Load() != 1 {
			t.Fatalf("HTTP refusal retried: calls=%d err=%v", calls.Load(), err)
		}
		err = waitDeployReadiness(ctx, server.URL, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: x509.NewCertPool()})
		cancel()
		server.Close()
		var verification *tls.CertificateVerificationError
		if !errors.As(err, &verification) || calls.Load() != 1 {
			t.Fatalf("untrusted TLS did not fail before HTTP: calls=%d err=%v", calls.Load(), err)
		}
	}
}

func TestDeployReadinessDeadline(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	if err := waitDeployReadiness(ctx, server.URL, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unready service passed: %v", err)
	}
}

func TestDeployReadinessStartupFailureClasses(t *testing.T) {
	for _, err := range []error{syscall.ECONNREFUSED, syscall.ECONNRESET, io.EOF, io.ErrUnexpectedEOF} {
		if !deployReadinessStarting(err) {
			t.Fatalf("startup transport not observable: %v", err)
		}
	}
	for _, err := range []error{errors.New("permanent refusal"), &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}} {
		if deployReadinessStarting(err) {
			t.Fatalf("permanent refusal treated as startup: %v", err)
		}
	}
}
