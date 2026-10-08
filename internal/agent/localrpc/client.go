//go:build linux

package localrpc

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
	"lindm/internal/trust"
)

// BaseURL is the Connect base URL for Dial. The host is not resolved; the
// client dials the Unix socket supplied to Dial.
const BaseURL = "http://lindm-executor.invalid"

// Dial returns a Connect client for socketPath and a cleanup that closes idle
// connections. The caller must call cleanup. Every connection checks
// SO_PEERCRED and refuses a peer that is not UID 0 before any HTTP request
// bytes are written. There is no non-root fallback.
func Dial(socketPath string) (agentv1connect.ExecutorServiceClient, func() error, error) {
	return dial(socketPath, requireRootPeer)
}

func dial(socketPath string, authenticate func(net.Conn) error) (agentv1connect.ExecutorServiceClient, func() error, error) {
	if socketPath == "" || authenticate == nil {
		return nil, nil, errors.New("missing executor socket")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			conn, err := dialer.DialContext(ctx, "unix", socketPath)
			if err != nil {
				return nil, err
			}
			if err := authenticate(conn); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return conn, nil
		},
	}
	httpClient := &http.Client{Transport: transport}
	cleanup := func() error {
		httpClient.CloseIdleConnections()
		return nil
	}
	return agentv1connect.NewExecutorServiceClient(httpClient, BaseURL), cleanup, nil
}

func requireRootPeer(conn net.Conn) error {
	uid, err := peerCredential(conn)
	if err != nil {
		return err
	}
	if uid != 0 {
		return errors.New("executor socket peer is not root")
	}
	return nil
}

// NewTLSSigner returns a pure Ed25519 message signer for one certificate.
// Each signature uses ctx as its parent and a 15-second deadline. The private
// key remains in the executor; certificate selects it by SHA-256 of cert.Raw.
func NewTLSSigner(ctx context.Context, client agentv1connect.ExecutorServiceClient, certificate *x509.Certificate) (*trust.TLSMessageSigner, error) {
	if ctx == nil || client == nil || certificate == nil {
		return nil, errors.New("invalid TLS message signer")
	}
	public, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("TLS message signer requires an Ed25519 certificate")
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	return trust.NewTLSMessageSigner(public, func(message []byte) ([]byte, error) {
		call, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		response, err := client.SignTLSClientMessage(call, connect.NewRequest(&agentv1.SignTLSClientMessageRequest{
			CertificateSha256: bytesClone(fingerprint[:]),
			Message:           message,
		}))
		if err != nil {
			return nil, err
		}
		signature := response.Msg.GetSignature()
		if len(signature) != ed25519.SignatureSize {
			return nil, errors.New("invalid TLS signature")
		}
		return signature, nil
	})
}

func bytesClone(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
