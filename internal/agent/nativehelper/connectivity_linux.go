// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nativehelper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/config"
	"lindm/internal/agent/connectivityguard"
	"lindm/internal/agent/localrpc"
	"lindm/internal/pki"
	"lindm/internal/trust"
)

// newFirewallGuard obtains authenticated enrollment pins directly from the
// root-authenticated local executor. The caller must close the returned custody
// after ApplyNative finishes. No private TLS key leaves the executor, and no
// profile, network relay or serialized request can select the controller origin.
func newFirewallGuard(ctx context.Context, document *config.Document, request *agentv1.NativeResourceTransactionRequest) (*connectivityguard.Guard, func() error, error) {
	if request.GetPlan().GetRef().GetKind() != 8 || request.GetOwnership() == nil {
		return nil, nil, connectivityguard.ErrConflict
	}
	return newNativeConnectivityGuard(ctx, document, request.GetOwnership(), func(ctx context.Context, request *agentv1.NativeResourceTransactionRequest, receipt []byte) error {
		return retainFirewallConfirmation(ctx, document.StateDirectory, request, receipt)
	})
}
func newFirewallVerifier(ctx context.Context, document *config.Document, request *agentv1.NativeResourceObservationRequest) (*connectivityguard.Guard, func() error, error) {
	if request.GetDesired().GetRef().GetKind() != 8 {
		return nil, nil, connectivityguard.ErrConflict
	}
	return newNativeConnectivityGuard(ctx, document, nil, nil)
}

// retainFirewallConfirmation durably seals the controller receipt in the exact
// per-action helper directory before the guard records COMMITTED.
func retainFirewallConfirmation(_ context.Context, stateDirectory string, request *agentv1.NativeResourceTransactionRequest, receipt []byte) error {
	directory, err := resourceDirectory(stateDirectory, "resource-transactions", request.GetActionId(), false)
	if err != nil {
		return err
	}
	return writeProtected(directory, "firewall-confirmation.pb", receipt)
}
func newNativeConnectivityGuard(ctx context.Context, document *config.Document, owner *agentv1.ResourceOwnershipLedger, retain func(context.Context, *agentv1.NativeResourceTransactionRequest, []byte) error) (*connectivityguard.Guard, func() error, error) {
	if document == nil || document.Proto.GetConnectivityGuard() == nil {
		return nil, nil, connectivityguard.ErrConflict
	}
	client, cleanup, err := localrpc.Dial(document.SocketPath)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*connectivityguard.Guard, func() error, error) {
		return nil, nil, errors.Join(err, cleanup())
	}
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	response, err := client.GetConnection(call, connect.NewRequest(&agentv1.GetConnectionRequest{}))
	if err != nil {
		return fail(err)
	}
	connection := response.Msg
	if !connection.GetSessionEpochUsable() || connection.GetSessionEpoch() == 0 || connection.GetIdentityExpired() || connection.GetDeviceActionReportOnly() {
		return fail(connectivityguard.ErrConflict)
	}
	if owner != nil && (owner.GetDeploymentId() != connection.GetDeploymentId() || owner.GetDeviceId() != connection.GetDeviceId() || owner.GetEnrollmentGeneration() != connection.GetEnrollmentGeneration()) {
		return fail(connectivityguard.ErrConflict)
	}
	if connection.GetCredentialKind() != agentv1.TLSCredentialKind_TLS_CREDENTIAL_KIND_ED25519 || len(connection.GetCertificatePem()) > 16384 {
		return fail(connectivityguard.ErrConflict)
	}
	block, rest := pem.Decode(connection.GetCertificatePem())
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return fail(connectivityguard.ErrConflict)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fail(err)
	}
	deployment, err := uuid.Parse(connection.GetDeploymentId())
	if err != nil {
		return fail(err)
	}
	device, err := uuid.Parse(connection.GetDeviceId())
	if err != nil {
		return fail(err)
	}
	generation, err := uuid.Parse(connection.GetEnrollmentGeneration())
	if err != nil {
		return fail(err)
	}
	if err := pki.CheckDeviceCertificate(leaf, deployment, device, generation); err != nil {
		return fail(err)
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	if !bytes.Equal(fingerprint[:], connection.GetCertificateSha256()) {
		return fail(connectivityguard.ErrConflict)
	}
	public, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fail(connectivityguard.ErrConflict)
	}
	keyID, err := trust.KeyID(public)
	if err != nil || keyID != connection.GetKeyId() {
		return fail(errors.Join(connectivityguard.ErrConflict, err))
	}
	roots := x509.NewCertPool()
	if len(connection.GetTransportCaPem()) < 64 || len(connection.GetTransportCaPem()) > 65536 || !roots.AppendCertsFromPEM(connection.GetTransportCaPem()) {
		return fail(connectivityguard.ErrConflict)
	}
	tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, GetClientCertificate: func(handshake *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		signer, err := localrpc.NewTLSSigner(handshake.Context(), client, leaf)
		if err != nil {
			return nil, err
		}
		return &tls.Certificate{Certificate: [][]byte{leaf.Raw}, Leaf: leaf, PrivateKey: signer}, nil
	}}
	guard, err := connectivityguard.New(connectivityguard.Config{Directory: connectivityguard.StateDirectory, Policy: document.Proto.GetConnectivityGuard(), Native: document.Proto.GetFirewallProvider(), Origin: connection.GetDeviceOrigin(), TransportTLS: tlsConfig, DeploymentID: connection.GetDeploymentId(), DeviceID: connection.GetDeviceId(), EnrollmentGeneration: connection.GetEnrollmentGeneration(), SessionEpoch: connection.GetSessionEpoch(), RetainConfirmation: retain})
	if err != nil {
		return fail(err)
	}
	return guard, func() error { return errors.Join(guard.Close(), cleanup()) }, nil
}
