//go:build linux

// Package enrollment performs the public enrollment exchange using only the
// HTTPS origin and transport trust authenticated by the root executor.
package enrollment

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"

	agentv1 "lindm/gen/lindm/agent/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	"lindm/gen/lindm/enrollment/v1/enrollmentv1connect"
)

// ErrPendingApproval means the immutable reservation exists without usable authority.
var ErrPendingApproval = errors.New("enrollment awaits administrator approval; run lindm-agent resume")

// Enroll sends the protected pending transaction through pinned TLS. It does
// not install the certificate or alter the executor's durable pending intent.
func Enroll(ctx context.Context, pins *agentv1.PrepareBootstrapResponse) (*enrollmentv1.EnrollResponse, error) {
	if pins == nil {
		return nil, errors.New("missing enrollment material")
	}
	origin, err := url.Parse(pins.GetEnrollmentOrigin())
	if err != nil || len(pins.GetEnrollmentOrigin()) > 2048 ||
		origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil ||
		origin.Opaque != "" || (origin.Path != "" && origin.Path != "/") || origin.RawPath != "" ||
		origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" || origin.RawFragment != "" ||
		strings.ContainsAny(pins.GetEnrollmentOrigin(), "?#") {
		return nil, errors.New("invalid enrollment origin")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pins.GetTransportCaPem()) {
		return nil, errors.New("invalid transport trust")
	}
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("enrollment redirect is not accepted")
		},
		Transport: &http.Transport{
			DialContext:            (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool},
			TLSHandshakeTimeout:    10 * time.Second,
			ResponseHeaderTimeout:  15 * time.Second,
			MaxResponseHeaderBytes: 16 << 10,
		},
	}
	defer httpClient.CloseIdleConnections()
	client := enrollmentv1connect.NewEnrollmentServiceClient(httpClient, origin.String(), connect.WithReadMaxBytes(64<<10))
	if pins.GetOfflineRequest() != nil {
		return nil, errors.New("offline enrollment requires a signed response file")
	}
	if pins.GetProvisioningToken() {
		return provision(ctx, client, pins)
	}
	response, err := client.Enroll(ctx, connect.NewRequest(&enrollmentv1.EnrollRequest{
		GrantSecret: pins.GetPendingGrant(), TransactionId: pins.GetEnrollmentTransactionId(), CsrPem: pins.GetCsrPem(),
	}))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func provision(ctx context.Context, client enrollmentv1connect.EnrollmentServiceClient, pins *agentv1.PrepareBootstrapResponse) (*enrollmentv1.EnrollResponse, error) {
	var result *enrollmentv1.ProvisionResponse
	if pins.GetResumed() {
		retrieved, err := client.RetrieveProvisioningIssuance(ctx, connect.NewRequest(&enrollmentv1.RetrieveProvisioningIssuanceRequest{AuthorityProof: pins.GetProvisioningRetrievalProof()}))
		if err == nil {
			result = retrieved.Msg.GetEnrollment()
		} else if connect.CodeOf(err) != connect.CodeNotFound {
			return nil, err
		}
	}
	if result == nil {
		response, err := client.Provision(ctx, connect.NewRequest(&enrollmentv1.ProvisionRequest{ProvisioningToken: pins.GetPendingGrant(), TransactionId: pins.GetEnrollmentTransactionId(), CsrPem: pins.GetCsrPem(), InstallationId: pins.GetInstallationId()}))
		if err != nil {
			return nil, err
		}
		result = response.Msg
	}
	if result.GetState() == "pending_approval" {
		return nil, ErrPendingApproval
	}
	if result.GetState() != "ready" || len(result.GetCertificatePem()) == 0 {
		return nil, errors.New("invalid provisioning issuance state")
	}
	return &enrollmentv1.EnrollResponse{DeviceId: result.GetDeviceId(), EnrollmentGeneration: result.GetEnrollmentGeneration(), CertificatePem: result.GetCertificatePem(), ExpiresAt: result.GetExpiresAt()}, nil
}
