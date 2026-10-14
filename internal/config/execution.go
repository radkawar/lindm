// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"

	"lindm/internal/trust"
)

// ExecutionBootstrap retains the exact verified public installation documents.
// The authority store persists their original acceptance for historical replay.
// Online plan/start private keys are a separate resource and are not stored here.
type ExecutionBootstrap struct {
	RootJSON          []byte
	Envelope          []byte
	ReleaseRootJSON   []byte
	TransportCAPEM    []byte
	InitialDelegation *agentv1.UpdateExecutionTrustRequest
}

func (d *Document) executionBootstrap(resources *Resources) (*ExecutionBootstrap, *trust.ExecutionVerifier, error) {
	configured := d.Proto.GetExecutionBootstrap()
	if configured == nil {
		return nil, nil, nil
	}
	root, err := readFile(reference(d.base, configured.GetRootFile()), false)
	if err != nil {
		return nil, nil, fmt.Errorf("read execution_bootstrap.root_file: %w", err)
	}
	envelope, err := readFile(reference(d.base, configured.GetBootstrapFile()), false)
	if err != nil {
		return nil, nil, fmt.Errorf("read execution_bootstrap.bootstrap_file: %w", err)
	}
	authority, err := trust.New()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	verified, err := authority.VerifyBootstrap(context.Background(), root, envelope, now)
	if err != nil {
		return nil, nil, fmt.Errorf("verify execution bootstrap: %w", err)
	}
	if verified.Root.GetDeploymentId() != d.Proto.GetDeploymentId() {
		return nil, nil, errors.New("execution bootstrap deployment differs from server configuration")
	}
	if verified.Bundle.GetEnrollmentOrigin() != d.Proto.GetPublicUrl() || verified.Bundle.GetDeviceOrigin() != d.Proto.GetDevicePublicUrl() {
		return nil, nil, errors.New("execution bootstrap origins differ from server configuration")
	}
	if !verified.DeviceCA.Equal(resources.DeviceCACertificate) {
		return nil, nil, errors.New("execution bootstrap device CA differs from server configuration")
	}
	intermediates := x509.NewCertPool()
	for _, encoded := range resources.ServerCertificate.Certificate[1:] {
		certificate, err := x509.ParseCertificate(encoded)
		if err != nil {
			return nil, nil, fmt.Errorf("parse server TLS intermediate: %w", err)
		}
		intermediates.AddCert(certificate)
	}
	for _, origin := range []string{d.Proto.GetPublicUrl(), d.Proto.GetDevicePublicUrl()} {
		endpoint, err := url.Parse(origin)
		if err != nil {
			return nil, nil, fmt.Errorf("parse execution bootstrap origin: %w", err)
		}
		if _, err := resources.ServerCertificate.Leaf.Verify(x509.VerifyOptions{
			Roots: verified.TransportRoots, Intermediates: intermediates,
			DNSName: endpoint.Hostname(), CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			return nil, nil, fmt.Errorf("server TLS does not satisfy execution bootstrap transport pins: %w", err)
		}
	}
	verifier, err := authority.NewExecutionVerifier(verified, resources.ServerCertificate.Leaf.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("execution bootstrap reuses a server TLS key: %w", err)
	}
	var initial *agentv1.UpdateExecutionTrustRequest
	if configured.GetInitialDelegationFile() != "" {
		encoded, err := readFile(reference(d.base, configured.GetInitialDelegationFile()), false)
		if err != nil {
			return nil, nil, fmt.Errorf("read execution_bootstrap.initial_delegation_file: %w", err)
		}
		initial, err = decodeInitialDelegation(encoded)
		if err != nil {
			return nil, nil, err
		}
	}
	return &ExecutionBootstrap{RootJSON: root, Envelope: envelope, ReleaseRootJSON: verified.Bundle.GetReleaseRootJson(), TransportCAPEM: verified.Bundle.GetTransportCaPem(), InitialDelegation: initial}, verifier, nil
}

// Loading a signed request is not admission. The authority store verifies its
// signatures, expiry, deployment, rollback counters and key separation while the
// first owner's credential transaction holds the principal and authority fences.
func decodeInitialDelegation(encoded []byte) (*agentv1.UpdateExecutionTrustRequest, error) {
	request := new(agentv1.UpdateExecutionTrustRequest)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(encoded, request); err != nil {
		return nil, fmt.Errorf("decode initial execution delegation: %w", err)
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(request))
	if err != nil {
		return nil, fmt.Errorf("compile initial execution delegation validation: %w", err)
	}
	if err := validator.Validate(request); err != nil {
		return nil, fmt.Errorf("validate initial execution delegation: %w", err)
	}
	return request, nil
}
