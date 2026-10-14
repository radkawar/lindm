// SPDX-License-Identifier: Apache-2.0

package loadlab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	devicev1connect "lindm/gen/lindm/device/v1/devicev1connect"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
)

type simulatedDevice struct {
	id, generation, boot, incarnation    string
	installation                         string
	key                                  ed25519.PrivateKey
	certificate                          []byte
	transport                            *http.Transport
	client                               devicev1connect.DeviceServiceClient
	epoch, hostSequence, packageSequence uint64
	root                                 *agentv1.ExecutionRoot
	delegation                           *agentv1.ExecutionDelegation
	rootDigest, delegationDigest         []byte
	completed                            map[string]bool
	pending                              *pendingService
	// serviceSequences retains the last executed sequence per resource ref;
	// serviceReports counts every admitted terminal service report.
	serviceSequences map[string]uint64
	serviceReports   int
	inventoryUpload  *pendingInventoryUpload
	lastInventory    time.Time
	// demo selects a console demo host and executor results; nil for capacity.
	demo *demoDevice
}

func (r *runner) transport(address string, certificate *tls.Certificate) *http.Transport {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: r.roots}
	if certificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*certificate}
	}
	return &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: 30 * time.Second, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
	}}
}

// enroll performs the owner-side grant and assignment around the device-side
// protocol. A remote generator runs only enrollDevice; grants never leave the
// orchestrator except as the one-use secret consumed by that enrollment.
func (r *runner) enroll(ctx context.Context, index int) (*simulatedDevice, error) {
	var secret string
	var err error
	if index < len(r.demo) {
		secret = r.demo[index].provisioningToken
		if secret == "" {
			return nil, errors.New("demo device requires its organization provisioning token")
		}
	} else {
		secret, err = r.grant(ctx, index)
		if err != nil {
			return nil, err
		}
	}
	d, err := r.enrollDevice(ctx, index, secret)
	if err != nil {
		return nil, err
	}
	if err := r.assign(ctx, index, d.id); err != nil {
		d.close()
		return nil, err
	}
	return d, nil
}
func (r *runner) grant(ctx context.Context, index int) (string, error) {
	started := time.Now()
	granted, err := r.owner.Admin.CreateEnrollmentGrant(ctx, connect.NewRequest(&adminv1.CreateEnrollmentGrantRequest{RequestId: uuid.NewString(), LifetimeSeconds: 300, Reason: "disposable capacity simulated device"}))
	r.metrics.observe("CreateEnrollmentGrant", time.Since(started), err)
	if err != nil {
		return "", fmt.Errorf("device %d: create enrollment grant: %w", index, err)
	}
	return granted.Msg.GetSecret(), nil
}
func (r *runner) assign(ctx context.Context, index int, id string) error {
	if index%100 >= r.options.AssignmentPercent {
		return nil
	}
	started := time.Now()
	_, err := r.owner.Admin.SetResourceAssignment(ctx, connect.NewRequest(&adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: id, Target: &adminv1.ResourceAssignmentTarget{ProfileId: r.profile.GetProfileId(), RevisionId: r.profile.GetRevisionId()}, Reason: "disposable capacity service assignment"}))
	r.metrics.observe("SetResourceAssignment", time.Since(started), err)
	if err != nil {
		return fmt.Errorf("device %d: assign resource profile: %w", index, err)
	}
	return nil
}
func (r *runner) enrollDevice(ctx context.Context, index int, secret string) (d *simulatedDevice, resultErr error) {
	d = &simulatedDevice{boot: uuid.NewString(), incarnation: uuid.NewString(), installation: uuid.NewString(), root: r.bootstrap.Root, rootDigest: r.rootDigest, completed: make(map[string]bool), serviceSequences: make(map[string]uint64)}
	if index < len(r.demo) {
		d.demo = r.demo[index]
	}
	defer func() {
		if resultErr != nil {
			d.close()
		}
	}()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return d, err
	}
	d.key = key
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return d, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
	if d.demo != nil {
		provisioned, err := r.enrollment.Provision(ctx, connect.NewRequest(&enrollmentv1.ProvisionRequest{ProvisioningToken: secret, TransactionId: uuid.NewString(), InstallationId: d.installation, CsrPem: csrPEM}))
		if err != nil {
			return d, fmt.Errorf("device %d: provision: %w", index, err)
		}
		d.id, d.generation, d.certificate = provisioned.Msg.GetDeviceId(), provisioned.Msg.GetEnrollmentGeneration(), provisioned.Msg.GetCertificatePem()
	} else {
		enrolled, err := r.enrollment.Enroll(ctx, connect.NewRequest(&enrollmentv1.EnrollRequest{GrantSecret: secret, TransactionId: uuid.NewString(), CsrPem: csrPEM}))
		if err != nil {
			return d, fmt.Errorf("device %d: enroll: %w", index, err)
		}
		d.id, d.generation, d.certificate = enrolled.Msg.GetDeviceId(), enrolled.Msg.GetEnrollmentGeneration(), enrolled.Msg.GetCertificatePem()
	}
	block, _ := pem.Decode(d.certificate)
	if block == nil {
		return d, errors.New("missing enrollment certificate")
	}
	certificate := tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key}
	d.transport = r.transport(r.deviceAddress, &certificate)
	d.client = devicev1connect.NewDeviceServiceClient(&http.Client{Transport: d.transport, Timeout: 30 * time.Second}, r.bootstrap.Bundle.GetDeviceOrigin(), connect.WithInterceptors(r.metrics))
	proof, err := r.authority.Sign(ctx, &agentv1.SessionAcquisition{DeploymentId: r.bootstrap.Bundle.GetDeploymentId(), DeviceId: d.id, EnrollmentGeneration: d.generation, RequestId: uuid.NewString(), Incarnation: d.incarnation, BootId: d.boot, AgentRelease: r.agentRelease, AgentProtocolVersion: r.agentProtocol, InstallationId: d.installation}, key)
	if err != nil {
		return d, fmt.Errorf("device %d: sign session acquisition: %w", index, err)
	}
	acquired, err := d.client.AcquireSession(ctx, connect.NewRequest(&devicev1.AcquireSessionRequest{AuthorityProof: proof}))
	if err != nil {
		return d, fmt.Errorf("device %d: acquire session: %w", index, err)
	}
	d.epoch = acquired.Msg.GetSessionEpoch()
	if err := r.syncTrust(ctx, d); err != nil {
		return d, fmt.Errorf("device %d: sync execution trust: %w", index, err)
	}
	if d.demo != nil && d.demo.agent != nil {
		if err := r.acceptCapabilityPolicy(ctx, d); err != nil {
			return d, fmt.Errorf("device %d: accept capability policy: %w", index, err)
		}
	}
	if d.demo != nil && d.demo.factsWithheld {
		return d, nil
	}
	if err := r.inventory(ctx, d, index); err != nil {
		return d, fmt.Errorf("device %d: report inventory: %w", index, err)
	}
	return d, nil
}
func (d *simulatedDevice) close() {
	if d.transport != nil {
		d.transport.CloseIdleConnections()
	}
	clear(d.key)
}
func (r *runner) syncTrust(ctx context.Context, d *simulatedDevice) error {
	request := &devicev1.GetExecutionTrustRequest{SessionEpoch: d.epoch, RootVersion: d.root.GetVersion(), RootSha256: d.rootDigest}
	if d.delegation != nil {
		request.DelegationVersion = d.delegation.GetVersion()
		request.DelegationSha256 = d.delegationDigest
		request.MinimumRecoveryEpoch = d.delegation.GetMinimumRecoveryEpoch()
	}
	response, err := d.client.GetExecutionTrust(ctx, connect.NewRequest(request))
	if err != nil {
		return err
	}
	update := response.Msg.GetUpdate()
	if update == nil {
		return nil
	}
	for _, transition := range update.GetRootTransitions() {
		root, err := r.verifier.VerifyRootTransition(ctx, d.root, transition, time.Now())
		if err != nil {
			return fmt.Errorf("verify root transition: %w", err)
		}
		d.root = root
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(root)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(encoded)
		d.rootDigest = digest[:]
	}
	if envelope := update.GetDelegationEnvelope(); len(envelope) > 0 {
		delegation, err := r.verifier.VerifyDelegation(ctx, d.root, envelope, d.delegation.GetVersion(), d.delegation.GetMinimumRecoveryEpoch(), time.Now())
		if err != nil {
			return fmt.Errorf("verify delegation: %w", err)
		}
		d.delegation = delegation
		digest := sha256.Sum256(envelope)
		d.delegationDigest = digest[:]
	}
	return nil
}
func stamp() *timestamppb.Timestamp { return timestamppb.New(time.Now().UTC()) }
func label(index int) string        { return fmt.Sprintf("load-device-%06d", index) }
