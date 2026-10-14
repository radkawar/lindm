// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	"lindm/gen/lindm/enrollment/v1/enrollmentv1connect"
	"lindm/internal/devlab"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

func approveUnattendedGuest(ctx context.Context, vm *guestVM, owner, approver *devlab.OwnerSession, tokenID string, evidence *unattendedDeviceEvidence) error {
	status, err := readGuestAgentStatus(ctx, vm)
	if err != nil {
		return err
	}
	if status.GetExecutor().GetLifecycle() != agentv1.Lifecycle_LIFECYCLE_PENDING_ENROLLMENT {
		return errors.New("approval-required guest acquired authority before approval")
	}
	pending, err := owner.Admin.GetPendingEnrollments(ctx, connect.NewRequest(&adminv1.GetPendingEnrollmentsRequest{PageSize: 200}))
	if err != nil {
		return vmControlPlaneError("observe pending enrollment", err)
	}
	var target *adminv1.PendingEnrollment
	for _, entry := range pending.Msg.GetEnrollments() {
		if entry.GetTokenId() == tokenID && entry.GetInstallationId() == status.GetExecutor().GetInstallationId() {
			target = entry
		}
	}
	if target == nil || target.GetState() != "pending_approval" || !vmValidID(target.GetApprovalId()) {
		return errors.New("native pending installation has no bound approval inbox entry")
	}
	evidence.DeviceID, evidence.Generation, evidence.InstallationID = target.GetDeviceId(), target.GetEnrollmentGeneration(), target.GetInstallationId()
	request := &adminv1.ApprovePendingEnrollmentRequest{RequestId: target.GetTransactionId(), TransactionId: target.GetTransactionId(), DeviceId: target.GetDeviceId(), Reason: unattendedReason, ApprovalId: target.GetApprovalId()}
	_, denied := owner.Admin.ApprovePendingEnrollment(ctx, connect.NewRequest(request))
	if connect.CodeOf(denied) != connect.CodePermissionDenied {
		return errors.New("pending enrollment was not denied before independent approval")
	}
	evidence.PendingDenied = true
	_, denied = owner.Admin.ApproveApproval(ctx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: target.GetApprovalId(), Reason: unattendedReason}))
	if connect.CodeOf(denied) != connect.CodePermissionDenied {
		return errors.New("token creator was not denied self approval")
	}
	evidence.SelfApprovalDenied = true
	before, err := owner.Admin.GetDevice(ctx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: target.GetDeviceId()}))
	if err != nil {
		return vmControlPlaneError("observe pending device", err)
	}
	if before.Msg.GetDevice().GetLifecycleState() != adminv1.DeviceState_DEVICE_STATE_PENDING || before.Msg.GetDevice().GetLastSeenAt() != nil || before.Msg.GetCurrentSnapshot() != nil {
		return errors.New("pending device activated or published before approval")
	}
	services, err := owner.Admin.GetDeviceResourceState(ctx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: target.GetDeviceId()}))
	if err != nil {
		return vmControlPlaneError("observe pending assignment denial", err)
	}
	if services.Msg.GetAssignment() != nil || len(services.Msg.GetRecentActions()) != 0 {
		return errors.New("pending device received executable service assignment before approval")
	}
	approved, err := approver.ApproveApproval(ctx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: target.GetApprovalId(), Reason: unattendedReason}))
	if err != nil {
		return vmControlPlaneError("independently approve enrollment", err)
	}
	if approved.Msg.GetApproval().GetRequesterId() != owner.AccountID || approved.Msg.GetApproval().GetApproverId() != approver.AccountID || owner.AccountID == approver.AccountID || approved.Msg.GetApproval().GetState() != adminv1.ApprovalState_APPROVAL_STATE_APPROVED {
		return errors.New("approval did not bind independent human authority")
	}
	if _, err := owner.Admin.ApprovePendingEnrollment(ctx, connect.NewRequest(request)); err != nil {
		return vmControlPlaneError("consume independent enrollment approval", err)
	}
	evidence.ApproverID = approver.AccountID
	return nil
}

// The exhaustion probe is a real third reservation with a fresh valid key, not
// a malformed-request rejection or replay of one of the two admitted devices.
func probeUnattendedExhaustion(ctx context.Context, public *devlab.AgentFixture, token []byte) (string, error) {
	authority, err := trust.New()
	if err != nil {
		return "", err
	}
	verified, err := authority.VerifyBootstrap(ctx, public.ExecutionRootJSON, public.BootstrapEnvelope, time.Now())
	if err != nil {
		return "", err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: verified.ConsoleRoots}, ResponseHeaderTimeout: 15 * time.Second}
	defer transport.CloseIdleConnections()
	client := enrollmentv1connect.NewEnrollmentServiceClient(&http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, verified.Bundle.GetEnrollmentOrigin())
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	defer clear(key)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return "", err
	}
	_, denied := client.Provision(ctx, connect.NewRequest(&enrollmentv1.ProvisionRequest{ProvisioningToken: string(token), TransactionId: uuid.NewString(), InstallationId: uuid.NewString(), CsrPem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})}))
	return unattendedExhaustionReason(denied)
}

func unattendedExhaustionReason(err error) (string, error) {
	var rpc *connect.Error
	if !errors.As(err, &rpc) || rpc.Code() != connect.CodeResourceExhausted || rpcreason.Get(rpc) != "provisioning_token_exhausted" {
		return "", errors.New("third distinct provisioning use did not return the exact exhaustion denial")
	}
	return "provisioning_token_exhausted", nil
}
