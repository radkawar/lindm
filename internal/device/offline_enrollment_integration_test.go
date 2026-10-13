//go:build linux && integration

package device

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"lindm/internal/device/assistance"
	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	"lindm/internal/agent/executor"
	"lindm/internal/config"
	"lindm/internal/executionauthority"
	"lindm/internal/identity"
	"lindm/internal/trust"
)

type offlineFixture struct {
	*provisioningFixture
	root                *agentv1.ExecutionRoot
	rootJSON, bootstrap []byte
	rootKey             ed25519.PrivateKey
}

func newOfflineFixture(t *testing.T) *offlineFixture {
	t.Helper()
	f := &offlineFixture{provisioningFixture: newProvisioningFixture(t), rootKey: ed25519Key(t)}
	now := time.Now().UTC()
	public := func(key ed25519.PrivateKey) *agentv1.ExecutionKey {
		t.Helper()
		pub := ed25519.PublicKey(key[ed25519.SeedSize:])
		id, err := trust.KeyID(pub)
		if err != nil {
			t.Fatal(err)
		}
		return &agentv1.ExecutionKey{KeyId: id, PublicKey: pub}
	}
	sign := func(message proto.Message, key ed25519.PrivateKey) []byte {
		t.Helper()
		value, err := f.service.Authority.Sign(t.Context(), message, key)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	f.root = &agentv1.ExecutionRoot{DeploymentId: f.service.DeploymentID.String(), Version: 1, Threshold: 1, NotBefore: timestamppb.New(now.Add(-time.Hour)), ExpiresAt: timestamppb.New(now.Add(24 * time.Hour)), Keys: []*agentv1.ExecutionKey{public(f.rootKey)}}
	var err error
	f.rootJSON, err = protojson.Marshal(f.root)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(f.rootJSON)
	transportCA, _ := testCA(t, now.Add(48*time.Hour))
	bootstrap := &agentv1.BootstrapBundle{BundleId: uuid.NewString(), DeploymentId: f.service.DeploymentID.String(), EnrollmentOrigin: "https://offline-admin.example", DeviceOrigin: "https://offline-device.example", TransportCaPem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: transportCA.Raw}), DeviceCaPem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.service.CA.Raw}), ReleaseRootJson: dispatchReleaseRoot(t, now), ExecutionRootVersion: 1, ExecutionRootSha256: digest[:], NotBefore: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(now.Add(12 * time.Hour))}
	f.bootstrap = sign(bootstrap, f.rootKey)
	store, err := executionauthority.New(t.Context(), f.service.Pool, executionauthority.Config{RootJSON: f.rootJSON, BootstrapEnvelope: f.bootstrap, TLSPublicKey: ed25519Key(t).Public()})
	if err != nil {
		t.Fatal(err)
	}
	plan, start := ed25519Key(t), ed25519Key(t)
	delegation := &agentv1.ExecutionDelegation{DeploymentId: f.service.DeploymentID.String(), RootVersion: 1, Version: 1, NotBefore: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(now.Add(2 * time.Hour)), Delegates: []*agentv1.ExecutionDelegate{{Key: public(plan), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, Capabilities: []string{trust.OfflineEnrollmentCapability}}, {Key: public(start), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, Capabilities: []string{trust.OfflineEnrollmentCapability}}}}
	tx, err := f.service.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(t.Context(), tx, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: sign(delegation, f.rootKey)}, f.owner.ID, "admit isolated offline enrollment delegates"); err != nil {
		_ = tx.Rollback(t.Context())
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	old := f.service
	f.service, err = New(old.Pool, core.Config{DeploymentID: old.DeploymentID.String(), CACertificate: old.CA, CAKey: old.CAKey, Identity: old.Identity, ExecutionAuthority: store, ExecutionSigning: &config.ExecutionSigning{PlanKey: plan, StartKey: start}}, assistance.NewRuntime())
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *offlineFixture) authorization(t *testing.T, token *adminv1.CreateProvisioningTokenResponse) *agentv1.OfflineEnrollmentAuthorizationFile {
	t.Helper()
	digest, err := trust.ExecutionRootDigest(f.root)
	if err != nil {
		t.Fatal(err)
	}
	request := &adminv1.CreateOfflineEnrollmentAuthorizationRequest{RequestId: uuid.NewString(), ProvisioningToken: token.GetSecret(), LifetimeSeconds: 1800, Reason: "offline enrollment authorization", BootstrapRootVersion: 1, BootstrapRootSha256: digest[:]}
	first, err := f.service.CreateOfflineEnrollmentAuthorization(f.ownerCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.service.CreateOfflineEnrollmentAuthorization(f.ownerCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(first.Msg, second.Msg) {
		t.Fatal("authorization retry changed signed bytes")
	}
	document, err := proto.Marshal(first.Msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(document, []byte(token.GetSecret())) {
		t.Fatal("authorization exported raw provisioning token")
	}
	return first.Msg.GetAuthorization()
}

func (f *offlineFixture) pendingExecutor(t *testing.T, authorization *agentv1.OfflineEnrollmentAuthorizationFile) (*executor.Service, *agentv1.OfflineEnrollmentRequestFile, string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	service, err := executor.New(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	prepared, err := service.PrepareBootstrap(t.Context(), connect.NewRequest(&agentv1.PrepareBootstrapRequest{ExecutionRootJson: f.rootJSON, BootstrapEnvelope: f.bootstrap, OfflineAuthorization: authorization}))
	if err != nil {
		t.Fatal(err)
	}
	return service, prepared.Msg.GetOfflineRequest(), directory
}

func TestOfflineFilePairRealPostgresAndExecutor(t *testing.T) {
	parallelDeviceIntegration(t)
	for _, approval := range []bool{false, true} {
		t.Run(map[bool]string{false: "ready", true: "approval"}[approval], func(t *testing.T) {
			f := newOfflineFixture(t)
			token := f.mint(t, 1, approval)
			authorization := f.authorization(t, token)
			root, request, directory := f.pendingExecutor(t, authorization)
			// No device-side HTTP service exists in this fixture: only files and root RPC.
			before := &adminv1.ExportOfflineEnrollmentResponseRequest{Request: request, Reason: "transfer approved offline response"}
			if _, err := f.service.ExportOfflineEnrollmentResponse(f.ownerCtx, connect.NewRequest(before)); connect.CodeOf(err) != connect.CodeNotFound {
				t.Fatalf("export minted unimported request: %v", err)
			}
			tampered := proto.CloneOf(request)
			tampered.CsrPem = append(tampered.CsrPem, byte('x'))
			if _, err := f.service.ImportOfflineEnrollmentRequest(f.ownerCtx, connect.NewRequest(&adminv1.ImportOfflineEnrollmentRequestRequest{Request: tampered})); err == nil {
				t.Fatal("tampered CSR imported")
			}
			imported, err := f.service.ImportOfflineEnrollmentRequest(f.ownerCtx, connect.NewRequest(&adminv1.ImportOfflineEnrollmentRequestRequest{Request: request}))
			if err != nil {
				t.Fatal(err)
			}
			replay, err := f.service.ImportOfflineEnrollmentRequest(f.ownerCtx, connect.NewRequest(&adminv1.ImportOfflineEnrollmentRequestRequest{Request: request}))
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(imported.Msg.GetEnrollment(), replay.Msg.GetEnrollment()) {
				t.Fatal("request replay changed reservation")
			}
			if approval {
				if imported.Msg.GetEnrollment().GetState() != "pending_approval" || len(imported.Msg.GetEnrollment().GetCertificatePem()) != 0 {
					t.Fatal("approval bypass issued authority")
				}
				if _, err := f.service.ExportOfflineEnrollmentResponse(f.ownerCtx, connect.NewRequest(before)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
					t.Fatalf("pending exported authority: %v", err)
				}
				inbox, err := f.service.ListApprovals(f.ownerCtx, connect.NewRequest(&adminv1.ListApprovalsRequest{}))
				if err != nil {
					t.Fatal(err)
				}
				if len(inbox.Msg.GetApprovals()) != 1 {
					t.Fatal("offline reservation missing from shared approval inbox")
				}
				entry := inbox.Msg.GetApprovals()[0]
				if _, err := f.service.ApproveApproval(f.reviewerCtx, connect.NewRequest(&adminv1.ApproveApprovalRequest{ApprovalId: entry.GetId(), Reason: "independent offline device approval"})); err != nil {
					t.Fatal(err)
				}
				approve := proto.CloneOf(entry.GetApprovePendingEnrollment())
				approve.ApprovalId = entry.GetId()
				if _, err := f.service.ApprovePendingEnrollment(f.ownerCtx, connect.NewRequest(approve)); err != nil {
					t.Fatal(err)
				}
			}
			exported, err := f.service.ExportOfflineEnrollmentResponse(f.ownerCtx, connect.NewRequest(before))
			if err != nil {
				t.Fatal(err)
			}
			installed, err := root.ImportOfflineEnrollment(t.Context(), connect.NewRequest(&agentv1.ImportOfflineEnrollmentRequest{Response: exported.Msg.GetResponse()}))
			if err != nil {
				t.Fatal(err)
			}
			if installed.Msg.GetEnrollment().GetDeviceId() != imported.Msg.GetEnrollment().GetDeviceId() {
				t.Fatal("response replaced reserved device identity")
			}
			if err := root.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := executor.New(t.Context(), directory)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reopened.Close() }()
			if _, err := reopened.ImportOfflineEnrollment(t.Context(), connect.NewRequest(&agentv1.ImportOfflineEnrollmentRequest{Response: exported.Msg.GetResponse()})); err == nil {
				t.Fatal("durable response replay accepted")
			}
			status, err := reopened.Status(t.Context(), connect.NewRequest(&agentv1.StatusRequest{}))
			if err != nil {
				t.Fatal(err)
			}
			if status.Msg.GetLifecycle() != agentv1.Lifecycle_LIFECYCLE_ENROLLED || !status.Msg.GetTlsUsable() {
				t.Fatal("offline response did not durably install usable identity")
			}
			var uses, devices int
			if err := f.conn.QueryRow(t.Context(), "SELECT used_count,(SELECT count(*) FROM devices) FROM provisioning_tokens WHERE id=$1", token.GetTokenId()).Scan(&uses, &devices); err != nil {
				t.Fatal(err)
			}
			if uses != 1 || devices != 1 {
				t.Fatalf("offline replay consumed extra use or device: %d/%d", uses, devices)
			}
			var imports int
			if err := f.conn.QueryRow(t.Context(), "SELECT count(*) FROM audit_events WHERE action='enrollment.offline_import' AND actor_id=$1", f.owner.ID).Scan(&imports); err != nil {
				t.Fatal(err)
			}
			if imports != 1 {
				t.Fatalf("offline request replay duplicated its import audit: %d", imports)
			}
		})
	}
}

func TestOfflineAuthorizationTokenRevocation(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newOfflineFixture(t)
	token := f.mint(t, 1, false)
	authorization := f.authorization(t, token)
	_, request, _ := f.pendingExecutor(t, authorization)
	if _, err := f.service.RevokeProvisioningToken(f.ownerCtx, connect.NewRequest(&adminv1.RevokeProvisioningTokenRequest{RequestId: uuid.NewString(), TokenId: token.GetTokenId(), Reason: "revoke portable authorization"})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.ImportOfflineEnrollmentRequest(f.ownerCtx, connect.NewRequest(&adminv1.ImportOfflineEnrollmentRequestRequest{Request: request})); err == nil {
		t.Fatal("signed file bypassed revoked provisioning authority")
	}
	var uses int
	if err := f.conn.QueryRow(t.Context(), "SELECT used_count FROM provisioning_tokens WHERE id=$1", token.GetTokenId()).Scan(&uses); err != nil {
		t.Fatal(err)
	}
	if uses != 0 {
		t.Fatal("revoked import consumed a use")
	}
}

func TestOfflineReservationRechecksAuthorityInsideTransaction(t *testing.T) {
	parallelDeviceIntegration(t)
	for _, scenario := range []string{"authorization_expired", "delegation_revoked", "substituted_transaction"} {
		t.Run(scenario, func(t *testing.T) {
			f := newOfflineFixture(t)
			token := f.mint(t, 1, false)
			authorization := f.authorization(t, token)
			_, file, _ := f.pendingExecutor(t, authorization)
			csr, err := core.ParseDeviceCSR(file.GetCsrPem())
			if err != nil {
				t.Fatal(err)
			}
			public, ok := csr.PublicKey.(ed25519.PublicKey)
			if !ok {
				t.Fatal("fixture requires Ed25519")
			}
			proof := new(agentv1.OfflineEnrollmentRequestProof)
			if err := f.service.Authority.Verify(t.Context(), file.GetRequestProof(), proof, 1, public); err != nil {
				t.Fatal(err)
			}
			request := &enrollmentv1.ProvisionRequest{TransactionId: proof.GetTransactionId(), InstallationId: proof.GetInstallationId(), CsrPem: file.GetCsrPem()}
			importer, err := f.service.Identity.AuthorizeFresh(t.Context(), f.owner.ID, identity.PermissionManageEnrollment)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "authorization_expired":
				if _, err := f.conn.Exec(t.Context(), "UPDATE offline_enrollment_authorizations SET expires_at=clock_timestamp()-interval '1 second' WHERE token_id=$1", token.GetTokenId()); err != nil {
					t.Fatal(err)
				}
			case "delegation_revoked":
				tx, err := f.service.Pool.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				snapshot, _, err := f.service.Execution.CurrentInTransaction(t.Context(), tx)
				if err != nil {
					_ = tx.Rollback(t.Context())
					t.Fatal(err)
				}
				next := proto.CloneOf(snapshot.Delegation)
				next.Version++
				next.Delegates = nil
				envelope, err := f.service.Authority.Sign(t.Context(), next, f.rootKey)
				if err != nil {
					_ = tx.Rollback(t.Context())
					t.Fatal(err)
				}
				if _, err := f.service.Execution.Apply(t.Context(), tx, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: envelope}, f.owner.ID, "revoke offline enrollment signers"); err != nil {
					_ = tx.Rollback(t.Context())
					t.Fatal(err)
				}
				if err := tx.Commit(t.Context()); err != nil {
					t.Fatal(err)
				}
			case "substituted_transaction":
				request.TransactionId = uuid.NewString()
			}
			tokenID, err := uuid.Parse(token.GetTokenId())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.service.ProvisionOfflineToken(t.Context(), tokenID, request, importer, file); err == nil {
				t.Fatal("stale or substituted offline authority crossed the common reservation transaction")
			}
			var used, devices int
			if err := f.conn.QueryRow(t.Context(), "SELECT used_count,(SELECT count(*) FROM devices) FROM provisioning_tokens WHERE id=$1", token.GetTokenId()).Scan(&used, &devices); err != nil {
				t.Fatal(err)
			}
			if used != 0 || devices != 0 {
				t.Fatal("rejected offline authority consumed a reservation")
			}
		})
	}
}

func TestOfflineEnrollmentMissingSignerCapabilityIsActionable(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newOfflineFixture(t)
	token := f.mint(t, 1, false)
	authorization := f.authorization(t, token)
	_, request, _ := f.pendingExecutor(t, authorization)
	if _, err := f.service.ImportOfflineEnrollmentRequest(f.ownerCtx, connect.NewRequest(&adminv1.ImportOfflineEnrollmentRequestRequest{Request: request})); err != nil {
		t.Fatal(err)
	}
	digest, err := trust.ExecutionRootDigest(f.root)
	if err != nil {
		t.Fatal(err)
	}
	f.service.Signing.PlanKey = ed25519Key(t)
	_, err = f.service.CreateOfflineEnrollmentAuthorization(f.ownerCtx, connect.NewRequest(&adminv1.CreateOfflineEnrollmentAuthorizationRequest{
		RequestId: uuid.NewString(), ProvisioningToken: f.mint(t, 1, false).GetSecret(), LifetimeSeconds: 120,
		Reason: "verify missing offline signing delegation", BootstrapRootVersion: 1, BootstrapRootSha256: digest[:],
	}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("missing PLAN authority was not actionable: %v", err)
	}
	f.service.Signing.StartKey = ed25519Key(t)
	_, err = f.service.ExportOfflineEnrollmentResponse(f.ownerCtx, connect.NewRequest(&adminv1.ExportOfflineEnrollmentResponseRequest{Request: request, Reason: "verify missing offline response signer"}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("missing START authority was not actionable: %v", err)
	}
}
