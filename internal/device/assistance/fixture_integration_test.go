// SPDX-License-Identifier: Apache-2.0

//go:build integration

package assistance

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/device/dispatch"
	"lindm/internal/device/inventory"
	"lindm/internal/device/secrets"
	"lindm/internal/identity"
	"lindm/internal/testdb"
)

// This feature-local fixture uses the real core enrollment, certificate binding,
// signed session acquisition and inventory APIs. White-box authority races stay
// in their owning package without exporting production test hooks.
type fixtureAssistance = Service
type fixtureInventory = inventory.Service
type fixtureService struct {
	*core.Service
	*fixtureAssistance
	*fixtureInventory
}

type enrolledFixture struct {
	ctx        context.Context
	svc        *fixtureService
	conn       *pgx.Conn
	principal  core.DevicePrincipal
	key        ed25519.PrivateKey
	generation string
	deviceID   string
	ownerCtx   context.Context
	now        time.Time
}

func newEnrolled(t *testing.T, budget int64) *enrolledFixture {
	t.Helper()
	f := &enrolledFixture{ctx: t.Context(), now: time.Now().UTC().Truncate(time.Microsecond)}
	pool, conn := testdb.Open(t)
	f.conn = conn
	ca, caKey := assistanceTestCA(t, f.now)
	var work *dispatch.Service
	base, err := core.New(pool, core.Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: caKey, InventoryBudgetBytes: budget, Identity: localIdentity(t, pool)}, func(ctx context.Context, tx pgx.Tx, token devicedb.ProvisioningToken, receipt devicedb.ProvisioningEnrollment, assignment *adminv1.CreateProvisioningTokenRequest) error {
		return work.ActivateProvisioningProfile(ctx, tx, token, receipt, assignment)
	})
	if err != nil {
		t.Fatal(err)
	}
	base.Clock = func() time.Time { return f.now }
	facts := inventory.New(base)
	work = dispatch.New(base, secrets.New(base), facts)
	support, err := New(base, NewRuntime())
	if err != nil {
		t.Fatal(err)
	}
	f.svc = &fixtureService{Service: base, fixtureAssistance: support, fixtureInventory: facts}
	f.ownerCtx = identity.WithPrincipal(f.ctx, insertPrincipal(t, f.ctx, conn, identity.RoleOwner))
	f.key = ed25519Key(t)
	enrolled := enrollAssistanceDevice(t, f.ctx, f.svc, f.ownerCtx, f.key)
	f.principal, err = f.svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), parseCertPEM(t, enrolled.Msg.GetCertificatePem()))
	if err != nil {
		t.Fatal(err)
	}
	f.generation, f.deviceID = enrolled.Msg.GetEnrollmentGeneration(), enrolled.Msg.GetDeviceId()
	acquireTestSession(t, f.ctx, f.svc, f.principal, f.key, 0)
	return f
}

// separateAssistanceService uses the same database schema through a distinct
// pool and core, sharing only the explicitly supplied assistance runtime.
func separateAssistanceService(t *testing.T, f *assistanceFixture, runtime *Runtime) *Service {
	t.Helper()
	pool, err := pgxpool.NewWithConfig(f.ctx, f.svc.Pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var work *dispatch.Service
	base, err := core.New(pool, core.Config{
		DeploymentID: f.svc.DeploymentID.String(), CACertificate: f.svc.CA, CAKey: f.svc.CAKey,
		Identity: localIdentity(t, pool), Assistance: f.relay, AssistancePolicyCeiling: f.svc.AssistanceCeiling,
	}, func(ctx context.Context, tx pgx.Tx, token devicedb.ProvisioningToken, receipt devicedb.ProvisioningEnrollment, assignment *adminv1.CreateProvisioningTokenRequest) error {
		return work.ActivateProvisioningProfile(ctx, tx, token, receipt, assignment)
	})
	if err != nil {
		t.Fatal(err)
	}
	base.Clock = func() time.Time { return f.now }
	facts := inventory.New(base)
	work = dispatch.New(base, secrets.New(base), facts)
	support, err := New(base, runtime)
	if err != nil {
		t.Fatal(err)
	}
	return support
}

func (f *enrolledFixture) deviceCtx() context.Context {
	return core.WithDevicePrincipal(f.ctx, f.principal)
}

func ed25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func assistanceTestCA(t *testing.T, now time.Time) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	key := ed25519Key(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func parseCertPEM(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("invalid issued certificate PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func enrollAssistanceDevice(t *testing.T, ctx context.Context, svc *fixtureService, ownerCtx context.Context, key crypto.Signer) *connect.Response[enrollmentv1.EnrollResponse] {
	t.Helper()
	grant, err := svc.CreateEnrollmentGrant(ownerCtx, connect.NewRequest(&adminv1.CreateEnrollmentGrantRequest{RequestId: uuid.NewString(), LifetimeSeconds: 120, Reason: "assistance integration enrollment"}))
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := svc.Enroll(ctx, connect.NewRequest(&enrollmentv1.EnrollRequest{GrantSecret: grant.Msg.GetSecret(), TransactionId: uuid.NewString(), CsrPem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})}))
	if err != nil {
		t.Fatal(err)
	}
	return enrolled
}

func (s *fixtureService) authenticateDeviceRequest(request *http.Request, leaf *x509.Certificate) (core.DevicePrincipal, error) {
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, s.CA}}}
	now := s.Now()
	presented, device, generation, err := s.PresentedIdentity(request, now)
	if err != nil {
		return core.DevicePrincipal{}, err
	}
	return s.BindCertificate(request.Context(), presented, device, generation, now)
}

func acquireTestSession(t *testing.T, ctx context.Context, svc *fixtureService, principal core.DevicePrincipal, key ed25519.PrivateKey, predecessor uint64) {
	t.Helper()
	proof, err := svc.Authority.Sign(ctx, &agentv1.SessionAcquisition{DeploymentId: svc.DeploymentID.String(), DeviceId: principal.DeviceID.String(), EnrollmentGeneration: principal.GenerationID.String(), RequestId: uuid.NewString(), PredecessorEpoch: predecessor, Incarnation: uuid.NewString(), BootId: uuid.NewString(), InstallationId: principal.DeviceID.String()}, key)
	if err != nil {
		t.Fatal(err)
	}
	acquired, err := svc.AcquireSession(core.WithDevicePrincipal(ctx, principal), connect.NewRequest(&devicev1.AcquireSessionRequest{AuthorityProof: proof}))
	if err != nil {
		t.Fatal(err)
	}
	if acquired.Msg.GetSessionEpoch() != predecessor+1 {
		t.Fatal("real device session epoch did not advance")
	}
}

func insertPrincipal(t *testing.T, ctx context.Context, conn *pgx.Conn, role string) identity.Principal {
	t.Helper()
	id := uuid.New()
	var deployment uuid.UUID
	if err := conn.QueryRow(ctx, "SELECT deployment_id FROM deployment_identity WHERE id").Scan(&deployment); err != nil {
		t.Fatal(err)
	}
	issuer, subject := "urn:lindm:local:"+deployment.String(), id.String()
	if _, err := conn.Exec(ctx, "INSERT INTO principals (id,issuer,subject,authorization_role,directory_enabled) VALUES ($1,$2,$3,$4,true)", id, issuer, subject, role); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "INSERT INTO local_accounts (id,username,role) VALUES ($1,$2,$3)", id, "test-"+subject, role); err != nil {
		t.Fatal(err)
	}
	return identity.Principal{ID: id, Issuer: issuer, Subject: subject, Role: role}
}

func localIdentity(t *testing.T, pool *pgxpool.Pool) *identity.Service {
	t.Helper()
	service, err := identity.New(t.Context(), pool, identity.Config{Local: true, PublicURL: "https://admin.example"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	return service
}

func hostObservation(generation string, sequence uint64, hostname string) *devicev1.ReportHostObservationRequest {
	now := timestamppb.Now()
	observed := func(status inventoryv1.CollectionStatus, value string) *inventoryv1.ObservedString {
		return &inventoryv1.ObservedString{Status: status, Value: value}
	}
	const success = inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	const unavailable = inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE
	return &devicev1.ReportHostObservationRequest{EnrollmentGeneration: generation, SessionEpoch: 1, Sequence: sequence, Observation: &inventoryv1.HostObservation{
		StartedAt: now, FinishedAt: now, BootId: observed(success, uuid.NewString()), Hostname: observed(success, hostname), OsId: observed(success, "debian"), OsVersion: observed(success, "12"), Architecture: observed(success, "amd64"), KernelRelease: observed(success, "6.8.0"), HardwareVendor: observed(unavailable, ""), HardwareModel: observed(unavailable, ""), HardwareSerial: observed(unavailable, ""),
	}}
}
