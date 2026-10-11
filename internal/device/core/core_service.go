package core

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"math"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"connectrpc.com/validate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
	releasemanagementv1 "lindm/gen/lindm/releasemanagement/v1"
	"lindm/internal/advisory"
	"lindm/internal/assistrelay"
	"lindm/internal/config"
	"lindm/internal/device/devicedb"
	"lindm/internal/escrow"
	"lindm/internal/executionauthority"
	"lindm/internal/identity"
	"lindm/internal/policy"
	"lindm/internal/releaseupdate"
	"lindm/internal/resource"
	"lindm/internal/rpcreason"
	"lindm/internal/targeting"
	"lindm/internal/trust"
)

const (
	// Inventory upload bounds: one decoded batch and the per-deployment budget.
	MaxBatchBytes          = 768 * 1024
	defaultInventoryBudget = 10 << 30
	MinInventoryBudget     = 64 << 20
	maxInventoryBudget     = math.MaxInt64

	MaxMessageBytes    = 1 << 20
	MaxMessageOverhead = 16 << 10
	// inFlightPerConnection admits this many concurrent device-service RPCs
	// per configured database connection (64 at the default pool of 8);
	// beyond it requests are rejected as retryable admission backpressure
	// instead of queueing behind a saturated pool.
	inFlightPerConnection = 8
	minInFlight           = 64
	maxInFlight           = 512
	RpcTimeout            = 15 * time.Second
	defaultPageSize       = 50
	maxPageSize           = 200

	// JSON base64 expands the maximum decoded batch to 1 MiB. Allow a
	// bounded envelope only for PutPackageBatch; response limits stay fixed.
	MaxBatchRequestBytes = ((MaxBatchBytes + 2) / 3 * 4) + (1 << 10)

	StatePending      = "pending"
	StateActive       = "active"
	StateRevoked      = "revoked"
	StateRecoveryHold = "recovery_hold"

	methodCreateGrant  = "CreateEnrollmentGrant"
	methodRevokeGrant  = "RevokeEnrollmentGrant"
	methodRevokeDevice = "RevokeDevice"

	actionGrantCreate        = "enrollment_grant.create"
	actionGrantRevoke        = "enrollment_grant.revoke"
	actionDeviceRevoke       = "device.revoke"
	actionDeviceEnroll       = "device.enroll"
	ActionDeviceRenew        = "device.renew"
	ActionDeviceActivate     = "device.activate"
	ActionDeviceRecoveryHold = "device.recovery_hold"
)

// Config holds resolved control-plane resources. It is not a serialized
// configuration document; lindm.config.v1.ServerConfig is that contract.
type Config struct {
	DeploymentID                 string
	CACertificate                *x509.Certificate
	CAKey                        crypto.Signer
	InventoryBudgetBytes         int64
	ExecutionAuthority           *executionauthority.Store
	Identity                     *identity.Service
	ExecutionSigning             *config.ExecutionSigning
	Advisories                   *advisory.Service
	Escrow                       *escrow.Custody
	EscrowRevealApprovalRequired bool
	ReleasePublisher             *releaseupdate.Publisher
	RecoveryArtifacts            *releaseupdate.Client
	EnrollmentInstructions       *adminv1.GetEnrollmentInstructionsResponse
	// Production composition always enables the release gate. Direct service
	// fixtures must explicitly supply real build identity to exercise it.
	RequireReleaseCompatibility bool
	ServerRelease               string
	ServerProtocol              uint32
	// Assistance is nil when remote assistance is not configured; Create, Join
	// and Answer then fail with assistance_unconfigured.
	Assistance *assistrelay.Relay
}

// ProfileActivator copies a provisioning token's immutable profile revision to
// the enrolled device's resource assignment inside the enrollment transaction.
type ProfileActivator func(ctx context.Context, tx pgx.Tx, token devicedb.ProvisioningToken, receipt devicedb.ProvisioningEnrollment, assignment *adminv1.CreateProvisioningTokenRequest) error

// Core holds the resolved dependencies and RPC plumbing every device domain
// shares, and implements device identity, enrollment and execution trust.
type Service struct {
	activateProfile ProfileActivator
	// fleetPopulation is the latest background unrestricted fleet aggregate.
	FleetPopulation *atomic.Pointer[adminv1.GetFleetSummaryResponse]
	Pool            *pgxpool.Pool
	DeploymentID    uuid.UUID
	CA              *x509.Certificate
	CAKey           crypto.Signer
	validator       *validate.Interceptor
	Rules           protovalidate.Validator
	// inFlight counts admitted RPCs; inFlightMax is the device/enrollment
	// limit, and admin-console requests may use adminReserve more above it.
	inFlight               atomic.Int64
	inFlightMax            int64
	Clock                  func() time.Time
	Authority              *trust.Authority
	InventoryBudget        int64
	Execution              *executionauthority.Store
	Identity               *identity.Service
	Profiles               *policy.Store
	Targeting              *targeting.Store
	Signing                *config.ExecutionSigning
	Advisories             *advisory.Service
	Escrow                 *escrow.Custody
	RevealApproval         bool
	ReleasePublisher       *releaseupdate.Publisher
	RecoveryArtifacts      *releaseupdate.Client
	RequireCompatibility   bool
	ServerRelease          string
	ServerProtocol         uint32
	EnrollmentInstructions *adminv1.GetEnrollmentInstructionsResponse
	Assistance             *assistrelay.Relay
}

// NewCore validates cfg and builds the shared device dependencies.
func New(pool *pgxpool.Pool, cfg Config, activate ProfileActivator) (*Service, error) {
	if pool == nil {
		return nil, errors.New("device: database pool is required")
	}
	if activate == nil {
		return nil, errors.New("device: provisioning profile activation is required")
	}
	deploymentID, err := uuid.Parse(cfg.DeploymentID)
	if err != nil || deploymentID == uuid.Nil {
		return nil, errors.New("device: deployment id must be a UUID")
	}
	if cfg.CACertificate == nil || cfg.CAKey == nil || !cfg.CACertificate.IsCA || cfg.CACertificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("device: certificate authority is required")
	}
	if err := samePublicKey(cfg.CACertificate.PublicKey, cfg.CAKey.Public()); err != nil {
		return nil, err
	}
	budget := cfg.InventoryBudgetBytes
	if budget == 0 {
		budget = defaultInventoryBudget
	}
	if budget < MinInventoryBudget || budget > maxInventoryBudget {
		return nil, errors.New("device: inventory budget is outside the admitted range")
	}
	if cfg.ExecutionAuthority != nil && cfg.Identity == nil {
		return nil, errors.New("device: execution authority requires fresh identity authorization")
	}
	if cfg.ExecutionSigning != nil {
		if cfg.ExecutionAuthority == nil || len(cfg.ExecutionSigning.PlanKey) != ed25519.PrivateKeySize || len(cfg.ExecutionSigning.StartKey) != ed25519.PrivateKeySize || cfg.ExecutionSigning.PlanKey.Equal(cfg.ExecutionSigning.StartKey) {
			return nil, errors.New("device: execution signing requires authority and distinct Ed25519 keys")
		}
	}
	compiled, err := protovalidate.New(protovalidate.WithMessages(validatedMessages()...), protovalidate.WithDisableLazy())
	if err != nil {
		return nil, err
	}
	if err := resource.Initialize(); err != nil {
		return nil, err
	}
	authority, err := trust.New()
	if err != nil {
		return nil, err
	}
	profiles, err := policy.NewStore(pool)
	if err != nil {
		return nil, err
	}
	targetingStore, err := targeting.New()
	if err != nil {
		return nil, err
	}
	var instructions *adminv1.GetEnrollmentInstructionsResponse
	if cfg.EnrollmentInstructions != nil {
		if err := compiled.Validate(cfg.EnrollmentInstructions); err != nil {
			return nil, err
		}
		instructions = proto.CloneOf(cfg.EnrollmentInstructions)
	}
	return &Service{
		activateProfile:        activate,
		Pool:                   pool,
		DeploymentID:           deploymentID,
		CA:                     cfg.CACertificate,
		CAKey:                  cfg.CAKey,
		validator:              validate.NewInterceptor(validate.WithValidator(compiled)),
		Rules:                  compiled,
		inFlightMax:            int64(inFlightLimit(pool)),
		FleetPopulation:        new(atomic.Pointer[adminv1.GetFleetSummaryResponse]),
		Clock:                  time.Now,
		Authority:              authority,
		InventoryBudget:        budget,
		Execution:              cfg.ExecutionAuthority,
		Identity:               cfg.Identity,
		Escrow:                 cfg.Escrow,
		RevealApproval:         cfg.EscrowRevealApprovalRequired,
		Profiles:               profiles,
		Targeting:              targetingStore,
		Signing:                cfg.ExecutionSigning,
		Advisories:             cfg.Advisories,
		ReleasePublisher:       cfg.ReleasePublisher,
		RecoveryArtifacts:      cfg.RecoveryArtifacts,
		RequireCompatibility:   cfg.RequireReleaseCompatibility,
		ServerRelease:          cfg.ServerRelease,
		ServerProtocol:         cfg.ServerProtocol,
		EnrollmentInstructions: instructions,
		Assistance:             cfg.Assistance,
	}, nil
}

func (s *Service) HandlerOptions() []connect.HandlerOption {
	return []connect.HandlerOption{
		connect.WithInterceptors(s.validator),
		connect.WithReadMaxBytes(MaxMessageBytes),
		connect.WithSendMaxBytes(MaxMessageBytes),
	}
}

func (s *Service) Require(ctx context.Context, perm identity.Permission) (identity.Principal, error) {
	principal, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return identity.Principal{}, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if !identity.Authorize(principal, perm) {
		return identity.Principal{}, rpcreason.Error(connect.CodePermissionDenied, "permission_denied")
	}
	return principal, nil
}

func (s *Service) Acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	limit := s.inFlightMax
	if limit == 0 {
		limit = minInFlight
	}
	if ctx.Value(adminAdmissionKey{}) != nil {
		limit += adminReserve
	}
	if s.inFlight.Add(1) > limit {
		s.inFlight.Add(-1)
		return rpcreason.Error(connect.CodeResourceExhausted, "admission_rejected")
	}
	return nil
}
func (s *Service) Release() {
	s.inFlight.Add(-1)
}

// adminReserve is admission headroom only admin-console requests may use, so a
// fleet saturating device admission cannot lock operators out of the console.
const adminReserve = 16

type adminAdmissionKey struct{}

// withAdminAdmission marks requests arriving on the admin handler.
func WithAdminAdmission(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminAdmissionKey{}, true)))
	})
}

func (s *Service) Within(ctx context.Context, fn func(context.Context, *devicedb.Queries) error) error {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(ctx, devicedb.New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) Now() time.Time {
	return s.Clock().UTC().Truncate(time.Microsecond)
}

func Bound(ctx context.Context) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= RpcTimeout {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, RpcTimeout)
}

func PageLimit(n uint32) int32 {
	switch {
	case n == 0:
		return defaultPageSize
	case n > maxPageSize:
		return maxPageSize
	default:
		return int32(n)
	}
}

func ParseUUID(raw string) (uuid.UUID, error) {
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil {
		return uuid.Nil, errors.New("uuid")
	}
	return id, nil
}

func HasNUL(values ...string) bool {
	for _, value := range values {
		if strings.IndexByte(value, 0) >= 0 {
			return true
		}
	}
	return false
}

func samePublicKey(a, b crypto.PublicKey) error {
	if a == nil || b == nil {
		return errors.New("device: certificate authority key does not match certificate")
	}
	left, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return errors.New("device: certificate authority key does not match certificate")
	}
	right, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return errors.New("device: certificate authority key does not match certificate")
	}
	if string(left) != string(right) {
		return errors.New("device: certificate authority key does not match certificate")
	}
	return nil
}

func NoStore[T any](msg *T) *connect.Response[T] {
	res := connect.NewResponse(msg)
	res.Header().Set("Cache-Control", "no-store")
	return res
}

func WriteRPCError(w http.ResponseWriter, r *http.Request, err error) {
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		err = MapErr(err)
	}
	writer := connect.NewErrorWriter()
	if writer.IsSupported(r) {
		_ = writer.Write(w, r, err)
		return
	}
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func inFlightLimit(pool *pgxpool.Pool) int {
	if pool == nil {
		return minInFlight
	}
	return min(max(int(pool.Config().MaxConns)*inFlightPerConnection, minInFlight), maxInFlight)
}

// validatedMessages are every request, response and config message whose
// buf.validate rules the device RPC surfaces enforce.
func validatedMessages() []proto.Message {
	return []proto.Message{
		&releasemanagementv1.GetRolloutRequest{},
		&releasemanagementv1.SetRolloutRequest{},
		&releasemanagementv1.RegisterReleaseSeriesRequest{},
		&releasemanagementv1.GetCompatibilityRequest{},
		&adminv1.ListDevicesRequest{},
		&adminv1.GetFleetSummaryRequest{},
		&adminv1.GetDeviceRequest{},
		&adminv1.ListDevicePackagesRequest{},
		&adminv1.SetDeviceMetadataRequest{},
		&adminv1.SetAttributeDefinitionRequest{},
		&adminv1.ListAttributeDefinitionsRequest{},
		&adminv1.ExportDevicesRequest{},
		&adminv1.CreateEnrollmentGrantRequest{},
		&adminv1.ListEnrollmentGrantsRequest{},
		&adminv1.GetEnrollmentInstructionsRequest{},
		&adminv1.GetEnrollmentInstructionsResponse{},
		&adminv1.RevokeEnrollmentGrantRequest{},
		&adminv1.CreateProvisioningTokenRequest{}, &adminv1.ListProvisioningTokensRequest{},
		&adminv1.RevokeProvisioningTokenRequest{}, &adminv1.GetPendingEnrollmentsRequest{},
		&adminv1.ApprovePendingEnrollmentRequest{}, &adminv1.CreateRecoveryEnrollmentGrantRequest{},
		&adminv1.CreateOfflineEnrollmentAuthorizationRequest{}, &adminv1.ImportOfflineEnrollmentRequestRequest{},
		&adminv1.ExportOfflineEnrollmentResponseRequest{},
		&adminv1.RevokeDeviceRequest{},
		&adminv1.ListAuditEventsRequest{},
		&adminv1.ListAuditActorsRequest{}, &adminv1.ListAuditDevicesRequest{},
		&adminv1.GetExecutionAuthorityRequest{},
		&adminv1.UpdateExecutionAuthorityRequest{},
		&adminv1.PublishProfileRevisionRequest{},
		&adminv1.GetProfileRevisionRequest{},
		&adminv1.ListProfilesRequest{},
		&adminv1.ListProfileRevisionsRequest{},
		&adminv1.SetResourceAssignmentRequest{},
		&adminv1.GetDeviceResourceStateRequest{},
		&adminv1.PutDynamicGroupRequest{},
		&adminv1.GetDynamicGroupRequest{},
		&adminv1.ListDynamicGroupsRequest{},
		&adminv1.PutTargetAssignmentRequest{},
		&adminv1.ListTargetAssignmentsRequest{},
		&adminv1.PreviewTargetAssignmentsRequest{},
		&adminv1.PreviewTargetAssignmentImpactRequest{}, &adminv1.SaveTargetAssignmentImpactRequest{},
		&adminv1.ActivateTargetPreviewRequest{},
		&adminv1.PutRolloutRequest{},
		&adminv1.ControlRolloutRequest{},
		&adminv1.ListRolloutsRequest{},
		&adminv1.ListDeviceFindingsRequest{},
		&adminv1.ListDeviceUncoveredPackagesRequest{},
		&adminv1.ListAdvisorySummaryRequest{},
		&adminv1.ListAdvisoryFeedsRequest{},
		&adminv1.AcceptAdvisoryFindingRequest{},
		&adminv1.CreateApprovalRequest{},
		&adminv1.ListApprovalsRequest{},
		&adminv1.ApproveApprovalRequest{},
		&adminv1.RejectApprovalRequest{},
		&adminv1.ListDeviceGroupsRequest{},
		&adminv1.SetDeviceGroupRequest{},
		&adminv1.DeleteDeviceGroupRequest{},
		&adminv1.CreateDeviceActionRequest{},
		&adminv1.GetDeviceActionsRequest{},
		&adminv1.GetDeviceActionRequest{},
		&adminv1.ListDeviceStorageTargetsRequest{},
		&adminv1.GetDeviceEncryptionRequest{},
		&adminv1.RevealRecoveryKeyRequest{},
		&adminv1.CreateSecretRequest{}, &adminv1.RotateSecretRequest{},
		&adminv1.ListSecretsRequest{}, &adminv1.GetSecretRequest{}, &adminv1.RevealSecretRequest{},
		&adminv1.SetLocalAdminPasswordPolicyRequest{}, &adminv1.RemoveLocalAdminPasswordPolicyRequest{},
		&adminv1.RequestLocalAdminPasswordRotationRequest{}, &adminv1.GetLocalAdminPasswordStatusRequest{},
		&adminv1.RevealLocalAdminPasswordRequest{},
		&adminv1.CreateAssistanceSessionRequest{}, &adminv1.ListAssistanceSessionsRequest{},
		&adminv1.GetAssistanceSessionRequest{}, &adminv1.JoinAssistanceSessionRequest{},
		&adminv1.AnswerAssistanceSessionRequest{}, &adminv1.StopAssistanceSessionRequest{},
		&devicev1.SyncAssistanceRequest{}, &devicev1.SyncAssistanceResponse{},
		&devicev1.GetDeviceActionWorkRequest{},
		&devicev1.AuthorizeDeviceActionStartRequest{},
		&devicev1.ReportDeviceActionResultRequest{},
		&devicev1.ConfirmRefreshInventoryPublicationRequest{},
		&devicev1.RegisterDeviceActionRecoveryRequest{},
		&recoveryv1.GetRecoveryTimeRequest{},
		&recoveryv1.AcquireRecoveryWorkRequest{},
		&recoveryv1.AuthorizeRecoveryStartRequest{},
		&recoveryv1.CheckpointRecoveryActionRequest{},
		&recoveryv1.ReportRecoveryResultRequest{},
		&devicev1.GetResourceWorkRequest{},
		&devicev1.AuthorizeResourceStartRequest{},
		&devicev1.ReportResourceResultRequest{},
		&enrollmentv1.EnrollRequest{},
		&enrollmentv1.RetrieveIssuanceRequest{},
		&enrollmentv1.ProvisionRequest{}, &enrollmentv1.RetrieveProvisioningIssuanceRequest{},
		&devicev1.AcquireSessionRequest{},
		&devicev1.GetSyncStateRequest{},
		&devicev1.GetExecutionTrustRequest{},
		&devicev1.ReportHostObservationRequest{},
		&devicev1.ReportPackageAttemptRequest{},
		&devicev1.BeginPackageSnapshotRequest{},
		&devicev1.PutPackageBatchRequest{},
		&devicev1.CommitPackageSnapshotRequest{},
		&devicev1.RenewIdentityRequest{},
		&devicev1.RegisterEncryptionKeyRequest{},
		&inventoryv1.PackageBatch{},
	}
}
