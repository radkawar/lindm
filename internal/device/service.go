package device

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"connectrpc.com/validate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/gen/lindm/admin/v1/adminv1connect"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/gen/lindm/device/v1/devicev1connect"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	"lindm/gen/lindm/enrollment/v1/enrollmentv1connect"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
	releasemanagementv1 "lindm/gen/lindm/releasemanagement/v1"
	"lindm/internal/advisory"
	"lindm/internal/config"
	"lindm/internal/device/devicedb"
	"lindm/internal/escrow"
	"lindm/internal/executionauthority"
	"lindm/internal/identity"
	"lindm/internal/policy"
	"lindm/internal/releaseupdate"
	"lindm/internal/resource"
	"lindm/internal/targeting"
	"lindm/internal/trust"
)

const (
	maxMessageBytes    = 1 << 20
	maxMessageOverhead = 16 << 10
	maxInFlight        = 64
	rpcTimeout         = 15 * time.Second
	defaultPageSize    = 50
	maxPageSize        = 200

	// JSON base64 expands the maximum decoded batch to 1 MiB. Allow a
	// bounded envelope only for PutPackageBatch; response limits stay fixed.
	maxBatchRequestBytes = ((maxBatchBytes + 2) / 3 * 4) + (1 << 10)

	statePending      = "pending"
	stateActive       = "active"
	stateRevoked      = "revoked"
	stateRecoveryHold = "recovery_hold"

	methodCreateGrant  = "CreateEnrollmentGrant"
	methodRevokeGrant  = "RevokeEnrollmentGrant"
	methodRevokeDevice = "RevokeDevice"

	actionGrantCreate        = "enrollment_grant.create"
	actionGrantRevoke        = "enrollment_grant.revoke"
	actionDeviceRevoke       = "device.revoke"
	actionDeviceEnroll       = "device.enroll"
	actionDeviceRenew        = "device.renew"
	actionDeviceActivate     = "device.activate"
	actionDeviceRecoveryHold = "device.recovery_hold"
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
	// Production composition always enables the release gate. Direct service
	// fixtures must explicitly supply real build identity to exercise it.
	RequireReleaseCompatibility bool
	ServerRelease               string
	ServerProtocol              uint32
}

// Service implements the admin, enrollment, and device RPC surfaces.
type Service struct {
	pool                 *pgxpool.Pool
	deploymentID         uuid.UUID
	ca                   *x509.Certificate
	caKey                crypto.Signer
	validator            *validate.Interceptor
	rules                protovalidate.Validator
	slots                chan struct{}
	clock                func() time.Time
	authority            *trust.Authority
	inventoryBudget      int64
	execution            *executionauthority.Store
	identity             *identity.Service
	profiles             *policy.Store
	targeting            *targeting.Store
	signing              *config.ExecutionSigning
	advisories           *advisory.Service
	escrow               *escrow.Custody
	revealApproval       bool
	releasePublisher     *releaseupdate.Publisher
	recoveryArtifacts    *releaseupdate.Client
	requireCompatibility bool
	serverRelease        string
	serverProtocol       uint32
}

var (
	_ adminv1connect.AdminServiceHandler           = (*Service)(nil)
	_ enrollmentv1connect.EnrollmentServiceHandler = (*Service)(nil)
	_ devicev1connect.DeviceServiceHandler         = (*Service)(nil)
)

func New(pool *pgxpool.Pool, cfg Config) (*Service, error) {
	if pool == nil {
		return nil, errors.New("device: database pool is required")
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
	if budget < minInventoryBudget || budget > maxInventoryBudget {
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
	compiled, err := protovalidate.New(
		protovalidate.WithMessages(
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
			&adminv1.RevokeEnrollmentGrantRequest{},
			&adminv1.CreateProvisioningTokenRequest{}, &adminv1.ListProvisioningTokensRequest{},
			&adminv1.RevokeProvisioningTokenRequest{}, &adminv1.GetPendingEnrollmentsRequest{},
			&adminv1.ApprovePendingEnrollmentRequest{}, &adminv1.CreateRecoveryEnrollmentGrantRequest{},
			&adminv1.CreateOfflineEnrollmentAuthorizationRequest{}, &adminv1.ImportOfflineEnrollmentRequestRequest{},
			&adminv1.ExportOfflineEnrollmentResponseRequest{},
			&adminv1.RevokeDeviceRequest{},
			&adminv1.ListAuditEventsRequest{},
			&adminv1.GetExecutionAuthorityRequest{},
			&adminv1.UpdateExecutionAuthorityRequest{},
			&adminv1.PublishProfileRevisionRequest{},
			&adminv1.GetProfileRevisionRequest{},
			&adminv1.ListProfilesRequest{},
			&adminv1.SetResourceAssignmentRequest{},
			&adminv1.GetDeviceResourceStateRequest{},
			&adminv1.PutDynamicGroupRequest{},
			&adminv1.GetDynamicGroupRequest{},
			&adminv1.ListDynamicGroupsRequest{},
			&adminv1.PutTargetAssignmentRequest{},
			&adminv1.ListTargetAssignmentsRequest{},
			&adminv1.PreviewTargetAssignmentsRequest{},
			&adminv1.ActivateTargetPreviewRequest{},
			&adminv1.PutRolloutRequest{},
			&adminv1.ControlRolloutRequest{},
			&adminv1.ListRolloutsRequest{},
			&adminv1.ListDeviceFindingsRequest{},
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
			&devicev1.GetServiceWorkRequest{},
			&devicev1.AuthorizeServiceStartRequest{},
			&devicev1.ReportServiceResultRequest{},
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
			&inventoryv1.PackageBatch{},
		),
		protovalidate.WithDisableLazy(),
	)
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
	return &Service{
		pool:                 pool,
		deploymentID:         deploymentID,
		ca:                   cfg.CACertificate,
		caKey:                cfg.CAKey,
		validator:            validate.NewInterceptor(validate.WithValidator(compiled)),
		rules:                compiled,
		slots:                make(chan struct{}, maxInFlight),
		clock:                time.Now,
		authority:            authority,
		inventoryBudget:      budget,
		execution:            cfg.ExecutionAuthority,
		identity:             cfg.Identity,
		escrow:               cfg.Escrow,
		revealApproval:       cfg.EscrowRevealApprovalRequired,
		profiles:             profiles,
		targeting:            targetingStore,
		signing:              cfg.ExecutionSigning,
		advisories:           cfg.Advisories,
		releasePublisher:     cfg.ReleasePublisher,
		recoveryArtifacts:    cfg.RecoveryArtifacts,
		requireCompatibility: cfg.RequireReleaseCompatibility,
		serverRelease:        cfg.ServerRelease,
		serverProtocol:       cfg.ServerProtocol,
	}, nil
}

func (s *Service) AdminHandler() (string, http.Handler) {
	path, handler := adminv1connect.NewAdminServiceHandler(s, s.handlerOptions()...)
	return path, http.MaxBytesHandler(handler, maxMessageBytes+maxMessageOverhead)
}

func (s *Service) EnrollmentHandler() (string, http.Handler) {
	path, handler := enrollmentv1connect.NewEnrollmentServiceHandler(s, s.handlerOptions()...)
	return path, http.MaxBytesHandler(handler, maxMessageBytes+maxMessageOverhead)
}

func (s *Service) DeviceHandler() (string, http.Handler) {
	options := append(s.handlerOptions(), connect.WithConditionalHandlerOptions(func(spec connect.Spec) []connect.HandlerOption {
		if spec.Procedure == devicev1connect.DeviceServicePutPackageBatchProcedure {
			return []connect.HandlerOption{connect.WithReadMaxBytes(maxBatchRequestBytes)}
		}
		return nil
	}))
	path, rpc := devicev1connect.NewDeviceServiceHandler(s, options...)
	limited := http.MaxBytesHandler(rpc, maxMessageBytes+maxMessageOverhead)
	return path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := bound(r.Context())
		defer cancel()
		now := s.now()
		leaf, deviceID, generationID, err := s.presentedIdentity(r, now)
		if err != nil {
			writeRPCError(w, r, err)
			return
		}
		if err := s.acquire(ctx); err != nil {
			writeRPCError(w, r, mapErr(err))
			return
		}
		defer s.release()
		principal, err := s.bindCertificate(ctx, leaf, deviceID, generationID, now)
		if err != nil {
			writeRPCError(w, r, err)
			return
		}
		limited.ServeHTTP(w, r.WithContext(withDevicePrincipal(ctx, principal)))
	})
}

func (s *Service) handlerOptions() []connect.HandlerOption {
	return []connect.HandlerOption{
		connect.WithInterceptors(s.validator),
		connect.WithReadMaxBytes(maxMessageBytes),
		connect.WithSendMaxBytes(maxMessageBytes),
	}
}

func (s *Service) require(ctx context.Context, perm identity.Permission) (identity.Principal, error) {
	principal, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return identity.Principal{}, rpcError(connect.CodeUnauthenticated, "unauthenticated")
	}
	if !identity.Authorize(principal, perm) {
		return identity.Principal{}, rpcError(connect.CodePermissionDenied, "permission_denied")
	}
	return principal, nil
}

func (s *Service) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return rpcError(connect.CodeResourceExhausted, "admission_rejected")
	}
}

func (s *Service) release() {
	select {
	case <-s.slots:
	default:
	}
}

func (s *Service) within(ctx context.Context, fn func(context.Context, *devicedb.Queries) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(ctx, devicedb.New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) now() time.Time {
	return s.clock().UTC().Truncate(time.Microsecond)
}

func bound(ctx context.Context) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= rpcTimeout {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, rpcTimeout)
}

func pageLimit(n uint32) int32 {
	switch {
	case n == 0:
		return defaultPageSize
	case n > maxPageSize:
		return maxPageSize
	default:
		return int32(n)
	}
}

func parseUUID(raw string) (uuid.UUID, error) {
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil {
		return uuid.Nil, errors.New("uuid")
	}
	return id, nil
}

func hasNUL(values ...string) bool {
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

func noStore[T any](msg *T) *connect.Response[T] {
	res := connect.NewResponse(msg)
	res.Header().Set("Cache-Control", "no-store")
	return res
}

func writeRPCError(w http.ResponseWriter, r *http.Request, err error) {
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		err = mapErr(err)
	}
	writer := connect.NewErrorWriter()
	if writer.IsSupported(r) {
		_ = writer.Write(w, r, err)
		return
	}
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
