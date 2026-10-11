package device

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/gen/lindm/admin/v1/adminv1connect"
	"lindm/gen/lindm/device/v1/devicev1connect"
	"lindm/gen/lindm/enrollment/v1/enrollmentv1connect"
	"lindm/internal/device/assistance"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/device/directory"
	"lindm/internal/device/dispatch"
	"lindm/internal/device/inventory"
	"lindm/internal/device/secrets"
)

// Service composes the admin, enrollment, device, recovery and release
// management RPC surfaces from the domain packages over one shared core.
type Service struct {
	*core.Service
	*assistanceService
	*directoryService
	*dispatchService
	*inventoryService
	*secretsService
}

// Domain services are embedded under distinct names so their RPC methods
// promote onto Service.
type (
	assistanceService = assistance.Service
	directoryService  = directory.Service
	dispatchService   = dispatch.Service
	inventoryService  = inventory.Service
	secretsService    = secrets.Service
)

var (
	_ adminv1connect.AdminServiceHandler           = (*Service)(nil)
	_ enrollmentv1connect.EnrollmentServiceHandler = (*Service)(nil)
	_ devicev1connect.DeviceServiceHandler         = (*Service)(nil)
)

// New composes the device RPC surfaces over one shared core.
func New(pool *pgxpool.Pool, cfg core.Config) (*Service, error) {
	var work *dispatch.Service
	c, err := core.New(pool, cfg, func(ctx context.Context, tx pgx.Tx, token devicedb.ProvisioningToken, receipt devicedb.ProvisioningEnrollment, assignment *adminv1.CreateProvisioningTokenRequest) error {
		return work.ActivateProvisioningProfile(ctx, tx, token, receipt, assignment)
	})
	if err != nil {
		return nil, err
	}
	facts, custody := inventory.New(c), secrets.New(c)
	work = dispatch.New(c, custody, facts)
	return &Service{
		Service:           c,
		assistanceService: assistance.New(c),
		directoryService:  directory.New(c, facts),
		dispatchService:   work,
		inventoryService:  facts,
		secretsService:    custody,
	}, nil
}

func (s *Service) AdminHandler() (string, http.Handler) {
	path, handler := adminv1connect.NewAdminServiceHandler(s, s.HandlerOptions()...)
	return path, core.WithAdminAdmission(http.MaxBytesHandler(handler, core.MaxMessageBytes+core.MaxMessageOverhead))
}

func (s *Service) EnrollmentHandler() (string, http.Handler) {
	path, handler := enrollmentv1connect.NewEnrollmentServiceHandler(s, s.HandlerOptions()...)
	return path, http.MaxBytesHandler(handler, core.MaxMessageBytes+core.MaxMessageOverhead)
}

func (s *Service) DeviceHandler() (string, http.Handler) {
	options := append(s.HandlerOptions(), connect.WithConditionalHandlerOptions(func(spec connect.Spec) []connect.HandlerOption {
		if spec.Procedure == devicev1connect.DeviceServicePutPackageBatchProcedure {
			return []connect.HandlerOption{connect.WithReadMaxBytes(core.MaxBatchRequestBytes)}
		}
		return nil
	}))
	path, rpc := devicev1connect.NewDeviceServiceHandler(s, options...)
	limited := http.MaxBytesHandler(rpc, core.MaxMessageBytes+core.MaxMessageOverhead)
	return path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := core.Bound(r.Context())
		defer cancel()
		now := s.Now()
		leaf, deviceID, generationID, err := s.PresentedIdentity(r, now)
		if err != nil {
			core.WriteRPCError(w, r, err)
			return
		}
		if err := s.Acquire(ctx); err != nil {
			core.WriteRPCError(w, r, core.MapErr(err))
			return
		}
		defer s.Release()
		principal, err := s.BindCertificate(ctx, leaf, deviceID, generationID, now)
		if err != nil {
			core.WriteRPCError(w, r, err)
			return
		}
		limited.ServeHTTP(w, r.WithContext(core.WithDevicePrincipal(ctx, principal)))
	})
}
