// Package integrations owns encrypted destinations and transactional audit-event
// delivery. It provides at-least-once transport with stable deduplication IDs, not
// remote exactly-once execution. Domain audit creation and report chains live elsewhere.
package integrations

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net/http"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"connectrpc.com/validate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/gen/lindm/integrations/v1/integrationsv1connect"
	"lindm/internal/identity"
	"lindm/internal/integrations/integrationdb"
	"lindm/internal/rpcreason"
)

const messageLimit = 8 << 20

// Service has immutable process dependencies; all mutable delivery state is durable.
type Service struct {
	pool       *pgxpool.Pool
	auth       *identity.Service
	aead       cipher.AEAD
	receiptKey [32]byte
	rules      protovalidate.Validator
	validator  *validate.Interceptor
	clock      func() time.Time
	slots      chan struct{}
}

var _ integrationsv1connect.IntegrationServiceHandler = (*Service)(nil)

// New requires a protected, backed-up 32-byte encryption root. Losing or replacing
// that root makes existing destination credentials unreadable. It is not a webhook key.
func New(pool *pgxpool.Pool, auth *identity.Service, encryptionKey []byte, clock func() time.Time) (*Service, error) {
	if pool == nil || auth == nil || len(encryptionKey) != 32 || clock == nil {
		return nil, errors.New("integrations: pool, identity, 32-byte encryption key and clock required")
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	rules, err := protovalidate.New(protovalidate.WithMessages(
		&integrationsv1.CreateDestinationRequest{}, &integrationsv1.UpdateDestinationRequest{},
		&integrationsv1.DeleteDestinationRequest{}, &integrationsv1.RotateDestinationSecretRequest{},
		&integrationsv1.ListDestinationsRequest{}, &integrationsv1.ListDeliveriesRequest{}, &integrationsv1.ReplayDeliveryRequest{},
	), protovalidate.WithDisableLazy())
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, encryptionKey)
	mac.Write([]byte("lindm/integrations/receipts-and-cursors/v1"))
	s := &Service{pool: pool, auth: auth, aead: aead, rules: rules, clock: clock, slots: make(chan struct{}, 32)}
	copy(s.receiptKey[:], mac.Sum(nil))
	s.validator = validate.NewInterceptor(validate.WithValidator(rules))
	return s, nil
}

// AdminHandler must be mounted behind identity.RequireSession. Business checks
// are repeated below and every mutation uses fresh authority and transaction fences.
func (s *Service) AdminHandler() (string, http.Handler) {
	path, handler := integrationsv1connect.NewIntegrationServiceHandler(s, connect.WithInterceptors(s.validator), connect.WithReadMaxBytes(messageLimit), connect.WithSendMaxBytes(messageLimit))
	bounded := http.MaxBytesHandler(handler, messageLimit+(16<<10))
	return path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		select {
		case s.slots <- struct{}{}:
			defer func() { <-s.slots }()
		default:
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		bounded.ServeHTTP(w, r.WithContext(ctx))
	})
}

func storeError(err error) error {
	if err == nil {
		return nil
	}
	var rpc *connect.Error
	if errors.As(err, &rpc) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return rpcreason.Error(connect.CodeNotFound, "not_found")
	}
	if errors.Is(err, identity.ErrAuthorizationDenied) || errors.Is(err, identity.ErrAuthorizationChanged) || errors.Is(err, identity.ErrAuthorizationExpired) {
		return rpcreason.Error(connect.CodePermissionDenied, "authorization_denied")
	}
	if errors.Is(err, context.Canceled) {
		return rpcreason.Error(connect.CodeCanceled, "cancelled")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return rpcreason.Error(connect.CodeDeadlineExceeded, "deadline_exceeded")
	}
	return rpcreason.Error(connect.CodeUnavailable, "integration_store_unavailable")
}
func (s *Service) principal(ctx context.Context, msg proto.Message) (identity.Principal, error) {
	p, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return p, rpcreason.Error(connect.CodeUnauthenticated, "session_required")
	}
	if !identity.Authorize(p, identity.PermissionManageIntegrations) {
		return p, rpcreason.Error(connect.CodePermissionDenied, "permission_denied")
	}
	unrestricted, _ := identity.DeviceScopes(p, identity.PermissionManageIntegrations)
	if !unrestricted {
		return p, rpcreason.Error(connect.CodePermissionDenied, "global_permission_required")
	}
	if err := s.rules.Validate(msg); err != nil {
		return p, rpcreason.Error(connect.CodeInvalidArgument, "invalid_request")
	}
	return p, nil
}

// mutate records only an authenticated digest of input and a nonsecret response.
// Concurrent equal IDs serialize at the receipt row; changed requests cannot replay.
func (s *Service) mutate(ctx context.Context, requestID string, request, response proto.Message, apply func(*integrationdb.Queries, uuid.UUID) error) (result error) {
	p, err := s.principal(ctx, request)
	if err != nil {
		return err
	}
	approval, err := s.auth.AuthorizeFresh(ctx, p.ID, identity.PermissionManageIntegrations)
	if err != nil {
		return storeError(err)
	}
	unrestricted, _ := identity.DeviceScopes(approval.Principal(), identity.PermissionManageIntegrations)
	if !unrestricted {
		return rpcreason.Error(connect.CodePermissionDenied, "global_permission_required")
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return rpcreason.Error(connect.CodeInternal, "request_encoding")
	}
	defer clear(encoded)
	mac := hmac.New(sha256.New, s.receiptKey[:])
	mac.Write([]byte(request.ProtoReflect().Descriptor().FullName()))
	mac.Write([]byte{0})
	mac.Write(encoded)
	digest := mac.Sum(nil)
	id, err := uuid.Parse(requestID)
	if err != nil {
		return rpcreason.Error(connect.CodeInvalidArgument, "invalid_request")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return storeError(err)
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		rollbackErr := tx.Rollback(rollbackCtx)
		if rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			result = errors.Join(result, storeError(rollbackErr))
		}
	}()
	if err = s.auth.LockAuthorization(ctx, tx, approval, identity.PermissionManageIntegrations); err != nil {
		return storeError(err)
	}
	q := integrationdb.New(tx)
	if err = q.InsertMutation(ctx, integrationdb.InsertMutationParams{ActorID: p.ID, RequestID: id, RequestHash: digest}); err != nil {
		return storeError(err)
	}
	receipt, err := q.LockMutation(ctx, integrationdb.LockMutationParams{ActorID: p.ID, RequestID: id})
	if err != nil {
		return storeError(err)
	}
	if !hmac.Equal(receipt.RequestHash, digest) {
		return rpcreason.Error(connect.CodeAlreadyExists, "request_id_conflict")
	}
	if receipt.Response != nil {
		if err = proto.Unmarshal(receipt.Response, response); err != nil {
			return rpcreason.Error(connect.CodeInternal, "receipt_invalid")
		}
	} else {
		if err = apply(q, p.ID); err != nil {
			return storeError(err)
		}
		encodedResponse, encodeErr := proto.Marshal(response)
		if encodeErr != nil {
			return rpcreason.Error(connect.CodeInternal, "response_encoding")
		}
		if encodedResponse == nil {
			encodedResponse = []byte{}
		}
		if err = q.CompleteMutation(ctx, integrationdb.CompleteMutationParams{ActorID: p.ID, RequestID: id, Response: encodedResponse}); err != nil {
			return storeError(err)
		}
	}
	if err = s.auth.LockAuthorization(ctx, tx, approval, identity.PermissionManageIntegrations); err != nil {
		return storeError(err)
	}
	return storeError(tx.Commit(ctx))
}
