package integrations

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/url"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/types/known/timestamppb"

	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/internal/auditkind"
	"lindm/internal/integrations/integrationdb"
	"lindm/internal/rpcreason"
)

func validateTrust(config *integrationsv1.DestinationConfig) error {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Hostname() == "" || endpoint.User != nil {
		return rpcreason.Error(connect.CodeInvalidArgument, "invalid_endpoint")
	}
	if config.Kind == integrationsv1.DestinationKind_DESTINATION_KIND_SYSLOG_TLS {
		if _, _, err = net.SplitHostPort(endpoint.Host); err != nil {
			return rpcreason.Error(connect.CodeInvalidArgument, "invalid_endpoint")
		}
	}
	if config.PinnedCaPem != "" {
		remaining := bytes.TrimSpace([]byte(config.PinnedCaPem))
		if len(remaining) == 0 {
			return rpcreason.Error(connect.CodeInvalidArgument, "invalid_ca")
		}
		for len(remaining) != 0 {
			// Trust material is returned by read APIs. Reject key blocks and
			// unparsed text rather than persisting an accidental private key.
			if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
				return rpcreason.Error(connect.CodeInvalidArgument, "invalid_ca")
			}
			block, rest := pem.Decode(remaining)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return rpcreason.Error(connect.CodeInvalidArgument, "invalid_ca")
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return rpcreason.Error(connect.CodeInvalidArgument, "invalid_ca")
			}
			remaining = bytes.TrimSpace(rest)
		}
	}
	return nil
}
func timestamp(value pgtype.Timestamptz) *timestamppb.Timestamp {
	if !value.Valid {
		return nil
	}
	return timestamppb.New(value.Time)
}
func destinationMessage(row integrationdb.IntegrationDestination) *integrationsv1.Destination {
	return &integrationsv1.Destination{Id: row.ID.String(), Config: &integrationsv1.DestinationConfig{DisplayName: row.DisplayName, Kind: integrationsv1.DestinationKind(row.Kind), Endpoint: row.Endpoint, PinnedCaPem: row.PinnedCaPem, Enabled: row.Enabled}, CreatedAt: timestamp(row.CreatedAt), UpdatedAt: timestamp(row.UpdatedAt), Version: uint64(row.Version), PreviousSecretExpiresAt: timestamp(row.PreviousSecretExpiresAt)}
}
func audit(ctx context.Context, q *integrationdb.Queries, actor uuid.UUID, action auditkind.Kind, resource, reason string) error {
	return q.InsertIntegrationAudit(ctx, integrationdb.InsertIntegrationAuditParams{ID: uuid.New(), ActorID: &actor, Action: action.String(), ResourceID: resource, Reason: reason})
}
func (s *Service) CreateDestination(ctx context.Context, req *connect.Request[integrationsv1.CreateDestinationRequest]) (*connect.Response[integrationsv1.CreateDestinationResponse], error) {
	response := &integrationsv1.CreateDestinationResponse{}
	err := s.mutate(ctx, req.Msg.RequestId, req.Msg, response, func(q *integrationdb.Queries, actor uuid.UUID) error {
		cfg := req.Msg.Config
		if err := validateTrust(cfg); err != nil {
			return err
		}
		id := uuid.New()
		secret := []byte{}
		if cfg.Kind == integrationsv1.DestinationKind_DESTINATION_KIND_WEBHOOK {
			secret = s.aead.Seal(nil, nil, req.Msg.SigningSecret, id[:])
		}
		row, err := q.CreateDestination(ctx, integrationdb.CreateDestinationParams{ID: id, DisplayName: cfg.DisplayName, Kind: int32(cfg.Kind), Endpoint: cfg.Endpoint, PinnedCaPem: cfg.PinnedCaPem, Enabled: cfg.Enabled, SecretCiphertext: secret})
		if err != nil {
			return err
		}
		response.Destination = destinationMessage(row)
		return audit(ctx, q, actor, auditkind.IntegrationDestinationCreated, id.String(), req.Msg.Reason)
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}
func (s *Service) UpdateDestination(ctx context.Context, req *connect.Request[integrationsv1.UpdateDestinationRequest]) (*connect.Response[integrationsv1.UpdateDestinationResponse], error) {
	response := &integrationsv1.UpdateDestinationResponse{}
	err := s.mutate(ctx, req.Msg.RequestId, req.Msg, response, func(q *integrationdb.Queries, actor uuid.UUID) error {
		cfg := req.Msg.Config
		if err := validateTrust(cfg); err != nil {
			return err
		}
		id, err := uuid.Parse(req.Msg.DestinationId)
		if err != nil {
			return err
		}
		current, err := q.LockDestination(ctx, id)
		if err != nil {
			return err
		}
		if uint64(current.Version) != req.Msg.ExpectedVersion {
			return rpcreason.Error(connect.CodeAborted, "destination_version_changed")
		}
		if current.Kind != int32(cfg.Kind) {
			return rpcreason.Error(connect.CodeInvalidArgument, "destination_kind_immutable")
		}
		row, err := q.UpdateDestination(ctx, integrationdb.UpdateDestinationParams{ID: id, DisplayName: cfg.DisplayName, Endpoint: cfg.Endpoint, PinnedCaPem: cfg.PinnedCaPem, Enabled: cfg.Enabled})
		if err != nil {
			return err
		}
		response.Destination = destinationMessage(row)
		return audit(ctx, q, actor, auditkind.IntegrationDestinationUpdated, id.String(), req.Msg.Reason)
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}
func (s *Service) DeleteDestination(ctx context.Context, req *connect.Request[integrationsv1.DeleteDestinationRequest]) (*connect.Response[integrationsv1.DeleteDestinationResponse], error) {
	response := &integrationsv1.DeleteDestinationResponse{}
	err := s.mutate(ctx, req.Msg.RequestId, req.Msg, response, func(q *integrationdb.Queries, actor uuid.UUID) error {
		id, err := uuid.Parse(req.Msg.DestinationId)
		if err != nil {
			return err
		}
		row, err := q.LockDestination(ctx, id)
		if err != nil {
			return err
		}
		if uint64(row.Version) != req.Msg.ExpectedVersion {
			return rpcreason.Error(connect.CodeAborted, "destination_version_changed")
		}
		if err = q.DeleteDestination(ctx, id); err != nil {
			return err
		}
		if err = q.CancelDestinationDeliveries(ctx, id); err != nil {
			return err
		}
		return audit(ctx, q, actor, auditkind.IntegrationDestinationDeleted, id.String(), req.Msg.Reason)
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}
func (s *Service) RotateDestinationSecret(ctx context.Context, req *connect.Request[integrationsv1.RotateDestinationSecretRequest]) (*connect.Response[integrationsv1.RotateDestinationSecretResponse], error) {
	response := &integrationsv1.RotateDestinationSecretResponse{}
	err := s.mutate(ctx, req.Msg.RequestId, req.Msg, response, func(q *integrationdb.Queries, actor uuid.UUID) error {
		id, err := uuid.Parse(req.Msg.DestinationId)
		if err != nil {
			return err
		}
		current, err := q.LockDestination(ctx, id)
		if err != nil {
			return err
		}
		if uint64(current.Version) != req.Msg.ExpectedVersion {
			return rpcreason.Error(connect.CodeAborted, "destination_version_changed")
		}
		if current.Kind != int32(integrationsv1.DestinationKind_DESTINATION_KIND_WEBHOOK) {
			return rpcreason.Error(connect.CodeFailedPrecondition, "webhook_required")
		}
		// A second rotation must not silently discard a still-valid overlap key.
		if current.PreviousSecretExpiresAt.Valid && s.clock().Before(current.PreviousSecretExpiresAt.Time) {
			return rpcreason.Error(connect.CodeFailedPrecondition, "rotation_overlap_active")
		}
		ciphertext := s.aead.Seal(nil, nil, req.Msg.SigningSecret, id[:])
		row, err := q.RotateDestinationSecret(ctx, integrationdb.RotateDestinationSecretParams{ID: id, Ciphertext: ciphertext, ExpiresAt: pgtype.Timestamptz{Time: s.clock().Add(time.Duration(req.Msg.OverlapSeconds) * time.Second), Valid: true}})
		if err != nil {
			return err
		}
		response.Destination = destinationMessage(row)
		return audit(ctx, q, actor, auditkind.IntegrationDestinationSecretRotated, id.String(), req.Msg.Reason)
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}
func (s *Service) ReplayDelivery(ctx context.Context, req *connect.Request[integrationsv1.ReplayDeliveryRequest]) (*connect.Response[integrationsv1.ReplayDeliveryResponse], error) {
	response := &integrationsv1.ReplayDeliveryResponse{}
	err := s.mutate(ctx, req.Msg.RequestId, req.Msg, response, func(q *integrationdb.Queries, actor uuid.UUID) error {
		id, err := uuid.Parse(req.Msg.DeliveryId)
		if err != nil {
			return err
		}
		row, err := q.LockDelivery(ctx, id)
		if err != nil {
			return err
		}
		if row.Status != int32(integrationsv1.DeliveryStatus_DELIVERY_STATUS_DEAD_LETTER) {
			return rpcreason.Error(connect.CodeFailedPrecondition, "dead_letter_required")
		}
		target, err := q.LoadDeliveryTarget(ctx, row.DestinationID)
		if err != nil {
			return err
		}
		if !target.Enabled {
			return rpcreason.Error(connect.CodeFailedPrecondition, "destination_disabled")
		}
		row, err = q.ReplayDelivery(ctx, id)
		if err != nil {
			return err
		}
		response.Delivery = deliveryMessage(row)
		return audit(ctx, q, actor, auditkind.IntegrationDeliveryReplayed, id.String(), req.Msg.Reason)
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}
