// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"math"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/internal/integrations/integrationdb"
	"lindm/internal/rpcreason"
)

func deliveryMessage(row integrationdb.IntegrationDelivery) *integrationsv1.Delivery {
	return &integrationsv1.Delivery{Id: row.ID.String(), EventId: row.EventID.String(), DestinationId: row.DestinationID.String(), ResourceId: row.ResourceID, Sequence: uint64(row.Sequence), Status: integrationsv1.DeliveryStatus(row.Status), Attempts: uint32(row.Attempts), ReplayCount: uint32(row.ReplayCount), NextAttemptAt: timestamp(row.NextAttemptAt), DeliveredAt: timestamp(row.DeliveredAt), LastError: row.LastError}
}
func pageSize(size uint32) int32 {
	if size == 0 {
		return 50
	}
	return int32(size)
}
func (s *Service) cursor(token, filter string) (*integrationsv1.IntegrationPageCursor, error) {
	digest := sha256.Sum256([]byte(filter))
	if token == "" {
		return &integrationsv1.IntegrationPageCursor{BeforeTime: timestamppb.New(time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)), BeforeSequence: math.MaxInt64, BeforeId: "ffffffff-ffff-ffff-ffff-ffffffffffff", FilterHash: digest[:]}, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(data) < sha256.Size {
		return nil, rpcreason.Error(connect.CodeInvalidArgument, "invalid_page_token")
	}
	payload, signature := data[:len(data)-sha256.Size], data[len(data)-sha256.Size:]
	mac := hmac.New(sha256.New, s.receiptKey[:])
	mac.Write([]byte("cursor\x00"))
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), signature) {
		return nil, rpcreason.Error(connect.CodeInvalidArgument, "invalid_page_token")
	}
	cursor := &integrationsv1.IntegrationPageCursor{}
	if err = proto.Unmarshal(payload, cursor); err != nil || !hmac.Equal(cursor.FilterHash, digest[:]) || cursor.BeforeTime == nil || cursor.BeforeTime.CheckValid() != nil {
		return nil, rpcreason.Error(connect.CodeInvalidArgument, "invalid_page_token")
	}
	if _, err = uuid.Parse(cursor.BeforeId); err != nil {
		return nil, rpcreason.Error(connect.CodeInvalidArgument, "invalid_page_token")
	}
	return cursor, nil
}
func (s *Service) encodeCursor(cursor *integrationsv1.IntegrationPageCursor) (string, error) {
	data, err := proto.Marshal(cursor)
	if err != nil {
		return "", rpcreason.Error(connect.CodeInternal, "cursor_encoding")
	}
	mac := hmac.New(sha256.New, s.receiptKey[:])
	mac.Write([]byte("cursor\x00"))
	mac.Write(data)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(data)), nil
}
func (s *Service) ListDestinations(ctx context.Context, req *connect.Request[integrationsv1.ListDestinationsRequest]) (*connect.Response[integrationsv1.ListDestinationsResponse], error) {
	if _, err := s.principal(ctx, req.Msg); err != nil {
		return nil, err
	}
	cursor, err := s.cursor(req.Msg.PageToken, "destinations")
	if err != nil {
		return nil, err
	}
	before, err := uuid.Parse(cursor.BeforeId)
	if err != nil {
		return nil, rpcreason.Error(connect.CodeInvalidArgument, "invalid_page_token")
	}
	size := pageSize(req.Msg.PageSize)
	rows, err := integrationdb.New(s.pool).ListDestinations(ctx, integrationdb.ListDestinationsParams{BeforeTime: pgtype.Timestamptz{Time: cursor.BeforeTime.AsTime(), Valid: true}, BeforeID: before, PageLimit: size + 1})
	if err != nil {
		return nil, storeError(err)
	}
	response := &integrationsv1.ListDestinationsResponse{}
	if len(rows) > int(size) {
		rows = rows[:size]
		last := rows[len(rows)-1]
		cursor.BeforeTime = timestamp(last.CreatedAt)
		cursor.BeforeId = last.ID.String()
		response.NextPageToken, err = s.encodeCursor(cursor)
		if err != nil {
			return nil, err
		}
	}
	for _, row := range rows {
		response.Destinations = append(response.Destinations, destinationMessage(row))
	}
	return connect.NewResponse(response), nil
}
func (s *Service) ListDeliveries(ctx context.Context, req *connect.Request[integrationsv1.ListDeliveriesRequest]) (*connect.Response[integrationsv1.ListDeliveriesResponse], error) {
	if _, err := s.principal(ctx, req.Msg); err != nil {
		return nil, err
	}
	filter := "deliveries\x00" + req.Msg.GetDestinationId() + "\x00" + req.Msg.Status.String()
	if req.Msg.FailuresOnly {
		filter += "\x00failures"
	}
	cursor, err := s.cursor(req.Msg.PageToken, filter)
	if err != nil {
		return nil, err
	}
	before, err := uuid.Parse(cursor.BeforeId)
	if err != nil {
		return nil, rpcreason.Error(connect.CodeInvalidArgument, "invalid_page_token")
	}
	var destinationID *uuid.UUID
	if req.Msg.DestinationId != nil {
		id, parseErr := uuid.Parse(*req.Msg.DestinationId)
		if parseErr != nil {
			return nil, rpcreason.Error(connect.CodeInvalidArgument, "invalid_request")
		}
		destinationID = &id
	}
	size := pageSize(req.Msg.PageSize)
	rows, err := integrationdb.New(s.pool).ListDeliveries(ctx, integrationdb.ListDeliveriesParams{DestinationID: destinationID, StatusFilter: int32(req.Msg.Status), FailuresOnly: req.Msg.FailuresOnly, BeforeSequence: cursor.BeforeSequence, BeforeID: before, PageLimit: size + 1})
	if err != nil {
		return nil, storeError(err)
	}
	response := &integrationsv1.ListDeliveriesResponse{}
	if len(rows) > int(size) {
		rows = rows[:size]
		last := rows[len(rows)-1]
		cursor.BeforeSequence = last.Sequence
		cursor.BeforeId = last.ID.String()
		response.NextPageToken, err = s.encodeCursor(cursor)
		if err != nil {
			return nil, err
		}
	}
	for _, row := range rows {
		response.Deliveries = append(response.Deliveries, deliveryMessage(row))
	}
	return connect.NewResponse(response), nil
}

// deliverySummaryWindow bounds the delivered count the console reports per destination.
const deliverySummaryWindow = 24 * time.Hour

func (s *Service) SummarizeDeliveries(ctx context.Context, req *connect.Request[integrationsv1.SummarizeDeliveriesRequest]) (*connect.Response[integrationsv1.SummarizeDeliveriesResponse], error) {
	if _, err := s.principal(ctx, req.Msg); err != nil {
		return nil, err
	}
	since := s.clock().Add(-deliverySummaryWindow)
	rows, err := integrationdb.New(s.pool).SummarizeDeliveries(ctx, pgtype.Timestamptz{Time: since, Valid: true})
	if err != nil {
		return nil, storeError(err)
	}
	response := &integrationsv1.SummarizeDeliveriesResponse{DeliveredSince: timestamppb.New(since), Summaries: make([]*integrationsv1.DeliverySummary, 0, len(rows))}
	for _, row := range rows {
		response.Summaries = append(response.Summaries, &integrationsv1.DeliverySummary{DestinationId: row.DestinationID.String(), Delivered: uint64(row.Delivered), Failed: uint64(row.Failed), Retrying: uint64(row.Retrying), Queued: uint64(row.Queued), LastDeliveredAt: timestamp(row.LastDeliveredAt), LastError: row.LastError})
	}
	return connect.NewResponse(response), nil
}
