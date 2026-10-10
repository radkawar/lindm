package advisory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/advisory/advisorydb"
)

func (s *Service) ListDevice(ctx context.Context, req *adminv1.ListDeviceFindingsRequest, unrestricted bool, scopes []byte) (*adminv1.ListDeviceFindingsResponse, error) {
	deviceID, err := uuid.Parse(req.GetDeviceId())
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err := s.Evaluate(ctx, deviceID); err != nil {
		return nil, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := advisorydb.New(tx)
	visible, err := q.AdvisoryDeviceVisible(ctx, advisorydb.AdvisoryDeviceVisibleParams{DeviceID: deviceID, ScopeUnrestricted: unrestricted, Scopes: scopes})
	if err != nil {
		return nil, err
	}
	if !visible {
		return nil, ErrNotFound
	}
	e, err := q.GetAdvisoryEvaluation(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	after := uuid.Nil
	if req.GetPageToken() != "" {
		data, err := base64.RawURLEncoding.Strict().DecodeString(req.GetPageToken())
		if err != nil || len(data) != 48 {
			return nil, ErrInvalid
		}
		if !bytes.Equal(data[:16], deviceID[:]) || !bytes.Equal(data[16:32], e.ID[:]) {
			return nil, ErrConflict
		}
		copy(after[:], data[32:])
	}
	// Project rejection reasons only for the exact evaluated revision and
	// implicated binary/source package. Device-wide UNKNOWN is not evidence
	// that every otherwise valid finding came from a rejected record.
	var rejectedIDs, rejectedPackages []string
	if e.FeedID != "" {
		source, err := q.GetAdvisoryFeed(ctx, e.FeedID)
		if err != nil {
			return nil, err
		}
		if e.FeedRevision != nil && source.Revision == *e.FeedRevision {
			var manifest advisoryv1.FeedManifest
			if err := proto.Unmarshal(source.SourceManifest, &manifest); err != nil {
				return nil, err
			}
			for _, rejected := range manifest.GetRejectedRecords() {
				for _, name := range rejected.GetPackageNames() {
					rejectedIDs = append(rejectedIDs, rejected.GetId())
					rejectedPackages = append(rejectedPackages, name)
				}
			}
		}
	}
	limit := pageSize(req.GetPageSize())
	rows, err := q.ListDeviceAdvisoryFindings(ctx, advisorydb.ListDeviceAdvisoryFindingsParams{DeviceID: deviceID, ID: after, RowLimit: limit + 1, SnapshotID: e.SnapshotID, RejectedIds: rejectedIDs, RejectedPackages: rejectedPackages})
	if err != nil {
		return nil, err
	}
	fresh, err := s.freshness(ctx, q, e)
	if err != nil {
		return nil, err
	}
	response := &adminv1.ListDeviceFindingsResponse{Freshness: fresh}
	bytesUsed := 0
	for i, row := range rows {
		if i == int(limit) {
			break
		}
		f := &adminv1.AdvisoryFinding{Id: row.ID.String(), AdvisoryId: row.AdvisoryID, Cves: row.Cves, PackageName: row.PackageName, InstalledVersion: row.InstalledVersion, FixedVersion: row.FixedVersion, Architecture: row.Architecture, Severity: row.Severity, PublishedAt: protoTime(row.PublishedAt), State: findingState(row.State), FeedId: row.FeedID, SourceUrl: row.SourceUrl}
		if fresh.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN {
			f.State = adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN
		}
		if row.SourceRecordRejected {
			f.State = adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN
			f.Reason = "source_record_rejected"
		}
		if row.ExceptionActorID != nil {
			f.Exception = &adminv1.AdvisoryException{ActorId: row.ExceptionActorID.String(), Reason: row.ExceptionReason.String, AcceptedAt: protoTime(row.AcceptedAt), ExpiresAt: protoTime(row.ExceptionExpiresAt)}
		}
		size := proto.Size(f) + 16
		if bytesUsed+size > 128<<10 {
			if len(response.Findings) == 0 {
				return nil, ErrCapacity
			}
			break
		}
		bytesUsed += size
		response.Findings = append(response.Findings, f)
	}
	if len(rows) > len(response.Findings) {
		last := rows[len(response.Findings)-1].ID
		var token [48]byte
		copy(token[:16], deviceID[:])
		copy(token[16:32], e.ID[:])
		copy(token[32:], last[:])
		response.NextPageToken = base64.RawURLEncoding.EncodeToString(token[:])
	}
	if fresh.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN {
		if len(e.FindingDigest) == sha256.Size {
			empty := sha256.Sum256(nil)
			if bytes.Equal(e.FindingDigest, empty[:]) {
				fresh.State = adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_CLEAR
				fresh.Reason = "no_vendor_findings"
			} else {
				fresh.State = adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED
				fresh.Reason = "vendor_findings_present"
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return response, nil
}

func (s *Service) freshness(ctx context.Context, q *advisorydb.Queries, e advisorydb.AdvisoryEvaluation) (*adminv1.AdvisoryFreshness, error) {
	f := &adminv1.AdvisoryFreshness{State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED, Reason: e.Reason, InventoryAt: protoTime(e.InventoryAt), InventoryExpiresAt: protoTime(e.ExpiresAt), FeedId: e.FeedID}
	if e.SnapshotID != nil {
		f.SnapshotId = e.SnapshotID.String()
	}
	now, err := q.AdvisoryDatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	d, err := q.GetAdvisoryDevice(ctx, e.DeviceID)
	if err != nil {
		return nil, err
	}
	unknown := func(reason string) {
		f.State = adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN
		f.Reason = reason
	}
	if e.State == "unknown" {
		unknown(e.Reason)
	}
	if !e.ExpiresAt.Valid || !now.Time.Before(e.ExpiresAt.Time) {
		unknown("inventory_stale")
	}
	if d.State != "active" || !sameID(e.SnapshotID, d.CurrentSnapshotID) || e.HostReceivedAt != d.HostReceivedAt || d.PackageStatus.Int16 != 1 {
		unknown("inventory_changed")
	}
	if e.FeedID == "" {
		if f.State != adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN || f.Reason == "" {
			unknown("feed_unavailable")
		}
		return f, nil
	}
	row, err := q.GetAdvisoryFeed(ctx, e.FeedID)
	if err != nil {
		return nil, err
	}
	f.FeedCheckedAt = protoTime(row.CheckedAt)
	f.FeedExpiresAt = protoTime(row.ExpiresAt)
	f.SourceSha256 = hex.EncodeToString(row.SourceSha256)
	if !row.Enabled || e.FeedRevision == nil || row.Revision != *e.FeedRevision || !row.ExpiresAt.Valid || !now.Time.Before(row.ExpiresAt.Time) {
		unknown("feed_stale_or_changed")
	}
	return f, nil
}

func (s *Service) Feeds(ctx context.Context) (*adminv1.ListAdvisoryFeedsResponse, error) {
	q := advisorydb.New(s.pool)
	rows, err := q.ListAdvisoryFeeds(ctx)
	if err != nil {
		return nil, err
	}
	now, err := q.AdvisoryDatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	out := &adminv1.ListAdvisoryFeedsResponse{}
	for _, row := range rows {
		var manifest advisoryv1.FeedManifest
		if err := proto.Unmarshal(row.SourceManifest, &manifest); err != nil {
			return nil, err
		}
		out.Feeds = append(out.Feeds, &adminv1.AdvisoryFeedStatus{Id: row.ID, Distro: row.Distro, Release: row.Release, PlatformStream: row.PlatformStream, Artifacts: manifest.Artifacts, RejectedRecords: manifest.RejectedRecords, SnapshotAt: protoTime(row.SnapshotAt), SourceUrl: row.SourceUrl, SourceSha256: hex.EncodeToString(row.SourceSha256), CheckedAt: protoTime(row.CheckedAt), ExpiresAt: protoTime(row.ExpiresAt), AttemptedAt: protoTime(row.AttemptedAt), Error: row.Error, Fresh: row.CompleteSnapshot && row.ExpiresAt.Valid && now.Time.Before(row.ExpiresAt.Time), AdvisoryCount: uint64(row.AdvisoryCount)})
	}
	return out, nil
}

func (s *Service) Summary(ctx context.Context, req *adminv1.ListAdvisorySummaryRequest, unrestricted bool, scopes []byte) (*adminv1.ListAdvisorySummaryResponse, error) {
	var afterAdvisory, afterSeverity string
	if req.GetPageToken() != "" {
		data, err := base64.RawURLEncoding.Strict().DecodeString(req.GetPageToken())
		if err != nil {
			return nil, ErrInvalid
		}
		parts := strings.Split(string(data), "\x00")
		if len(parts) != 2 {
			return nil, ErrInvalid
		}
		afterAdvisory, afterSeverity = parts[0], parts[1]
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := advisorydb.New(tx)
	limit := pageSize(req.GetPageSize())
	rows, err := q.ListAdvisorySummary(ctx, advisorydb.ListAdvisorySummaryParams{ScopeUnrestricted: unrestricted, Scopes: scopes, AfterAdvisory: afterAdvisory, AfterSeverity: afterSeverity, RowLimit: limit + 1})
	if err != nil {
		return nil, err
	}
	counts, err := q.CountAdvisoryDevices(ctx, advisorydb.CountAdvisoryDevicesParams{ScopeUnrestricted: unrestricted, Scopes: scopes})
	if err != nil {
		return nil, err
	}
	out := &adminv1.ListAdvisorySummaryResponse{UnknownDevices: uint64(counts.Total - counts.Evaluated), EvaluatedDevices: uint64(counts.Evaluated)}
	if len(rows) > int(limit) {
		last := rows[limit-1]
		out.NextPageToken = base64.RawURLEncoding.EncodeToString([]byte(last.AdvisoryID + "\x00" + last.Severity))
		rows = rows[:limit]
	}
	for _, row := range rows {
		out.Advisories = append(out.Advisories, &adminv1.AdvisorySummary{AdvisoryId: row.AdvisoryID, Severity: row.Severity, AffectedDevices: uint64(row.AffectedDevices), AcceptedDevices: uint64(row.AcceptedDevices), UnknownDevices: uint64(row.UnknownDevices)})
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// Accept runs inside the caller's fresh-authorization and device-scope transaction.
// Durable response receipts bind every retry to the exact actor/request payload.
func (s *Service) Accept(ctx context.Context, tx pgx.Tx, actor uuid.UUID, req *adminv1.AcceptAdvisoryFindingRequest) (*adminv1.AcceptAdvisoryFindingResponse, error) {
	if err := s.rules.Validate(req); err != nil {
		return nil, ErrInvalid
	}
	requestID, err := uuid.Parse(req.GetRequestId())
	if err != nil {
		return nil, ErrInvalid
	}
	deviceID, err := uuid.Parse(req.GetDeviceId())
	if err != nil {
		return nil, ErrInvalid
	}
	finding, err := uuid.Parse(req.GetFindingId())
	if err != nil {
		return nil, ErrInvalid
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(req)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	q := advisorydb.New(tx)
	receipt, err := q.GetAdvisoryExceptionRequest(ctx, advisorydb.GetAdvisoryExceptionRequestParams{ActorID: actor, RequestID: requestID})
	if err == nil {
		if !bytes.Equal(receipt.RequestDigest, digest[:]) {
			return nil, ErrConflict
		}
		out := &adminv1.AcceptAdvisoryFindingResponse{}
		if err := proto.Unmarshal(receipt.ResponseBytes, out); err != nil {
			return nil, err
		}
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if _, err := q.GetAdvisoryFinding(ctx, advisorydb.GetAdvisoryFindingParams{DeviceID: deviceID, ID: finding}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	e, err := q.GetAdvisoryEvaluation(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	d, err := q.GetAdvisoryDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	if !sameID(e.SnapshotID, d.CurrentSnapshotID) {
		return nil, ErrConflict
	}
	now, err := q.AdvisoryDatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	expires := req.GetExpiresAt().AsTime()
	if !expires.After(now.Time) || expires.After(now.Time.Add(366*24*time.Hour)) {
		return nil, ErrInvalid
	}
	out := &adminv1.AcceptAdvisoryFindingResponse{Exception: &adminv1.AdvisoryException{ActorId: actor.String(), Reason: req.GetReason(), AcceptedAt: protoTime(now), ExpiresAt: req.GetExpiresAt()}}
	if err := q.AcceptAdvisoryException(ctx, advisorydb.AcceptAdvisoryExceptionParams{FindingID: finding, DeviceID: deviceID, ActorID: actor, Reason: req.GetReason(), AcceptedAt: now, ExpiresAt: timestamp(expires)}); err != nil {
		return nil, err
	}
	payload, err := proto.Marshal(out)
	if err != nil {
		return nil, err
	}
	if err := q.InsertAdvisoryExceptionRequest(ctx, advisorydb.InsertAdvisoryExceptionRequestParams{ActorID: actor, RequestID: requestID, RequestDigest: digest[:], ResponseBytes: payload}); err != nil {
		return nil, err
	}
	if err := q.InsertAdvisoryAudit(ctx, advisorydb.InsertAdvisoryAuditParams{ID: uuid.New(), ActorID: &actor, Action: "advisory.exception.accepted", ResourceID: deviceID.String(), Reason: req.GetReason()}); err != nil {
		return nil, err
	}
	return out, nil
}

func pageSize(n uint32) int32 {
	if n == 0 {
		return 50
	}
	if n > 200 {
		return 200
	}
	return int32(n)
}
func protoTime(t pgtype.Timestamptz) *timestamppb.Timestamp {
	if !t.Valid {
		return nil
	}
	return timestamppb.New(t.Time)
}
func findingState(state string) adminv1.AdvisoryFindingState {
	switch state {
	case "affected":
		return adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED
	case "accepted":
		return adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_ACCEPTED
	default:
		return adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN
	}
}
