package advisory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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
	"lindm/internal/platform"
)

// evaluationPending marks a stored evaluation that no longer binds the
// device's current evidence, or a device not yet evaluated. The background
// job replaces it; it is UNKNOWN, never stale certainty.
const evaluationPending = "evaluation_pending"

// ListDevice serves the persisted evaluation only. Matching runs in the
// background job (EvaluatePending) when a snapshot, host observation or feed
// generation changes; until then the stored evaluation is reported UNKNOWN with
// reason evaluation_pending, never re-matched inside the request.
func (s *Service) ListDevice(ctx context.Context, req *adminv1.ListDeviceFindingsRequest, unrestricted bool, scopes []byte) (*adminv1.ListDeviceFindingsResponse, error) {
	deviceID, err := uuid.Parse(req.GetDeviceId())
	if err != nil {
		return nil, ErrInvalid
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
	if errors.Is(err, pgx.ErrNoRows) {
		if req.GetPageToken() != "" {
			return nil, ErrConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return &adminv1.ListDeviceFindingsResponse{Freshness: &adminv1.AdvisoryFreshness{State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN, Reason: evaluationPending}}, nil
	}
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
	// A partial evaluation stays PARTIAL with its vendor reason; only a
	// complete evaluation is summarised as AFFECTED or CLEAR.
	if fresh.State == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_AFFECTED {
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
		f.UncoveredPackages = 0
	}
	if e.State == "partial" {
		f.State = adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_PARTIAL
		f.UncoveredPackages = uint64(e.UncoveredPackages)
	}
	if e.State == "unknown" {
		unknown(e.Reason)
	}
	if !e.ExpiresAt.Valid || !now.Time.Before(e.ExpiresAt.Time) {
		unknown("inventory_stale")
	}
	if d.PackageStatus.Int16 != 1 {
		unknown("package_collection_failed")
	}
	if !sameID(e.SnapshotID, d.CurrentSnapshotID) || e.HostReceivedAt != d.HostReceivedAt {
		unknown(evaluationPending)
	}
	if d.State != "active" {
		unknown("device_not_active")
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
	if !row.ExpiresAt.Valid || !now.Time.Before(row.ExpiresAt.Time) {
		unknown("feed_stale")
	}
	if !row.Enabled || e.FeedRevision == nil || row.Revision != *e.FeedRevision {
		unknown(evaluationPending)
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
	out := &adminv1.ListAdvisorySummaryResponse{UnknownDevices: uint64(counts.Total - counts.Evaluated - counts.Partial), EvaluatedDevices: uint64(counts.Evaluated), PartialDevices: uint64(counts.Partial)}
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

// ListUncovered pages the installed packages of a PARTIAL evaluation that the
// applied base feed does not cover, each with its stable UNKNOWN reason. Any
// other evaluation state lists nothing: UNKNOWN already covers every package
// and a complete evaluation has none uncovered.
func (s *Service) ListUncovered(ctx context.Context, req *adminv1.ListDeviceUncoveredPackagesRequest, unrestricted bool, scopes []byte) (*adminv1.ListDeviceUncoveredPackagesResponse, error) {
	deviceID, err := uuid.Parse(req.GetDeviceId())
	if err != nil {
		return nil, ErrInvalid
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
	if errors.Is(err, pgx.ErrNoRows) {
		if req.GetPageToken() != "" {
			return nil, ErrConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return &adminv1.ListDeviceUncoveredPackagesResponse{Freshness: &adminv1.AdvisoryFreshness{State: adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN, Reason: evaluationPending}}, nil
	}
	if err != nil {
		return nil, err
	}
	after := int32(-1)
	if req.GetPageToken() != "" {
		data, err := base64.RawURLEncoding.Strict().DecodeString(req.GetPageToken())
		if err != nil || len(data) != 36 {
			return nil, ErrInvalid
		}
		if !bytes.Equal(data[:16], deviceID[:]) || !bytes.Equal(data[16:32], e.ID[:]) {
			return nil, ErrConflict
		}
		after = int32(binary.BigEndian.Uint32(data[32:]))
		if after < 0 || after >= maxSnapshotPositions {
			return nil, ErrInvalid
		}
	}
	fresh, err := s.freshness(ctx, q, e)
	if err != nil {
		return nil, err
	}
	response := &adminv1.ListDeviceUncoveredPackagesResponse{Freshness: fresh}
	if fresh.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_PARTIAL && e.SnapshotID != nil {
		d, err := q.GetAdvisoryDevice(ctx, deviceID)
		if err != nil {
			return nil, err
		}
		// The current host identity is the evaluated one: a changed host
		// observation already makes the evaluation pending above.
		coverage := derivativeCoverage(platform.Identify(platform.OSRelease{ID: d.OsID, VersionID: d.OsVersion}))
		if coverage == nil || coverage.reason != e.Reason {
			return nil, errors.New("advisory: partial evaluation without its origin policy")
		}
		limit := pageSize(req.GetPageSize())
		rows, err := q.ListAdvisoryUncoveredPackages(ctx, coverage.uncoveredParams(*e.SnapshotID, after, limit+1))
		if err != nil {
			return nil, err
		}
		for i, row := range rows {
			if i == int(limit) {
				var token [36]byte
				copy(token[:16], deviceID[:])
				copy(token[16:32], e.ID[:])
				binary.BigEndian.PutUint32(token[32:], uint32(rows[i-1].Position))
				response.NextPageToken = base64.RawURLEncoding.EncodeToString(token[:])
				break
			}
			response.Packages = append(response.Packages, &adminv1.UncoveredPackage{Name: row.Name, Version: row.Version, Architecture: row.Architecture, Reason: row.Reason})
		}
	} else if req.GetPageToken() != "" {
		return nil, ErrConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return response, nil
}

// ApprovalFinding projects the exact persisted finding under the caller's
// fresh-authorization and device-scope transaction, never a replacement match.
func (s *Service) ApprovalFinding(ctx context.Context, tx pgx.Tx, req *adminv1.AcceptAdvisoryFindingRequest) (*adminv1.AdvisoryFinding, error) {
	deviceID, err := uuid.Parse(req.GetDeviceId())
	if err != nil {
		return nil, ErrInvalid
	}
	findingID, err := uuid.Parse(req.GetFindingId())
	if err != nil {
		return nil, ErrInvalid
	}
	row, err := advisorydb.New(tx).GetAdvisoryFinding(ctx, advisorydb.GetAdvisoryFindingParams{DeviceID: deviceID, ID: findingID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &adminv1.AdvisoryFinding{Id: row.ID.String(), AdvisoryId: row.AdvisoryID, Cves: row.Cves, PackageName: row.PackageName, InstalledVersion: row.InstalledVersion, FixedVersion: row.FixedVersion, Architecture: row.Architecture, Severity: row.Severity, PublishedAt: protoTime(row.PublishedAt), FeedId: row.FeedID, SourceUrl: row.SourceUrl}, nil
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
	// Acceptance binds the persisted evaluation; it never re-matches inline.
	// Evidence newer than that evaluation conflicts until the background job
	// has evaluated it.
	if !sameID(e.SnapshotID, d.CurrentSnapshotID) || e.HostReceivedAt != d.HostReceivedAt {
		return nil, ErrConflict
	}
	if e.FeedID != "" {
		source, err := q.GetAdvisoryFeed(ctx, e.FeedID)
		if err != nil {
			return nil, err
		}
		if !source.Enabled || e.FeedRevision == nil || source.Revision != *e.FeedRevision {
			return nil, ErrConflict
		}
	}
	now, err := q.AdvisoryDatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	expires := req.GetExpiresAt().AsTime()
	if !expires.After(now.Time) || expires.After(now.Time.Add(366*24*time.Hour)) {
		return nil, ErrInvalid
	}
	stored, err := q.AcceptAdvisoryException(ctx, advisorydb.AcceptAdvisoryExceptionParams{FindingID: finding, DeviceID: deviceID, ActorID: actor, Reason: req.GetReason(), AcceptedAt: now, ExpiresAt: timestamp(expires)})
	if err != nil {
		return nil, err
	}
	// Receipt and subsequent findings project the same persisted timestamps,
	// including PostgreSQL's microsecond precision, not the input's nanoseconds.
	out := &adminv1.AcceptAdvisoryFindingResponse{Exception: &adminv1.AdvisoryException{ActorId: stored.ActorID.String(), Reason: stored.Reason, AcceptedAt: protoTime(stored.AcceptedAt), ExpiresAt: protoTime(stored.ExpiresAt)}}
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
