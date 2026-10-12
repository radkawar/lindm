package directory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"strconv"
	"strings"
	"time"
	"unicode"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/device/inventory"
	"lindm/internal/identity"
)

func (s *Service) ListDevices(ctx context.Context, req *connect.Request[adminv1.ListDevicesRequest]) (*connect.Response[adminv1.ListDevicesResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_filter")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	page, err := s.searchDevicePage(ctx, actor, req.Msg.GetFilter(), req.Msg.GetPageToken(), core.PageLimit(req.Msg.GetPageSize()), adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_UNSPECIFIED)
	if err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(&adminv1.ListDevicesResponse{Devices: page.devices, NextPageToken: page.next, PageToken: page.token, CursorExpiresAt: page.expires}), nil
}

func (s *Service) ExportDevices(ctx context.Context, req *connect.Request[adminv1.ExportDevicesRequest]) (*connect.Response[adminv1.ExportDevicesResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_filter")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	page, err := s.searchDevicePage(ctx, actor, req.Msg.GetFilter(), req.Msg.GetPageToken(), core.PageLimit(req.Msg.GetPageSize()), req.Msg.GetFormat())
	if err != nil {
		return nil, core.MapErr(err)
	}
	media := "application/json"
	if req.Msg.GetFormat() == adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_CSV {
		media = "text/csv; charset=utf-8"
	}
	return core.NoStore(&adminv1.ExportDevicesResponse{Content: page.content, MediaType: media, NextPageToken: page.next}), nil
}

type deviceSearchPage struct {
	devices []*adminv1.Device
	content []byte
	next    string
	token   string
	expires *timestamppb.Timestamp
}

// MaxDeviceSearchCursors bounds each actor's live search cursors.
const MaxDeviceSearchCursors = 256

// The opaque cursor binds the actor, filters, scope, purpose and fixed expiry.
// Position is an immutable (enrolled_at,id) keyset, never an offset. Projections
// may change between pages; new enrollments after the initial cutoff are excluded.
func (s *Service) searchDevicePage(ctx context.Context, actor identity.Principal, filter *adminv1.DeviceFilter, token string, limit int32, format adminv1.DeviceExportFormat) (*deviceSearchPage, error) {
	if filter == nil {
		filter = &adminv1.DeviceFilter{}
	}
	unrestricted, scopes, err := core.DeviceScopeFilter(actor, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(filter)
	if err != nil {
		return nil, err
	}
	binding := sha256.New()
	_, _ = binding.Write(encoded)
	_, _ = binding.Write([]byte{byte(format)})
	if unrestricted {
		_, _ = binding.Write([]byte{1})
	} else {
		_, _ = binding.Write([]byte{0})
	}
	_, _ = binding.Write(scopes)
	digest := binding.Sum(nil)
	metadataFilter, err := protojson.Marshal(&adminv1.DeviceMetadata{Labels: filter.GetLabels(), Attributes: filter.GetAttributes()})
	if err != nil {
		return nil, err
	}
	page := new(deviceSearchPage)
	err = s.Within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		if err := core.ValidateAttributeValues(ctx, q, filter.GetAttributes()); err != nil {
			return err
		}
		now := s.Now()
		cursor := devicedb.DeviceSearchCursor{ActorID: actor.ID, FilterDigest: digest, UpperEnrolledAt: core.Timestamptz(now), ExpiresAt: core.Timestamptz(now.Add(15 * time.Minute))}
		params := devicedb.SearchDevicesParams{
			ScopeUnrestricted: unrestricted, Scopes: scopes, MetadataFilter: metadataFilter, PatchStaleAfterSeconds: inventory.PatchStaleAfterSeconds,
			OsID: filter.GetOsId(), OsVersion: filter.GetOsVersion(), RowLimit: limit + 1, NamePrefix: filter.GetNamePrefix(),
			AgentRelease:     filter.GetAgentRelease(),
			CursorEnrolledAt: core.Timestamptz(now), CursorID: uuid.Nil,
		}
		if filter.GetLastSeenFrom() != nil {
			params.SeenFrom = core.Timestamptz(filter.GetLastSeenFrom().AsTime())
		}
		if filter.GetLastSeenUntil() != nil {
			params.SeenUntil = core.Timestamptz(filter.GetLastSeenUntil().AsTime())
		}
		if token != "" {
			if err := resumeDeviceSearchCursor(ctx, q, &cursor, &params, actor.ID, digest, token, now); err != nil {
				return err
			}
		}
		params.UpperEnrolledAt = cursor.UpperEnrolledAt
		rows, err := q.SearchDevices(ctx, params)
		if err != nil {
			return err
		}
		encryption, err := rootEncryptions(ctx, q, rows)
		if err != nil {
			return err
		}
		var content bytes.Buffer
		if err := appendDeviceSearchRows(page, rows, encryption, limit, format, &content); err != nil {
			return err
		}
		if token == "" && (len(page.devices) < len(rows) || format == adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_UNSPECIFIED) {
			// Serialize capacity admission without holding a lock on fleet rows.
			if err := q.LockInventoryMetadata(ctx); err != nil {
				return err
			}
			if err := q.DeleteExpiredDeviceSearchCursors(ctx, core.Timestamptz(now)); err != nil {
				return err
			}
			count, err := q.CountDeviceSearchCursors(ctx, actor.ID)
			if err != nil {
				return err
			}
			// Bounded per actor: a new search evicts the actor's oldest cursors, so
			// ordinary browsing never locks the console out. Evicted pages read as expired.
			if count >= MaxDeviceSearchCursors {
				if err := q.DeleteOldestDeviceSearchCursors(ctx, devicedb.DeleteOldestDeviceSearchCursorsParams{ActorID: actor.ID, Excess: int32(count - MaxDeviceSearchCursors + 1)}); err != nil {
					return err
				}
			}
			cursor.ID = uuid.New()
			if err := q.InsertDeviceSearchCursor(ctx, devicedb.InsertDeviceSearchCursorParams{ID: cursor.ID, ActorID: actor.ID, FilterDigest: digest, UpperEnrolledAt: cursor.UpperEnrolledAt, ExpiresAt: cursor.ExpiresAt}); err != nil {
				return err
			}
		}
		if cursor.ID != uuid.Nil {
			page.token = token
			if page.token == "" {
				page.token = cursor.ID.String() + "."
			}
			page.expires = core.ProtoTime(cursor.ExpiresAt)
		}
		if len(page.devices) < len(rows) {
			if len(page.devices) == 0 {
				return core.ErrInternalState
			}
			last := rows[len(page.devices)-1]
			position, err := core.EncodeCursor(last.EnrolledAt.Time, last.ID)
			if err != nil {
				return err
			}
			page.next = cursor.ID.String() + "." + position
		}
		if format == adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_JSON {
			content.WriteByte(']')
		}
		page.content = content.Bytes()
		return nil
	})
	return page, err
}

func resumeDeviceSearchCursor(ctx context.Context, q *devicedb.Queries, cursor *devicedb.DeviceSearchCursor, params *devicedb.SearchDevicesParams, actorID uuid.UUID, digest []byte, token string, now time.Time) error {
	idText, position, ok := strings.Cut(token, ".")
	if !ok {
		return core.Invalid("page_token")
	}
	id, err := core.ParseUUID(idText)
	if err != nil {
		return core.Invalid("page_token")
	}
	*cursor, err = q.GetDeviceSearchCursor(ctx, id)
	if err == pgx.ErrNoRows {
		// Purged after expiry or evicted for a newer search of this actor.
		return core.ErrPageExpired
	}
	if err != nil {
		return err
	}
	if cursor.ActorID != actorID || !bytes.Equal(cursor.FilterDigest, digest) {
		return core.Invalid("page_token")
	}
	expires, ok := core.FiniteTime(cursor.ExpiresAt)
	if !ok {
		return core.ErrInternalState
	}
	if !now.Before(expires) {
		return core.ErrPageExpired
	}
	if position != "" {
		when, deviceID, err := core.DecodeCursor(position)
		if err != nil {
			return err
		}
		params.HasCursor = true
		params.CursorEnrolledAt, params.CursorID = core.Timestamptz(when), deviceID
	}
	return nil
}

func appendDeviceSearchRows(page *deviceSearchPage, rows []devicedb.SearchDevicesRow, encryption []adminv1.DeviceRootEncryption, limit int32, format adminv1.DeviceExportFormat, content *bytes.Buffer) error {
	var budget core.ResponsePageBudget
	switch format {
	case adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_JSON:
		content.WriteByte('[')
	case adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_CSV:
		content.WriteString("id,hostname,os_id,os_version,architecture,state,enrolled_at,last_seen_at,labels,owner_principal_id,owner_text,attributes,compliance,last_verified_at,root_encryption,pending_updates,pending_security_updates,reboot_required,critical_findings,high_findings,medium_findings,low_findings,other_findings\n")
	}
	for i, row := range rows {
		if len(page.devices) == int(limit) {
			break
		}
		item, err := searchDevice(row, encryption[i])
		if err != nil {
			return err
		}
		if format == adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_UNSPECIFIED {
			fits, err := budget.Take(item)
			if err != nil {
				return err
			}
			if !fits {
				break
			}
		} else {
			encoded, err := exportDeviceRow(item, format)
			if err != nil {
				return err
			}
			// bytes use base64 in Connect JSON; reserve its expansion and envelope.
			if content.Len()+len(encoded)+2 > (core.MaxMessageBytes-core.PageEnvelopeBytes)*3/4 {
				break
			}
			if format == adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_JSON && len(page.devices) > 0 {
				content.WriteByte(',')
			}
			content.Write(encoded)
		}
		page.devices = append(page.devices, item)
	}
	return nil
}

func searchDevice(row devicedb.SearchDevicesRow, encryption adminv1.DeviceRootEncryption) (*adminv1.Device, error) {
	enrolled, ok := core.FiniteTime(row.EnrolledAt)
	if !ok || row.PublishedSequence < 0 || row.HostSequence < 0 || row.PackageSequence < 0 {
		return nil, core.ErrInternalState
	}
	if row.PendingUpdates < 0 || row.PendingSecurityUpdates < 0 || min(row.FindingsCritical, row.FindingsHigh, row.FindingsMedium, row.FindingsLow, row.FindingsOther) < 0 ||
		max(row.FindingsCritical, row.FindingsHigh, row.FindingsMedium, row.FindingsLow, row.FindingsOther) > int64(^uint32(0)) {
		return nil, core.ErrInternalState
	}
	state, err := core.DeviceState(row.State)
	if err != nil {
		return nil, err
	}
	metadata := new(adminv1.DeviceMetadata)
	if err := protojson.Unmarshal(row.Metadata, metadata); err != nil {
		return nil, core.ErrInternalState
	}
	var compliance adminv1.DeviceCompliance
	switch row.ComplianceRank {
	case 0:
		compliance = adminv1.DeviceCompliance_DEVICE_COMPLIANCE_UNASSIGNED
	case 1:
		compliance = adminv1.DeviceCompliance_DEVICE_COMPLIANCE_COMPLIANT
	case 2:
		compliance = adminv1.DeviceCompliance_DEVICE_COMPLIANCE_DRIFT_REMEDIATED
	case 3:
		compliance = adminv1.DeviceCompliance_DEVICE_COMPLIANCE_STALE
	case 4:
		compliance = adminv1.DeviceCompliance_DEVICE_COMPLIANCE_UNKNOWN
	case 5:
		compliance = adminv1.DeviceCompliance_DEVICE_COMPLIANCE_ATTENTION
	default:
		return nil, core.ErrInternalState
	}
	item := &adminv1.Device{
		Id: row.ID.String(), EnrollmentGeneration: core.GenerationString(row.CurrentGenerationID),
		Hostname: row.Hostname, OsId: row.OsID, OsVersion: row.OsVersion, Architecture: row.Architecture,
		LifecycleState: state, EnrolledAt: timestamppb.New(enrolled), LastSeenAt: core.ProtoTime(row.LastSeenAt),
		HostSequence: uint64(row.HostSequence), PackageSequence: uint64(row.PackageSequence),
		HostReceivedAt: core.ProtoTime(row.HostReceivedAt), PackageAttemptReceivedAt: core.ProtoTime(row.PackageAttemptReceivedAt),
		SnapshotReceivedAt: core.ProtoTime(row.SnapshotReceivedAt), PublishedSnapshotSequence: uint64(row.PublishedSequence), Metadata: metadata,
		Compliance: compliance, LastVerifiedAt: core.ProtoTime(row.LastVerifiedAt),
		AgentRelease: row.AgentRelease, AgentProtocolVersion: uint32(row.AgentProtocolVersion),
		AgentVersionAcceptedAt: core.ProtoTime(row.AgentVersionAcceptedAt),
		RootEncryption:         encryption,
	}
	if row.UpdatesReported {
		item.Updates = &adminv1.DeviceUpdateStatus{
			PendingUpdates: uint32(row.PendingUpdates), PendingSecurityUpdates: uint32(row.PendingSecurityUpdates),
			RebootRequired: row.RebootRequired, ReceivedAt: core.ProtoTime(row.UpdatesReceivedAt), Stale: row.UpdatesStale,
		}
	}
	if row.FindingsChecked {
		item.Findings = &adminv1.DeviceFindingCounts{
			Critical: uint32(row.FindingsCritical), High: uint32(row.FindingsHigh), Medium: uint32(row.FindingsMedium),
			Low: uint32(row.FindingsLow), Other: uint32(row.FindingsOther), Partial: row.FindingsPartial,
		}
	}
	return item, nil
}

func exportDeviceRow(item *adminv1.Device, format adminv1.DeviceExportFormat) ([]byte, error) {
	if format == adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_JSON {
		return protojson.Marshal(item)
	}
	attributes, err := protojson.Marshal(&adminv1.DeviceMetadata{Attributes: item.GetMetadata().GetAttributes()})
	if err != nil {
		return nil, err
	}
	seen := ""
	if item.GetLastSeenAt() != nil {
		seen = item.GetLastSeenAt().AsTime().Format(time.RFC3339Nano)
	}
	verified := ""
	if item.GetLastVerifiedAt() != nil {
		verified = item.GetLastVerifiedAt().AsTime().Format(time.RFC3339Nano)
	}
	// Empty update and finding cells mean not reported / not checked, never zero.
	var pending, security, reboot string
	if updates := item.GetUpdates(); updates != nil {
		pending, security = strconv.FormatUint(uint64(updates.GetPendingUpdates()), 10), strconv.FormatUint(uint64(updates.GetPendingSecurityUpdates()), 10)
		reboot = strconv.FormatBool(updates.GetRebootRequired())
	}
	findings := make([]string, 5)
	if counts := item.GetFindings(); counts != nil {
		for i, count := range []uint32{counts.GetCritical(), counts.GetHigh(), counts.GetMedium(), counts.GetLow(), counts.GetOther()} {
			findings[i] = strconv.FormatUint(uint64(count), 10)
		}
	}
	fields := []string{item.GetId(), item.GetHostname(), item.GetOsId(), item.GetOsVersion(), item.GetArchitecture(), item.GetLifecycleState().String(), item.GetEnrolledAt().AsTime().Format(time.RFC3339Nano), seen,
		strings.Join(item.GetMetadata().GetLabels(), ";"), item.GetMetadata().GetOwnerPrincipalId(), item.GetMetadata().GetOwnerText(), string(attributes),
		item.GetCompliance().String(), verified, item.GetRootEncryption().String(), pending, security, reboot}
	fields = append(fields, findings...)
	for i, value := range fields {
		// Quoting CSV alone does not prevent spreadsheet formulas. Inspect after
		// leading whitespace/control characters, but retain the original text.
		trimmed := strings.TrimLeftFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
		if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
			fields[i] = "'" + value
		}
	}
	var content bytes.Buffer
	writer := csv.NewWriter(&content)
	if err := writer.Write(fields); err != nil {
		return nil, err
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return content.Bytes(), nil
}
