package directory

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"maps"
	"slices"
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
	"lindm/internal/platform"
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
	page, err := s.searchDevicePage(ctx, actor, deviceQuery{filter: req.Msg.GetFilter(), sort: req.Msg.GetSort(), hostnameSearch: req.Msg.GetHostnameSearch()}, req.Msg.GetPageToken(), core.PageLimit(req.Msg.GetPageSize()), adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_UNSPECIFIED)
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
	page, err := s.searchDevicePage(ctx, actor, deviceQuery{filter: req.Msg.GetFilter(), sort: req.Msg.GetSort(), hostnameSearch: req.Msg.GetHostnameSearch()}, req.Msg.GetPageToken(), core.PageLimit(req.Msg.GetPageSize()), req.Msg.GetFormat())
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

// deviceQuery is one device list or export request's filter, order and search.
type deviceQuery struct {
	filter         *adminv1.DeviceFilter
	sort           *adminv1.DeviceSort
	hostnameSearch string
}

// MaxDeviceSearchCursors bounds each actor's live search cursors.
const MaxDeviceSearchCursors = 256

// The opaque cursor binds the actor, filters, order, search, scope, purpose and
// fixed expiry. Position is a (sort_last, sort_key, id) keyset, never an offset;
// the default order keys on enrollment time. Projections may change between
// pages; new enrollments after the initial cutoff are excluded.
func (s *Service) searchDevicePage(ctx context.Context, actor identity.Principal, query deviceQuery, token string, limit int32, format adminv1.DeviceExportFormat) (*deviceSearchPage, error) {
	filter := query.filter
	if filter == nil {
		filter = &adminv1.DeviceFilter{}
	}
	order, err := (proto.MarshalOptions{Deterministic: true}).Marshal(query.sort)
	if err != nil {
		return nil, err
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
	// Length-prefixed so filter, order and search bytes cannot alias.
	for _, part := range [][]byte{order, []byte(query.hostnameSearch)} {
		_, _ = binding.Write(binary.BigEndian.AppendUint32(nil, uint32(len(part))))
		_, _ = binding.Write(part)
	}
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
			AgentRelease: filter.GetAgentRelease(), HostnameSearch: query.hostnameSearch,
			SortField: int32(query.sort.GetField()), Descending: query.sort.GetDescending(),
		}
		if query.sort.GetField() == adminv1.DeviceSortField_DEVICE_SORT_FIELD_UNSPECIFIED {
			params.Descending = true // newest enrollment first
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
			position, err := encodeSortCursor(last.SortLast, last.SortKey, last.ID)
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
		last, key, deviceID, err := decodeSortCursor(position)
		if err != nil {
			return err
		}
		params.HasCursor = true
		params.CursorLast, params.CursorKey, params.CursorID = last, key, deviceID
	}
	return nil
}

func appendDeviceSearchRows(page *deviceSearchPage, rows []devicedb.SearchDevicesRow, encryption []adminv1.DeviceRootEncryption, limit int32, format adminv1.DeviceExportFormat, content *bytes.Buffer) error {
	var budget core.ResponsePageBudget
	switch format {
	case adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_JSON:
		content.WriteByte('[')
	case adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_CSV:
		content.WriteString(deviceCSVHeader)
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
		Hostname: row.Hostname, OsId: row.OsID, OsVersion: row.OsVersion, OsName: platform.Identify(platform.OSRelease{ID: row.OsID, VersionID: row.OsVersion}).DisplayName(row.OsVersion), Architecture: row.Architecture,
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

// deviceCSVHeader names spreadsheet columns in the console's words. Device ID and
// Owner account ID are the only machine identifiers (stable join keys).
const deviceCSVHeader = "Device ID,Hostname,Operating system,Architecture,State,Enrolled (UTC),Last contact (UTC),Labels,Owner,Owner account ID,Attributes,Compliance,Last verified (UTC),Root encryption,Pending updates,Pending security updates,Reboot required,Critical findings,High findings,Medium findings,Low findings,Other findings,Findings coverage\n"

// csvTime is a spreadsheet-readable UTC time; empty when never recorded.
func csvTime(value *timestamppb.Timestamp, never string) string {
	if value == nil {
		return never
	}
	return value.AsTime().UTC().Format(time.DateTime)
}

var deviceStateLabels = map[adminv1.DeviceState]string{
	adminv1.DeviceState_DEVICE_STATE_PENDING:       "Pending approval",
	adminv1.DeviceState_DEVICE_STATE_ACTIVE:        "Active",
	adminv1.DeviceState_DEVICE_STATE_REVOKED:       "Revoked",
	adminv1.DeviceState_DEVICE_STATE_RECOVERY_HOLD: "Recovery hold",
}

var deviceComplianceLabels = map[adminv1.DeviceCompliance]string{
	adminv1.DeviceCompliance_DEVICE_COMPLIANCE_UNASSIGNED:       "No profile",
	adminv1.DeviceCompliance_DEVICE_COMPLIANCE_COMPLIANT:        "Compliant",
	adminv1.DeviceCompliance_DEVICE_COMPLIANCE_DRIFT_REMEDIATED: "Drift remediated",
	adminv1.DeviceCompliance_DEVICE_COMPLIANCE_STALE:            "Stale",
	adminv1.DeviceCompliance_DEVICE_COMPLIANCE_UNKNOWN:          "Unknown",
	adminv1.DeviceCompliance_DEVICE_COMPLIANCE_ATTENTION:        "Needs attention",
}

var rootEncryptionLabels = map[adminv1.DeviceRootEncryption]string{
	adminv1.DeviceRootEncryption_DEVICE_ROOT_ENCRYPTION_ENCRYPTED:     "Encrypted",
	adminv1.DeviceRootEncryption_DEVICE_ROOT_ENCRYPTION_NOT_ENCRYPTED: "Not encrypted",
}

// csvOperatingSystem names the registry release ("Ubuntu 24.04 LTS"), else the
// reported os-release identity.
func csvOperatingSystem(item *adminv1.Device) string {
	if item.GetOsId() == "" {
		return "Not reported"
	}
	if release := platform.Identify(platform.OSRelease{ID: item.GetOsId(), VersionID: item.GetOsVersion()}); release.Known() {
		return release.Name
	}
	return strings.TrimSpace(item.GetOsId() + " " + item.GetOsVersion())
}

// csvAttributes renders custom attributes as "key: value; …" sorted by key.
func csvAttributes(attributes map[string]*adminv1.AttributeValue) string {
	keys := slices.Sorted(maps.Keys(attributes))
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		var value string
		switch v := attributes[key].GetValue().(type) {
		case *adminv1.AttributeValue_StringValue:
			value = v.StringValue
		case *adminv1.AttributeValue_IntValue:
			value = strconv.FormatInt(v.IntValue, 10)
		case *adminv1.AttributeValue_BoolValue:
			value = map[bool]string{true: "Yes", false: "No"}[v.BoolValue]
		case *adminv1.AttributeValue_EnumValue:
			value = v.EnumValue
		}
		parts = append(parts, key+": "+value)
	}
	return strings.Join(parts, "; ")
}

func exportDeviceRow(item *adminv1.Device, format adminv1.DeviceExportFormat) ([]byte, error) {
	if format == adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_JSON {
		return protojson.Marshal(item)
	}
	pending, security, reboot := "Not reported", "Not reported", "Not reported"
	if updates := item.GetUpdates(); updates != nil {
		pending, security = strconv.FormatUint(uint64(updates.GetPendingUpdates()), 10), strconv.FormatUint(uint64(updates.GetPendingSecurityUpdates()), 10)
		reboot = map[bool]string{true: "Yes", false: "No"}[updates.GetRebootRequired()]
	}
	// A checked device reports every count, including 0; an unchecked one never does.
	findings := []string{"Not checked", "Not checked", "Not checked", "Not checked", "Not checked", "Not checked"}
	if counts := item.GetFindings(); counts != nil {
		for i, count := range []uint32{counts.GetCritical(), counts.GetHigh(), counts.GetMedium(), counts.GetLow(), counts.GetOther()} {
			findings[i] = strconv.FormatUint(uint64(count), 10)
		}
		findings[5] = "Complete"
		if counts.GetPartial() {
			findings[5] = "Partial: only verified base packages checked"
		}
	}
	state := cmp.Or(deviceStateLabels[item.GetLifecycleState()], "Unknown")
	fields := []string{item.GetId(), item.GetHostname(), csvOperatingSystem(item), item.GetArchitecture(), state,
		csvTime(item.GetEnrolledAt(), ""), csvTime(item.GetLastSeenAt(), "Never"),
		strings.Join(item.GetMetadata().GetLabels(), "; "), item.GetMetadata().GetOwnerText(), item.GetMetadata().GetOwnerPrincipalId(),
		csvAttributes(item.GetMetadata().GetAttributes()),
		cmp.Or(deviceComplianceLabels[item.GetCompliance()], "Unknown"), csvTime(item.GetLastVerifiedAt(), "Never"),
		cmp.Or(rootEncryptionLabels[item.GetRootEncryption()], "Unknown"), pending, security, reboot}
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
