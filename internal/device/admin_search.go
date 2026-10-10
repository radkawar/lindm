package device

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"strings"
	"time"
	"unicode"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func (s *Service) ListDevices(ctx context.Context, req *connect.Request[adminv1.ListDevicesRequest]) (*connect.Response[adminv1.ListDevicesResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_filter")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	page, err := s.searchDevicePage(ctx, actor, req.Msg.GetFilter(), req.Msg.GetPageToken(), pageLimit(req.Msg.GetPageSize()), adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_UNSPECIFIED)
	if err != nil {
		return nil, mapErr(err)
	}
	return noStore(&adminv1.ListDevicesResponse{Devices: page.devices, NextPageToken: page.next, PageToken: page.token, CursorExpiresAt: page.expires}), nil
}

func (s *Service) ExportDevices(ctx context.Context, req *connect.Request[adminv1.ExportDevicesRequest]) (*connect.Response[adminv1.ExportDevicesResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_filter")
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	page, err := s.searchDevicePage(ctx, actor, req.Msg.GetFilter(), req.Msg.GetPageToken(), pageLimit(req.Msg.GetPageSize()), req.Msg.GetFormat())
	if err != nil {
		return nil, mapErr(err)
	}
	media := "application/json"
	if req.Msg.GetFormat() == adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_CSV {
		media = "text/csv; charset=utf-8"
	}
	return noStore(&adminv1.ExportDevicesResponse{Content: page.content, MediaType: media, NextPageToken: page.next}), nil
}

type deviceSearchPage struct {
	devices []*adminv1.Device
	content []byte
	next    string
	token   string
	expires *timestamppb.Timestamp
}

// The opaque cursor binds the actor, filters, scope, purpose and fixed expiry.
// Position is an immutable (enrolled_at,id) keyset, never an offset. Projections
// may change between pages; new enrollments after the initial cutoff are excluded.
func (s *Service) searchDevicePage(ctx context.Context, actor identity.Principal, filter *adminv1.DeviceFilter, token string, limit int32, format adminv1.DeviceExportFormat) (*deviceSearchPage, error) {
	if filter == nil {
		filter = &adminv1.DeviceFilter{}
	}
	unrestricted, scopes, err := deviceScopeFilter(actor, identity.PermissionReadFleet)
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
	err = s.within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		if err := validateAttributeValues(ctx, q, filter.GetAttributes()); err != nil {
			return err
		}
		now := s.now()
		cursor := devicedb.DeviceSearchCursor{ActorID: actor.ID, FilterDigest: digest, UpperEnrolledAt: timestamptz(now), ExpiresAt: timestamptz(now.Add(15 * time.Minute))}
		params := devicedb.SearchDevicesParams{
			ScopeUnrestricted: unrestricted, Scopes: scopes, MetadataFilter: metadataFilter,
			OsID: filter.GetOsId(), OsVersion: filter.GetOsVersion(), RowLimit: limit + 1, NamePrefix: filter.GetNamePrefix(),
			AgentRelease:     filter.GetAgentRelease(),
			CursorEnrolledAt: timestamptz(now), CursorID: uuid.Nil,
		}
		if filter.GetLastSeenFrom() != nil {
			params.SeenFrom = timestamptz(filter.GetLastSeenFrom().AsTime())
		}
		if filter.GetLastSeenUntil() != nil {
			params.SeenUntil = timestamptz(filter.GetLastSeenUntil().AsTime())
		}
		if token != "" {
			idText, position, ok := strings.Cut(token, ".")
			if !ok {
				return invalid("page_token")
			}
			id, err := parseUUID(idText)
			if err != nil {
				return invalid("page_token")
			}
			cursor, err = q.GetDeviceSearchCursor(ctx, id)
			if err == pgx.ErrNoRows {
				return invalid("page_token")
			}
			if err != nil {
				return err
			}
			if cursor.ActorID != actor.ID || !bytes.Equal(cursor.FilterDigest, digest) {
				return invalid("page_token")
			}
			expires, ok := finiteTime(cursor.ExpiresAt)
			if !ok {
				return errInternalState
			}
			if !now.Before(expires) {
				return errPageExpired
			}
			if position != "" {
				when, deviceID, err := decodeCursor(position)
				if err != nil {
					return err
				}
				params.HasCursor = true
				params.CursorEnrolledAt, params.CursorID = timestamptz(when), deviceID
			}
		}
		params.UpperEnrolledAt = cursor.UpperEnrolledAt
		rows, err := q.SearchDevices(ctx, params)
		if err != nil {
			return err
		}
		var budget responsePageBudget
		var content bytes.Buffer
		switch format {
		case adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_JSON:
			content.WriteByte('[')
		case adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_CSV:
			content.WriteString("id,hostname,os_id,os_version,architecture,state,enrolled_at,last_seen_at,labels,owner_principal_id,owner_text,attributes,compliance,last_verified_at\n")
		}
		for _, row := range rows {
			if len(page.devices) == int(limit) {
				break
			}
			item, err := searchDevice(row)
			if err != nil {
				return err
			}
			if format == adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_UNSPECIFIED {
				fits, err := budget.take(item)
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
				if content.Len()+len(encoded)+2 > (maxMessageBytes-pageEnvelopeBytes)*3/4 {
					break
				}
				if format == adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_JSON && len(page.devices) > 0 {
					content.WriteByte(',')
				}
				content.Write(encoded)
			}
			page.devices = append(page.devices, item)
		}
		if token == "" && (len(page.devices) < len(rows) || format == adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_UNSPECIFIED) {
			// Serialize capacity admission without holding a lock on fleet rows.
			if err := q.LockInventoryMetadata(ctx); err != nil {
				return err
			}
			if err := q.DeleteExpiredDeviceSearchCursors(ctx, timestamptz(now)); err != nil {
				return err
			}
			count, err := q.CountDeviceSearchCursors(ctx, actor.ID)
			if err != nil {
				return err
			}
			if count >= 256 {
				return rpcError(connect.CodeResourceExhausted, "search_cursor_capacity")
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
			page.expires = protoTime(cursor.ExpiresAt)
		}
		if len(page.devices) < len(rows) {
			if len(page.devices) == 0 {
				return errInternalState
			}
			last := rows[len(page.devices)-1]
			position, err := encodeCursor(last.EnrolledAt.Time, last.ID)
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

func searchDevice(row devicedb.SearchDevicesRow) (*adminv1.Device, error) {
	enrolled, ok := finiteTime(row.EnrolledAt)
	if !ok || row.PublishedSequence < 0 || row.HostSequence < 0 || row.PackageSequence < 0 {
		return nil, errInternalState
	}
	state, err := deviceState(row.State)
	if err != nil {
		return nil, err
	}
	metadata := new(adminv1.DeviceMetadata)
	if err := protojson.Unmarshal(row.Metadata, metadata); err != nil {
		return nil, errInternalState
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
		return nil, errInternalState
	}
	return &adminv1.Device{
		Id: row.ID.String(), EnrollmentGeneration: generationString(row.CurrentGenerationID),
		Hostname: row.Hostname, OsId: row.OsID, OsVersion: row.OsVersion, Architecture: row.Architecture,
		LifecycleState: state, EnrolledAt: timestamppb.New(enrolled), LastSeenAt: protoTime(row.LastSeenAt),
		HostSequence: uint64(row.HostSequence), PackageSequence: uint64(row.PackageSequence),
		HostReceivedAt: protoTime(row.HostReceivedAt), PackageAttemptReceivedAt: protoTime(row.PackageAttemptReceivedAt),
		SnapshotReceivedAt: protoTime(row.SnapshotReceivedAt), PublishedSnapshotSequence: uint64(row.PublishedSequence), Metadata: metadata,
		Compliance: compliance, LastVerifiedAt: protoTime(row.LastVerifiedAt),
		AgentRelease: row.AgentRelease, AgentProtocolVersion: uint32(row.AgentProtocolVersion),
		AgentVersionAcceptedAt: protoTime(row.AgentVersionAcceptedAt),
	}, nil
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
	fields := []string{item.GetId(), item.GetHostname(), item.GetOsId(), item.GetOsVersion(), item.GetArchitecture(), item.GetLifecycleState().String(), item.GetEnrolledAt().AsTime().Format(time.RFC3339Nano), seen,
		strings.Join(item.GetMetadata().GetLabels(), ";"), item.GetMetadata().GetOwnerPrincipalId(), item.GetMetadata().GetOwnerText(), string(attributes),
		item.GetCompliance().String(), verified}
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
