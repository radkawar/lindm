package device

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"unicode/utf8"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func (s *Service) GetDevice(ctx context.Context, req *connect.Request[adminv1.GetDeviceRequest]) (*connect.Response[adminv1.GetDeviceResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if req.Msg == nil {
		return nil, invalid("invalid_argument")
	}
	id, err := parseUUID(req.Msg.GetDeviceId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	// Every component must describe the same committed device state, without
	// preventing concurrent host reports or snapshot publication.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	if err := requireDeviceScope(ctx, q, actor, identity.PermissionReadFleet, id); err != nil {
		return nil, mapErr(err)
	}
	row, err := q.GetDeviceDetail(ctx, id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errNotFound
		}
		return nil, mapErr(err)
	}
	device, err := deviceFromDetail(row)
	if err != nil {
		return nil, mapErr(err)
	}
	metadata, err := q.GetDeviceMetadata(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	device.Metadata = new(adminv1.DeviceMetadata)
	if err := protojson.Unmarshal(metadata, device.Metadata); err != nil {
		return nil, mapErr(errInternalState)
	}
	response := &adminv1.GetDeviceResponse{Device: device}
	if row.CurrentGenerationID != nil {
		host, err := q.GetHostObservation(ctx, *row.CurrentGenerationID)
		if err != nil && err != pgx.ErrNoRows {
			return nil, mapErr(err)
		}
		if err == nil {
			detail, err := hostDetail(host)
			if err != nil {
				return nil, mapErr(err)
			}
			response.Host = detail
		}
		attempt, err := q.GetPackageAttempt(ctx, *row.CurrentGenerationID)
		if err != nil && err != pgx.ErrNoRows {
			return nil, mapErr(err)
		}
		if err == nil {
			detail, err := attemptDetail(attempt)
			if err != nil {
				return nil, mapErr(err)
			}
			response.PackageAttempt = detail
		}
	}
	if row.CurrentSnapshotID != nil {
		snapshot, err := q.GetPackageSnapshot(ctx, *row.CurrentSnapshotID)
		if err != nil {
			return nil, mapErr(err)
		}
		detail, err := snapshotDetail(snapshot)
		if err != nil {
			return nil, mapErr(err)
		}
		response.CurrentSnapshot = detail
	}
	if row.OpenSnapshotID != nil {
		snapshot, err := q.GetPackageSnapshot(ctx, *row.OpenSnapshotID)
		if err != nil && err != pgx.ErrNoRows {
			return nil, mapErr(err)
		}
		if err == nil && snapshot.State == "staging" {
			detail, err := snapshotDetail(snapshot)
			if err != nil {
				return nil, mapErr(err)
			}
			response.StagingSnapshot = detail
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(response), nil
}

func (s *Service) ListDevicePackages(ctx context.Context, req *connect.Request[adminv1.ListDevicePackagesRequest]) (*connect.Response[adminv1.ListDevicePackagesResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if req.Msg == nil {
		return nil, invalid("invalid_argument")
	}
	deviceID, err := parseUUID(req.Msg.GetDeviceId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	if hasNUL(req.Msg.GetManager(), req.Msg.GetNamePrefix()) || !utf8.ValidString(req.Msg.GetNamePrefix()) {
		return nil, invalid("invalid_text")
	}
	limit := pageLimit(req.Msg.GetPageSize())
	var response *adminv1.ListDevicePackagesResponse
	err = s.within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		device, err := lockDeviceScope(ctx, q, actor, identity.PermissionReadFleet, deviceID)
		if err != nil {
			if err == pgx.ErrNoRows {
				return errNotFound
			}
			return err
		}
		var cursor devicedb.PackagePageCursor
		var position uint32
		var pageToken string
		if req.Msg.GetPageToken() == "" {
			detail, err := q.GetDeviceDetail(ctx, deviceID)
			if err != nil {
				return err
			}
			if detail.CurrentSnapshotID == nil || detail.CurrentGenerationID == nil {
				return errSnapshotUnavailable
			}
			cursorID := uuid.New()
			if err := q.InsertPackageCursor(ctx, devicedb.InsertPackageCursorParams{
				ID: cursorID, ActorID: actor.ID, DeviceID: deviceID, GenerationID: *detail.CurrentGenerationID,
				SnapshotID: *detail.CurrentSnapshotID, Manager: req.Msg.GetManager(), NamePrefix: req.Msg.GetNamePrefix(),
				NextPosition: 0, CreatedAt: timestamptz(s.now()),
			}); err != nil {
				return err
			}
			cursor, err = q.GetPackageCursorForUpdate(ctx, cursorID)
			if err != nil {
				return err
			}
			pageToken, err = encodePackagePage(cursor.ID, 0)
			if err != nil {
				return err
			}
		} else {
			cursorID, start, err := decodePackagePage(req.Msg.GetPageToken())
			if err != nil {
				return err
			}
			cursor, err = q.GetPackageCursorForUpdate(ctx, cursorID)
			if err != nil {
				if err == pgx.ErrNoRows {
					return invalid("page_token")
				}
				return err
			}
			if cursor.ActorID != actor.ID || cursor.DeviceID != deviceID {
				return invalid("page_token")
			}
			position = start
			pageToken = req.Msg.GetPageToken()
		}
		expires, ok := finiteTime(cursor.ExpiresAt)
		if !ok {
			return errInternalState
		}
		// A request can wait on the cursor row after taking the device lock.
		// Judge its fixed expiry only after both locks have been acquired.
		if !s.now().Before(expires) {
			return errPageExpired
		}
		snapshot, err := q.GetPackageSnapshot(ctx, cursor.SnapshotID)
		if err != nil {
			if err == pgx.ErrNoRows {
				return errSnapshotExpired
			}
			return err
		}
		if snapshot.DeviceID != device.ID || !snapshot.BulkRetained {
			return errSnapshotExpired
		}
		if snapshot.Sequence < 0 {
			return errInternalState
		}
		pattern := "%"
		if cursor.NamePrefix != "" {
			pattern = likePrefix(cursor.NamePrefix)
		}
		rows, err := q.ListSnapshotPackages(ctx, devicedb.ListSnapshotPackagesParams{
			SnapshotID: cursor.SnapshotID, NextPosition: int32(position), Manager: cursor.Manager,
			NamePrefix: cursor.NamePrefix, NamePattern: pattern, RowLimit: limit + 1,
		})
		if err != nil {
			return err
		}
		var budget responsePageBudget
		packages := make([]*adminv1.DevicePackage, 0, min(len(rows), int(limit)))
		for _, row := range rows {
			if int32(len(packages)) == limit {
				break
			}
			if row.Position < 0 {
				return errInternalState
			}
			item := &adminv1.DevicePackage{
				Position: uint32(row.Position), Name: row.Name, Version: row.Version, Architecture: row.Architecture, Manager: row.Manager,
				SourceName: row.SourceName, SourceVersion: row.SourceVersion,
			}
			if row.ModuleStatus != 0 {
				item.Module = &inventoryv1.ModuleObservation{
					Status: inventoryv1.CollectionStatus(row.ModuleStatus), Modular: row.ModuleName != "",
					Name: row.ModuleName, Stream: row.ModuleStream, Version: row.ModuleVersion, Context: row.ModuleContext,
				}
			}
			fits, err := budget.take(item)
			if err != nil {
				return err
			}
			if !fits {
				if len(packages) == 0 {
					return errInternalState
				}
				break
			}
			packages = append(packages, item)
		}
		next := ""
		if len(packages) < len(rows) {
			last := packages[len(packages)-1]
			next, err = encodePackagePage(cursor.ID, last.Position+1)
			if err != nil {
				return err
			}
		}
		response = &adminv1.ListDevicePackagesResponse{
			SnapshotId: cursor.SnapshotID.String(), Sequence: uint64(snapshot.Sequence), Packages: packages,
			NextPageToken: next, CursorExpiresAt: timestamppb.New(expires), PageToken: pageToken,
		}
		return nil
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(response), nil
}

func deviceFromDetail(row devicedb.GetDeviceDetailRow) (*adminv1.Device, error) {
	enrolled, ok := finiteTime(row.EnrolledAt)
	if !ok || row.PublishedSequence < 0 || row.HostSequence < 0 || row.PackageSequence < 0 {
		return nil, errInternalState
	}
	state, err := deviceState(row.State)
	if err != nil {
		return nil, err
	}
	return &adminv1.Device{
		Id: row.ID.String(), EnrollmentGeneration: generationString(row.CurrentGenerationID),
		Hostname: row.Hostname, OsId: row.OsID, OsVersion: row.OsVersion, Architecture: row.Architecture,
		LifecycleState: state, EnrolledAt: timestamppb.New(enrolled), LastSeenAt: protoTime(row.LastSeenAt),
		HostSequence: uint64(row.HostSequence), PackageSequence: uint64(row.PackageSequence),
		HostReceivedAt: protoTime(row.HostReceivedAt), PackageAttemptReceivedAt: protoTime(row.PackageAttemptReceivedAt),
		SnapshotReceivedAt: protoTime(row.SnapshotReceivedAt), PublishedSnapshotSequence: uint64(row.PublishedSequence),
	}, nil
}

func hostDetail(row devicedb.GetHostObservationRow) (*adminv1.HostObservationDetail, error) {
	if row.Sequence < 0 {
		return nil, errInternalState
	}
	started, ok := finiteTime(row.StartedAt)
	if !ok {
		return nil, errInternalState
	}
	finished, ok := finiteTime(row.FinishedAt)
	if !ok {
		return nil, errInternalState
	}
	received, ok := finiteTime(row.ReceivedAt)
	if !ok {
		return nil, errInternalState
	}
	observation := &inventoryv1.HostObservation{StartedAt: timestamppb.New(started), FinishedAt: timestamppb.New(finished)}
	var err error
	if observation.BootId, err = observedMessage(row.BootIDStatus, row.BootIDValue); err != nil {
		return nil, err
	}
	if observation.Hostname, err = observedMessage(row.HostnameStatus, row.HostnameValue); err != nil {
		return nil, err
	}
	if observation.OsId, err = observedMessage(row.OsIDStatus, row.OsIDValue); err != nil {
		return nil, err
	}
	if observation.OsVersion, err = observedMessage(row.OsVersionStatus, row.OsVersionValue); err != nil {
		return nil, err
	}
	if observation.Architecture, err = observedMessage(row.ArchitectureStatus, row.ArchitectureValue); err != nil {
		return nil, err
	}
	if observation.KernelRelease, err = observedMessage(row.KernelReleaseStatus, row.KernelReleaseValue); err != nil {
		return nil, err
	}
	if observation.HardwareVendor, err = observedMessage(row.HardwareVendorStatus, row.HardwareVendorValue); err != nil {
		return nil, err
	}
	if observation.HardwareModel, err = observedMessage(row.HardwareModelStatus, row.HardwareModelValue); err != nil {
		return nil, err
	}
	if observation.HardwareSerial, err = observedMessage(row.HardwareSerialStatus, row.HardwareSerialValue); err != nil {
		return nil, err
	}
	if len(row.Details) != 0 {
		observation.Details = &inventoryv1.NativeDetails{}
		if err := proto.Unmarshal(row.Details, observation.Details); err != nil {
			return nil, errInternalState
		}
	}
	return &adminv1.HostObservationDetail{Sequence: uint64(row.Sequence), Observation: observation, ReceivedAt: timestamppb.New(received)}, nil
}

func attemptDetail(row devicedb.GetPackageAttemptRow) (*adminv1.PackageAttemptDetail, error) {
	if row.Sequence < 0 {
		return nil, errInternalState
	}
	started, ok := finiteTime(row.StartedAt)
	if !ok {
		return nil, errInternalState
	}
	finished, ok := finiteTime(row.FinishedAt)
	if !ok {
		return nil, errInternalState
	}
	received, ok := finiteTime(row.ReceivedAt)
	if !ok {
		return nil, errInternalState
	}
	status, err := collectionStatus(row.Status)
	if err != nil {
		return nil, err
	}
	detail := &adminv1.PackageAttemptDetail{
		Sequence: uint64(row.Sequence), StartedAt: timestamppb.New(started), FinishedAt: timestamppb.New(finished),
		ReceivedAt: timestamppb.New(received), Status: status, Backend: row.Backend,
	}
	if row.SnapshotID != nil {
		detail.SnapshotId = row.SnapshotID.String()
	}
	return detail, nil
}

func snapshotDetail(row devicedb.GetPackageSnapshotRow) (*adminv1.PackageSnapshotDetail, error) {
	state, err := snapshotState(row.State)
	if err != nil || row.Sequence < 0 || row.PackageCount < 0 || row.BatchCount < 0 || row.EncodedBytes < 0 {
		return nil, errInternalState
	}
	created, ok := finiteTime(row.CreatedAt)
	if !ok {
		return nil, errInternalState
	}
	started, ok := finiteTime(row.StartedAt)
	if !ok {
		return nil, errInternalState
	}
	finished, ok := finiteTime(row.FinishedAt)
	if !ok {
		return nil, errInternalState
	}
	received, ok := finiteTime(row.AcceptedAt)
	if !ok {
		return nil, errInternalState
	}
	return &adminv1.PackageSnapshotDetail{
		SnapshotId: row.ID.String(), Sequence: uint64(row.Sequence), State: state,
		CreatedAt: timestamppb.New(created), StartedAt: timestamppb.New(started), FinishedAt: timestamppb.New(finished),
		ReceivedAt: timestamppb.New(received), CommittedAt: protoTime(row.CommittedAt), SupersededAt: protoTime(row.SupersededAt),
		Backend: row.Backend, PackageCount: uint32(row.PackageCount), BatchCount: uint32(row.BatchCount),
		EncodedBytes: uint64(row.EncodedBytes), PackagesAvailable: row.BulkRetained,
	}, nil
}

func observedMessage(status int16, value string) (*inventoryv1.ObservedString, error) {
	parsed, err := collectionStatus(status)
	if err != nil {
		return nil, err
	}
	return &inventoryv1.ObservedString{Status: parsed, Value: value}, nil
}

func collectionStatus(status int16) (inventoryv1.CollectionStatus, error) {
	parsed := inventoryv1.CollectionStatus(status)
	if parsed < inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS || parsed > inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE {
		return 0, errInternalState
	}
	return parsed, nil
}

func encodePackagePage(id uuid.UUID, position uint32) (string, error) {
	if id == uuid.Nil || position > maxSnapshotRecords {
		return "", invalid("page_token")
	}
	var buf [21]byte
	buf[0] = 2
	copy(buf[1:17], id[:])
	binary.BigEndian.PutUint32(buf[17:], position)
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

func decodePackagePage(token string) (uuid.UUID, uint32, error) {
	if token == "" || len(token) > 512 {
		return uuid.Nil, 0, invalid("page_token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 21 || raw[0] != 2 {
		return uuid.Nil, 0, invalid("page_token")
	}
	id, err := uuid.FromBytes(raw[1:17])
	if err != nil || id == uuid.Nil {
		return uuid.Nil, 0, invalid("page_token")
	}
	position := binary.BigEndian.Uint32(raw[17:])
	if position > maxSnapshotRecords {
		return uuid.Nil, 0, invalid("page_token")
	}
	return id, position, nil
}

func likePrefix(prefix string) string {
	var b strings.Builder
	for _, r := range prefix {
		if r == '%' || r == '_' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('%')
	return b.String()
}
