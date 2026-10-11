package device

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/protodata"
	"lindm/internal/rpcreason"
)

func (s *Service) ReportHostObservation(ctx context.Context, req *connect.Request[devicev1.ReportHostObservationRequest]) (*connect.Response[devicev1.ReportHostObservationResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req.Msg == nil || !validSessionEpoch(req.Msg.GetSessionEpoch()) {
		return nil, invalid("session_epoch")
	}
	generation, err := parseUUID(req.Msg.GetEnrollmentGeneration())
	if err != nil || generation != principal.GenerationID {
		return nil, errGenerationMismatch
	}
	sequence, err := sequenceInt(req.Msg.GetSequence())
	if err != nil {
		return nil, err
	}
	observation := req.Msg.GetObservation()
	if observation == nil || protodata.ValidateClosed(observation.ProtoReflect()) != nil {
		return nil, invalid("observation")
	}
	if err := s.rules.Validate(observation); err != nil {
		return nil, invalid("observation")
	}
	// Device detail also carries list projections and bounded administrator
	// metadata. Reserve half the response envelope for those independent rows.
	if proto.Size(observation) > maxMessageBytes/2 {
		return nil, invalid("observation_capacity")
	}
	encoded, err := (protojson.MarshalOptions{Multiline: true}).Marshal(observation)
	if err != nil || len(encoded) > maxMessageBytes/2 {
		return nil, invalid("observation_capacity")
	}
	if err := observationText(observation); err != nil {
		return nil, err
	}
	digest, err := hostDigest(principal.GenerationID.String(), req.Msg.GetSequence(), observation)
	if err != nil {
		return nil, invalid("observation")
	}
	var accepted uint64
	serverTime := s.now()
	err = s.within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		authority, err := s.lockAuthority(ctx, q, principal)
		if err != nil {
			return err
		}
		if uint64(authority.generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
			return errSessionFenced
		}
		serverTime = authority.now
		switch relateSequence(authority.generation.HostSequence, sequence) {
		case sequenceOlder:
			accepted = uint64(authority.generation.HostSequence)
			return q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{LastSeenAt: timestamptz(authority.now), ID: authority.device.ID})
		case sequenceSame:
			row, err := q.GetHostObservation(ctx, principal.GenerationID)
			if err != nil {
				return err
			}
			if row.Sequence != sequence || !digestEqual(row.Digest, digest) {
				return errInventoryConflict
			}
			accepted = uint64(sequence)
			return q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{LastSeenAt: timestamptz(authority.now), ID: authority.device.ID})
		default:
			refresh, err := claimRefreshInventoryAdmission(ctx, q, authority.device.ID, principal.GenerationID, sequence, observation.GetStartedAt().AsTime(), authority.now, false)
			if err != nil {
				return err
			}
			if refresh.challengeIssuedAt.IsZero() && !rateAllowed(authority.generation.LastHostAdmissionAt, authority.now) {
				return errRateLimited
			}
			fields, err := hostFields(observation)
			if err != nil {
				return err
			}
			fields.GenerationID = principal.GenerationID
			fields.Sequence = sequence
			fields.StartedAt = timestamptz(observation.GetStartedAt().AsTime())
			fields.FinishedAt = timestamptz(observation.GetFinishedAt().AsTime())
			fields.ReceivedAt = timestamptz(authority.now)
			fields.Digest = digest
			if err := q.UpsertHostObservation(ctx, fields); err != nil {
				return err
			}
			state, err := activateIfPending(ctx, q, authority.device)
			if err != nil {
				return err
			}
			if err := q.UpdateHostProjection(ctx, projectionParams(observation, authority.now, state, authority.device.ID)); err != nil {
				return err
			}
			if err := q.AdmitHostSequence(ctx, devicedb.AdmitHostSequenceParams{HostSequence: sequence, AdmittedAt: timestamptz(authority.now), ID: principal.GenerationID}); err != nil {
				return err
			}
			accepted = uint64(sequence)
			return nil
		}
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(&devicev1.ReportHostObservationResponse{AcceptedSequence: accepted, ServerTime: timestamppb.New(serverTime)}), nil
}

func (s *Service) ReportPackageAttempt(ctx context.Context, req *connect.Request[devicev1.ReportPackageAttemptRequest]) (*connect.Response[devicev1.ReportPackageAttemptResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req.Msg == nil || !validSessionEpoch(req.Msg.GetSessionEpoch()) {
		return nil, invalid("session_epoch")
	}
	generation, err := parseUUID(req.Msg.GetEnrollmentGeneration())
	if err != nil || generation != principal.GenerationID {
		return nil, errGenerationMismatch
	}
	sequence, err := sequenceInt(req.Msg.GetSequence())
	if err != nil {
		return nil, err
	}
	status := req.Msg.GetStatus()
	if status == inventoryv1.CollectionStatus_COLLECTION_STATUS_UNSPECIFIED || status == inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS {
		return nil, invalid("attempt_status")
	}
	if hasNUL(req.Msg.GetBackend()) || req.Msg.GetFinishedAt().AsTime().Before(req.Msg.GetStartedAt().AsTime()) {
		return nil, invalid("attempt")
	}
	digest := attemptDigest(principal.GenerationID.String(), req.Msg.GetSequence(), req.Msg.GetStartedAt().AsTime(), req.Msg.GetFinishedAt().AsTime(), status, req.Msg.GetBackend())
	var accepted uint64
	serverTime := s.now()
	err = s.within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		authority, err := s.lockAuthority(ctx, q, principal)
		if err != nil {
			return err
		}
		if uint64(authority.generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
			return errSessionFenced
		}
		if err := s.cleanupDevice(ctx, q, authority.device, authority.now); err != nil {
			return err
		}
		device, err := q.GetDeviceForUpdate(ctx, principal.DeviceID)
		if err != nil {
			return err
		}
		authority.device = device
		serverTime = authority.now
		switch relateSequence(authority.generation.PackageSequence, sequence) {
		case sequenceOlder:
			accepted = uint64(authority.generation.PackageSequence)
			return q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{LastSeenAt: timestamptz(authority.now), ID: authority.device.ID})
		case sequenceSame:
			_, err := q.GetPackageSnapshotBySequence(ctx, devicedb.GetPackageSnapshotBySequenceParams{GenerationID: principal.GenerationID, Sequence: sequence})
			if err != nil && err != pgx.ErrNoRows {
				return err
			}
			if err == nil {
				return errInventoryConflict
			}
			row, err := q.GetPackageAttempt(ctx, principal.GenerationID)
			if err != nil {
				return err
			}
			if row.Sequence != sequence || !digestEqual(row.Digest, digest) {
				return errInventoryConflict
			}
			accepted = uint64(sequence)
			return q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{LastSeenAt: timestamptz(authority.now), ID: authority.device.ID})
		default:
			if !rateAllowed(authority.generation.LastPackageAdmissionAt, authority.now) {
				return errRateLimited
			}
			if authority.device.OpenSnapshotID != nil {
				if err := s.supersedeSnapshot(ctx, q, authority.device, *authority.device.OpenSnapshotID, authority.now); err != nil {
					return err
				}
			}
			state, err := activateIfPending(ctx, q, authority.device)
			if err != nil {
				return err
			}
			if err := q.UpsertPackageAttempt(ctx, devicedb.UpsertPackageAttemptParams{
				GenerationID: principal.GenerationID, Sequence: sequence,
				StartedAt: timestamptz(req.Msg.GetStartedAt().AsTime()), FinishedAt: timestamptz(req.Msg.GetFinishedAt().AsTime()),
				ReceivedAt: timestamptz(authority.now), Status: int16(status), Backend: req.Msg.GetBackend(), Digest: digest,
			}); err != nil {
				return err
			}
			if err := q.AdmitPackageSequence(ctx, devicedb.AdmitPackageSequenceParams{PackageSequence: sequence, AdmittedAt: timestamptz(authority.now), ID: principal.GenerationID}); err != nil {
				return err
			}
			if err := q.TouchPackageAttempt(ctx, devicedb.TouchPackageAttemptParams{
				PackageAttemptReceivedAt: timestamptz(authority.now), LastSeenAt: timestamptz(authority.now), State: state, ID: authority.device.ID,
			}); err != nil {
				return err
			}
			accepted = uint64(sequence)
			return nil
		}
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(&devicev1.ReportPackageAttemptResponse{AcceptedSequence: accepted, ServerTime: timestamppb.New(serverTime)}), nil
}

func hostDigest(generation string, sequence uint64, observation *inventoryv1.HostObservation) ([]byte, error) {
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(observation)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	writeLenString(h, "lindm-host-observation-v1")
	writeLenString(h, generation)
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], sequence)
	_, _ = h.Write(seq[:])
	_, _ = h.Write(canonical)
	return h.Sum(nil), nil
}

func attemptDigest(generation string, sequence uint64, started, finished time.Time, status inventoryv1.CollectionStatus, backend string) []byte {
	h := sha256.New()
	writeLenString(h, "lindm-package-attempt-v1")
	writeLenString(h, generation)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], sequence)
	_, _ = h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], uint64(started.UnixNano()))
	_, _ = h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], uint64(finished.UnixNano()))
	_, _ = h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], uint64(status))
	_, _ = h.Write(buf[:])
	writeLenString(h, backend)
	return h.Sum(nil)
}

func observationText(observation *inventoryv1.HostObservation) error {
	fields := []*inventoryv1.ObservedString{
		observation.GetBootId(), observation.GetHostname(), observation.GetOsId(), observation.GetOsVersion(),
		observation.GetArchitecture(), observation.GetKernelRelease(), observation.GetHardwareVendor(),
		observation.GetHardwareModel(), observation.GetHardwareSerial(),
	}
	for _, field := range fields {
		if field == nil || hasNUL(field.GetValue()) {
			return invalid("invalid_text")
		}
	}
	return nil
}

func hostFields(observation *inventoryv1.HostObservation) (devicedb.UpsertHostObservationParams, error) {
	var params devicedb.UpsertHostObservationParams
	var err error
	if params.BootIDStatus, params.BootIDValue, err = observedParts(observation.GetBootId()); err != nil {
		return params, err
	}
	if params.HostnameStatus, params.HostnameValue, err = observedParts(observation.GetHostname()); err != nil {
		return params, err
	}
	if params.OsIDStatus, params.OsIDValue, err = observedParts(observation.GetOsId()); err != nil {
		return params, err
	}
	if params.OsVersionStatus, params.OsVersionValue, err = observedParts(observation.GetOsVersion()); err != nil {
		return params, err
	}
	if params.ArchitectureStatus, params.ArchitectureValue, err = observedParts(observation.GetArchitecture()); err != nil {
		return params, err
	}
	if params.KernelReleaseStatus, params.KernelReleaseValue, err = observedParts(observation.GetKernelRelease()); err != nil {
		return params, err
	}
	if params.HardwareVendorStatus, params.HardwareVendorValue, err = observedParts(observation.GetHardwareVendor()); err != nil {
		return params, err
	}
	if params.HardwareModelStatus, params.HardwareModelValue, err = observedParts(observation.GetHardwareModel()); err != nil {
		return params, err
	}
	if params.HardwareSerialStatus, params.HardwareSerialValue, err = observedParts(observation.GetHardwareSerial()); err != nil {
		return params, err
	}
	params.Details = []byte{}
	if observation.GetDetails() != nil {
		params.Details, err = proto.MarshalOptions{Deterministic: true}.Marshal(observation.GetDetails())
	}
	return params, err
}

func observedParts(field *inventoryv1.ObservedString) (int16, string, error) {
	if field == nil {
		return 0, "", invalid("observation")
	}
	status := field.GetStatus()
	if status < inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS || status > inventoryv1.CollectionStatus_COLLECTION_STATUS_NATIVE_COMMAND_FAILURE {
		return 0, "", invalid("observation")
	}
	value := field.GetValue()
	success := status == inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	if success != (value != "") {
		return 0, "", invalid("observation")
	}
	return int16(status), value, nil
}

func projectionParams(observation *inventoryv1.HostObservation, now time.Time, state string, id uuid.UUID) devicedb.UpdateHostProjectionParams {
	params := devicedb.UpdateHostProjectionParams{HostReceivedAt: timestamptz(now), LastSeenAt: timestamptz(now), State: state, ID: id}
	if observation.GetHostname().GetStatus() == inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS {
		params.SetHostname = true
		params.Hostname = observation.GetHostname().GetValue()
	}
	if observation.GetOsId().GetStatus() == inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS {
		params.SetOsID = true
		params.OsID = observation.GetOsId().GetValue()
	}
	if observation.GetOsVersion().GetStatus() == inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS {
		params.SetOsVersion = true
		params.OsVersion = observation.GetOsVersion().GetValue()
	}
	if observation.GetArchitecture().GetStatus() == inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS {
		params.SetArchitecture = true
		params.Architecture = observation.GetArchitecture().GetValue()
	}
	return params
}
