package device

import (
	"bytes"
	"context"
	"crypto/sha256"
	"math"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/protodata"
	"lindm/internal/rpcreason"
)

const (
	maxBatchRecords         = 500
	maxBatchBytes           = 768 * 1024
	maxBatches              = 512
	maxSnapshotRecords      = 100000
	maxSnapshotBytes        = 64 << 20
	maxDeviceInventoryBytes = 256 << 20
	defaultInventoryBudget  = 10 << 30
	minInventoryBudget      = 64 << 20
	maxInventoryBudget      = math.MaxInt64
	snapshotOpenTTL         = 24 * time.Hour
	snapshotReceiptTTL      = 90 * 24 * time.Hour
	snapshotAdmissionAge    = 24 * time.Hour
	snapshotFutureSkew      = 5 * time.Minute
	snapshotAttemptInterval = 5 * time.Minute
	supersededBulkRetention = 15 * time.Minute
	packageCursorTTL        = 15 * time.Minute
	receiptMetadataOverhead = 1024
	maxManifestBytes        = 65536
	cleanupInterval         = time.Minute
	uuidTimeSkew            = time.Second
)

type sequenceRelation int

const (
	sequenceOlder sequenceRelation = iota
	sequenceSame
	sequenceNewer
)

type batchPlan struct {
	index         int32
	digest        []byte
	count         int32
	encodedSize   int32
	firstPosition int32
}

type boundManifest struct {
	id            uuid.UUID
	sequence      int64
	createdAt     time.Time
	startedAt     time.Time
	finishedAt    time.Time
	backend       string
	digest        []byte
	canonical     []byte
	packageCount  int32
	batchCount    int32
	encodedBytes  int64
	metadataBytes int64
	reservedBytes int64
	batches       []batchPlan
}

func relateSequence(current, requested int64) sequenceRelation {
	switch {
	case requested < current:
		return sequenceOlder
	case requested == current:
		return sequenceSame
	default:
		return sequenceNewer
	}
}

func rateAllowed(last pgtype.Timestamptz, now time.Time) bool {
	when, ok := finiteTime(last)
	if !ok {
		return true
	}
	return !now.Before(when.Add(snapshotAttemptInterval))
}

func (s *Service) BeginPackageSnapshot(ctx context.Context, req *connect.Request[devicev1.BeginPackageSnapshotRequest]) (*connect.Response[devicev1.BeginPackageSnapshotResponse], error) {
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
	manifest, err := bindManifest(req.Msg.GetManifest(), principal.GenerationID)
	if err != nil {
		return nil, err
	}
	var response *devicev1.BeginPackageSnapshotResponse
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
		generation, err := q.GetGenerationAuthority(ctx, principal.GenerationID)
		if err != nil {
			return err
		}
		authority.generation = generation
		row, err := q.GetPackageSnapshot(ctx, manifest.id)
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		if err == nil {
			response, err = s.replayBegin(ctx, q, authority, manifest, row)
			return err
		}
		response, err = s.admitBegin(ctx, q, authority, manifest)
		return err
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(response), nil
}

func (s *Service) replayBegin(ctx context.Context, q *devicedb.Queries, authority deviceAuthority, manifest boundManifest, row devicedb.GetPackageSnapshotRow) (*devicev1.BeginPackageSnapshotResponse, error) {
	if row.GenerationID != authority.generation.ID || row.DeviceID != authority.device.ID {
		return nil, errInventoryConflict
	}
	if !digestEqual(row.ManifestDigest, manifest.digest) {
		return nil, errInventoryConflict
	}
	if err := s.expireIfClosed(ctx, q, authority.device, row, authority.now); err != nil {
		return nil, err
	}
	if err := q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{LastSeenAt: timestamptz(authority.now), ID: authority.device.ID}); err != nil {
		return nil, err
	}
	return beginResponse(row, authority.generation.PackageSequence, authority.now)
}

func (s *Service) admitBegin(ctx context.Context, q *devicedb.Queries, authority deviceAuthority, manifest boundManifest) (*devicev1.BeginPackageSnapshotResponse, error) {
	if manifest.sequence <= authority.generation.PackageSequence {
		return nil, errSnapshotExpired
	}
	if manifest.createdAt.Before(authority.now.Add(-snapshotAdmissionAge)) {
		return nil, errSnapshotExpired
	}
	if manifest.createdAt.After(authority.now.Add(snapshotFutureSkew)) {
		return nil, invalid("manifest_time")
	}
	refresh, err := claimRefreshInventoryAdmission(ctx, q, authority.device.ID, authority.generation.ID, manifest.sequence, manifest.startedAt, authority.now, true)
	if err != nil {
		return nil, err
	}
	if refresh.challengeIssuedAt.IsZero() && !rateAllowed(authority.generation.LastPackageAdmissionAt, authority.now) {
		return nil, errRateLimited
	}
	if authority.device.OpenSnapshotID != nil {
		if refresh.challengeIssuedAt.IsZero() {
			return nil, errOpenUpload
		}
		old, err := q.GetPackageSnapshot(ctx, *authority.device.OpenSnapshotID)
		if err != nil {
			return nil, err
		}
		if old.DeviceID != authority.device.ID || old.GenerationID != authority.generation.ID || old.State != "staging" || old.Sequence >= manifest.sequence || !old.StartedAt.Valid || !old.AcceptedAt.Valid {
			return nil, errOpenUpload
		}
		// Pregrant admission is authoritative even when the collector clock
		// overlaps the challenge window. Stale postgrant routine data is also
		// replaceable; an already claimed same-action slot never reaches here.
		if old.AcceptedAt.Time.After(refresh.startAuthorizedAt) && !old.StartedAt.Time.Before(refresh.challengeIssuedAt) {
			return nil, errOpenUpload
		}
		// Staging rows were never published or paged. Retain their immutable
		// manifest/batch receipts, but release bulk before reserving fresh data.
		release := old.ReservedBytes - old.MetadataBytes
		if release < 0 || release > authority.device.ReservedInventoryBytes {
			return nil, errInternalState
		}
		if err := s.supersedeSnapshot(ctx, q, authority.device, old.ID, authority.now); err != nil {
			return nil, err
		}
		if err := q.DeleteSnapshotPackages(ctx, old.ID); err != nil {
			return nil, err
		}
		if err := q.ReleaseSnapshotBulk(ctx, devicedb.ReleaseSnapshotBulkParams{ID: old.ID, ReservedBytes: old.MetadataBytes}); err != nil {
			return nil, err
		}
		if err := s.releaseInventory(ctx, q, authority.device.ID, release); err != nil {
			return nil, err
		}
		authority.device.ReservedInventoryBytes -= release
		authority.device.OpenSnapshotID = nil
	}
	if err := s.reserveInventory(ctx, q, authority.device.ID, authority.device.ReservedInventoryBytes, manifest.reservedBytes); err != nil {
		return nil, err
	}
	if err := q.InsertPackageSnapshot(ctx, devicedb.InsertPackageSnapshotParams{
		ID: manifest.id, DeviceID: authority.device.ID, GenerationID: authority.generation.ID,
		Sequence: manifest.sequence, ManifestDigest: manifest.digest, ManifestBytes: manifest.canonical,
		CreatedAt: timestamptz(manifest.createdAt), StartedAt: timestamptz(manifest.startedAt), FinishedAt: timestamptz(manifest.finishedAt),
		AcceptedAt: timestamptz(authority.now), Backend: manifest.backend, PackageCount: manifest.packageCount,
		BatchCount: manifest.batchCount, EncodedBytes: manifest.encodedBytes, MetadataBytes: manifest.metadataBytes,
		ReservedBytes: manifest.reservedBytes,
	}); err != nil {
		return nil, err
	}
	if len(manifest.batches) > 0 {
		rows := make([]devicedb.InsertSnapshotBatchesParams, len(manifest.batches))
		for i, batch := range manifest.batches {
			rows[i] = devicedb.InsertSnapshotBatchesParams{
				SnapshotID: manifest.id, BatchIndex: batch.index, Digest: batch.digest,
				RecordCount: batch.count, EncodedSize: batch.encodedSize, FirstPosition: batch.firstPosition, Stored: false,
			}
		}
		if _, err := q.InsertSnapshotBatches(ctx, rows); err != nil {
			return nil, err
		}
	}
	state, err := activateIfPending(ctx, q, authority.device)
	if err != nil {
		return nil, err
	}
	if err := q.SetOpenSnapshot(ctx, devicedb.SetOpenSnapshotParams{
		OpenSnapshotID: &manifest.id, LastSeenAt: timestamptz(authority.now), State: state, ID: authority.device.ID,
	}); err != nil {
		return nil, err
	}
	if err := q.AdmitPackageSequence(ctx, devicedb.AdmitPackageSequenceParams{
		PackageSequence: manifest.sequence, AdmittedAt: timestamptz(authority.now), ID: authority.generation.ID,
	}); err != nil {
		return nil, err
	}
	stored, err := q.GetPackageSnapshot(ctx, manifest.id)
	if err != nil {
		return nil, err
	}
	return beginResponse(stored, manifest.sequence, authority.now)
}

func (s *Service) PutPackageBatch(ctx context.Context, req *connect.Request[devicev1.PutPackageBatchRequest]) (*connect.Response[devicev1.PutPackageBatchResponse], error) {
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
	snapshotID, err := parseUUID(req.Msg.GetSnapshotId())
	if err != nil {
		return nil, invalid("invalid_id")
	}
	payload := req.Msg.GetBatch()
	if len(payload) == 0 || len(payload) > maxBatchBytes || req.Msg.GetBatchIndex() > maxBatches-1 {
		return nil, invalid("batch")
	}
	sum := sha256.Sum256(payload)
	var response *devicev1.PutPackageBatchResponse
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
		row, err := q.GetPackageSnapshot(ctx, snapshotID)
		if err != nil {
			if err == pgx.ErrNoRows {
				return errSnapshotExpired
			}
			return err
		}
		if row.GenerationID != principal.GenerationID || row.DeviceID != principal.DeviceID {
			return errInventoryConflict
		}
		if err := s.expireIfClosed(ctx, q, authority.device, row, authority.now); err != nil {
			return err
		}
		batch, err := q.GetSnapshotBatch(ctx, devicedb.GetSnapshotBatchParams{SnapshotID: snapshotID, BatchIndex: int32(req.Msg.GetBatchIndex())})
		if err != nil {
			if err == pgx.ErrNoRows {
				return invalid("batch")
			}
			return err
		}
		if int(batch.EncodedSize) != len(payload) || !digestEqual(batch.Digest, sum[:]) {
			return errInventoryConflict
		}
		packages, err := decodeBatch(s.rules, payload, int(batch.RecordCount))
		if err != nil {
			return err
		}
		if !batch.Stored && row.State == "staging" {
			rows := make([]devicedb.InsertSnapshotPackagesParams, len(packages))
			var listings []devicedb.InsertSnapshotPackageListingsParams
			for i, pkg := range packages {
				position := batch.FirstPosition + int32(i)
				if position < batch.FirstPosition || position >= maxSnapshotRecords {
					return errSnapshotCapacity
				}
				rows[i] = devicedb.InsertSnapshotPackagesParams{
					SnapshotID: snapshotID, Position: position, Name: pkg.GetName(), Version: pkg.GetVersion(),
					Architecture: pkg.GetArchitecture(), Manager: pkg.GetManager(),
					SourceName: pkg.GetSourceName(), SourceVersion: pkg.GetSourceVersion(),
					ModuleStatus: int32(pkg.GetModule().GetStatus()), ModuleName: pkg.GetModule().GetName(),
					ModuleStream: pkg.GetModule().GetStream(), ModuleVersion: pkg.GetModule().GetVersion(),
					ModuleContext: pkg.GetModule().GetContext(), OriginStatus: int16(pkg.GetOrigin().GetStatus()),
				}
				// Validation bounds listings to 16 per package.
				for ordinal, listing := range pkg.GetOrigin().GetListings() {
					listings = append(listings, devicedb.InsertSnapshotPackageListingsParams{
						SnapshotID: snapshotID, Position: position, Ordinal: int16(ordinal),
						Origin: listing.GetOrigin(), Label: listing.GetLabel(), Suite: listing.GetSuite(), Codename: listing.GetCodename(),
						Signature: int16(listing.GetSignature()), Signer: listing.GetSigner(),
					})
				}
			}
			if len(rows) > 0 {
				if _, err := q.InsertSnapshotPackages(ctx, rows); err != nil {
					return err
				}
			}
			if len(listings) > 0 {
				if _, err := q.InsertSnapshotPackageListings(ctx, listings); err != nil {
					return err
				}
			}
			if err := q.MarkBatchStored(ctx, devicedb.MarkBatchStoredParams{SnapshotID: snapshotID, BatchIndex: int32(req.Msg.GetBatchIndex())}); err != nil {
				return err
			}
		}
		if err := q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{LastSeenAt: timestamptz(authority.now), ID: authority.device.ID}); err != nil {
			return err
		}
		fresh, err := q.GetPackageSnapshot(ctx, snapshotID)
		if err != nil {
			return err
		}
		response, err = putResponse(fresh, authority.now)
		return err
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(response), nil
}

func (s *Service) CommitPackageSnapshot(ctx context.Context, req *connect.Request[devicev1.CommitPackageSnapshotRequest]) (*connect.Response[devicev1.CommitPackageSnapshotResponse], error) {
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
	manifest, err := bindManifest(req.Msg.GetManifest(), principal.GenerationID)
	if err != nil {
		return nil, err
	}
	var response *devicev1.CommitPackageSnapshotResponse
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
		generation, err := q.GetGenerationAuthority(ctx, principal.GenerationID)
		if err != nil {
			return err
		}
		authority.generation = generation
		row, err := q.GetPackageSnapshot(ctx, manifest.id)
		if err != nil {
			if err == pgx.ErrNoRows {
				return errSnapshotExpired
			}
			return err
		}
		if row.GenerationID != principal.GenerationID || row.DeviceID != principal.DeviceID || !digestEqual(row.ManifestDigest, manifest.digest) {
			return errInventoryConflict
		}
		if err := s.expireIfClosed(ctx, q, authority.device, row, authority.now); err != nil {
			return err
		}
		fresh, err := q.GetPackageSnapshot(ctx, manifest.id)
		if err != nil {
			return err
		}
		switch fresh.State {
		case "committed":
			if err := q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{LastSeenAt: timestamptz(authority.now), ID: authority.device.ID}); err != nil {
				return err
			}
			response, err = commitResponse(fresh, authority.generation.PackageSequence, authority.device.PublishedSequence, authority.now)
			return err
		case "superseded":
			if err := q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{LastSeenAt: timestamptz(authority.now), ID: authority.device.ID}); err != nil {
				return err
			}
			response, err = commitResponse(fresh, authority.generation.PackageSequence, authority.device.PublishedSequence, authority.now)
			return err
		case "staging":
			if fresh.Sequence < authority.generation.PackageSequence {
				if err := s.supersedeSnapshot(ctx, q, authority.device, fresh.ID, authority.now); err != nil {
					return err
				}
				fresh, err = q.GetPackageSnapshot(ctx, manifest.id)
				if err != nil {
					return err
				}
				response, err = commitResponse(fresh, authority.generation.PackageSequence, authority.device.PublishedSequence, authority.now)
				return err
			}
			remaining, err := q.CountUnstoredBatches(ctx, manifest.id)
			if err != nil {
				return err
			}
			if remaining != 0 {
				return errSnapshotIncomplete
			}
			return s.publishSnapshot(ctx, q, authority, fresh, &response)
		default:
			return errSnapshotExpired
		}
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(response), nil
}

func (s *Service) publishSnapshot(ctx context.Context, q *devicedb.Queries, authority deviceAuthority, row devicedb.GetPackageSnapshotRow, response **devicev1.CommitPackageSnapshotResponse) error {
	if authority.generation.CurrentSnapshotID != nil && *authority.generation.CurrentSnapshotID != row.ID {
		if err := s.supersedeSnapshot(ctx, q, authority.device, *authority.generation.CurrentSnapshotID, authority.now); err != nil {
			return err
		}
	}
	if err := q.CommitPackageSnapshot(ctx, devicedb.CommitPackageSnapshotParams{CommittedAt: timestamptz(authority.now), ID: row.ID}); err != nil {
		return err
	}
	if err := q.SetGenerationSnapshot(ctx, devicedb.SetGenerationSnapshotParams{CurrentSnapshotID: &row.ID, ID: authority.generation.ID}); err != nil {
		return err
	}
	state, err := activateIfPending(ctx, q, authority.device)
	if err != nil {
		return err
	}
	accepted, ok := finiteTime(row.AcceptedAt)
	if !ok {
		return errInternalState
	}
	if err := q.PublishDeviceSnapshot(ctx, devicedb.PublishDeviceSnapshotParams{
		PublishedSequence: row.Sequence, SnapshotReceivedAt: timestamptz(accepted), PackageAttemptReceivedAt: timestamptz(accepted),
		LastSeenAt: timestamptz(authority.now), State: state, ID: authority.device.ID,
	}); err != nil {
		return err
	}
	started, ok := finiteTime(row.StartedAt)
	if !ok {
		return errInternalState
	}
	finished, ok := finiteTime(row.FinishedAt)
	if !ok {
		return errInternalState
	}
	if err := q.UpsertPackageAttempt(ctx, devicedb.UpsertPackageAttemptParams{
		GenerationID: authority.generation.ID, Sequence: row.Sequence, StartedAt: timestamptz(started), FinishedAt: timestamptz(finished),
		ReceivedAt: timestamptz(accepted), Status: int16(inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS), Backend: row.Backend,
		SnapshotID: &row.ID, Digest: row.ManifestDigest,
	}); err != nil {
		return err
	}
	fresh, err := q.GetPackageSnapshot(ctx, row.ID)
	if err != nil {
		return err
	}
	*response, err = commitResponse(fresh, row.Sequence, row.Sequence, authority.now)
	return err
}

func (s *Service) supersedeSnapshot(ctx context.Context, q *devicedb.Queries, device devicedb.GetDeviceForUpdateRow, id uuid.UUID, now time.Time) error {
	if err := q.SupersedePackageSnapshot(ctx, devicedb.SupersedePackageSnapshotParams{SupersededAt: timestamptz(now), ID: id}); err != nil {
		return err
	}
	return q.ClearOpenSnapshot(ctx, devicedb.ClearOpenSnapshotParams{ID: device.ID, OpenSnapshotID: &id})
}

func (s *Service) expireIfClosed(ctx context.Context, q *devicedb.Queries, device devicedb.GetDeviceForUpdateRow, row devicedb.GetPackageSnapshotRow, now time.Time) error {
	expires, ok := finiteTime(row.ReceiptExpiresAt)
	if !ok {
		return errInternalState
	}
	if row.State == "expired" || !now.Before(expires) {
		return errSnapshotExpired
	}
	if row.State != "staging" {
		return nil
	}
	open, ok := finiteTime(row.OpenUntil)
	if !ok {
		return errInternalState
	}
	if now.Before(open) {
		return nil
	}
	if err := q.DeleteSnapshotPackages(ctx, row.ID); err != nil {
		return err
	}
	if err := q.ExpireStagingSnapshot(ctx, devicedb.ExpireStagingSnapshotParams{ReservedBytes: row.MetadataBytes, ID: row.ID}); err != nil {
		return err
	}
	release := row.ReservedBytes - row.MetadataBytes
	if release < 0 {
		return errInternalState
	}
	if err := s.releaseInventory(ctx, q, device.ID, release); err != nil {
		return err
	}
	if err := q.ClearOpenSnapshot(ctx, devicedb.ClearOpenSnapshotParams{ID: device.ID, OpenSnapshotID: &row.ID}); err != nil {
		return err
	}
	return errSnapshotExpired
}

func (s *Service) reserveInventory(ctx context.Context, q *devicedb.Queries, deviceID uuid.UUID, reserved, need int64) error {
	if need < 0 || reserved < 0 {
		return errInternalState
	}
	global, err := q.LockInventoryReservation(ctx)
	if err != nil {
		return err
	}
	if need > maxDeviceInventoryBytes || reserved > maxDeviceInventoryBytes-need || need > s.inventoryBudget || global > s.inventoryBudget-need {
		return errInventoryBudget
	}
	if err := q.AddDeviceReservation(ctx, devicedb.AddDeviceReservationParams{Delta: need, ID: deviceID}); err != nil {
		return err
	}
	return q.AddInventoryReservation(ctx, need)
}

func (s *Service) releaseInventory(ctx context.Context, q *devicedb.Queries, deviceID uuid.UUID, amount int64) error {
	if amount == 0 {
		return nil
	}
	if amount < 0 {
		return errInternalState
	}
	if _, err := q.LockInventoryReservation(ctx); err != nil {
		return err
	}
	if err := q.AddDeviceReservation(ctx, devicedb.AddDeviceReservationParams{Delta: -amount, ID: deviceID}); err != nil {
		return err
	}
	return q.AddInventoryReservation(ctx, -amount)
}

func bindManifest(msg *devicev1.PackageSnapshotManifest, generation uuid.UUID) (boundManifest, error) {
	var bound boundManifest
	if msg == nil || msg.GetEnrollmentGeneration() != generation.String() {
		return bound, errGenerationMismatch
	}
	if hasNUL(msg.GetBackend()) {
		return bound, invalid("invalid_text")
	}
	id, err := parseUUID(msg.GetSnapshotId())
	if err != nil || id.Version() != 7 {
		return bound, invalid("manifest")
	}
	created := msg.GetCreatedAt().AsTime().UTC()
	sec, nsec := id.Time().UnixTime()
	if created.Sub(time.Unix(sec, nsec).UTC()).Abs() > uuidTimeSkew {
		return bound, invalid("manifest")
	}
	started := msg.GetStartedAt().AsTime().UTC()
	finished := msg.GetFinishedAt().AsTime().UTC()
	if finished.Before(started) {
		return bound, invalid("manifest")
	}
	sequence, err := sequenceInt(msg.GetSequence())
	if err != nil {
		return bound, err
	}
	if len(msg.GetBatches()) > maxBatches {
		return bound, errSnapshotCapacity
	}
	batches := make([]batchPlan, len(msg.GetBatches()))
	var packages int64
	var encoded int64
	var position int32
	for i, batch := range msg.GetBatches() {
		if batch == nil || int(batch.GetIndex()) != i || len(batch.GetSha256()) != sha256.Size || batch.GetCount() == 0 || batch.GetCount() > maxBatchRecords || batch.GetEncodedSize() == 0 || batch.GetEncodedSize() > maxBatchBytes {
			return bound, invalid("manifest")
		}
		next := position + int32(batch.GetCount())
		if next < position || next > maxSnapshotRecords {
			return bound, errSnapshotCapacity
		}
		packages += int64(batch.GetCount())
		encoded += int64(batch.GetEncodedSize())
		if packages > maxSnapshotRecords || encoded > maxSnapshotBytes {
			return bound, errSnapshotCapacity
		}
		batches[i] = batchPlan{index: int32(i), digest: bytes.Clone(batch.GetSha256()), count: int32(batch.GetCount()), encodedSize: int32(batch.GetEncodedSize()), firstPosition: position}
		position = next
	}
	if err := protodata.ValidateClosed(msg.ProtoReflect()); err != nil {
		return bound, invalid("manifest")
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil || len(canonical) == 0 || len(canonical) > maxManifestBytes {
		return bound, invalid("manifest")
	}
	sum := sha256.Sum256(canonical)
	metadata := int64(len(canonical)) + receiptMetadataOverhead
	return boundManifest{
		id: id, sequence: sequence, createdAt: created, startedAt: started, finishedAt: finished, backend: msg.GetBackend(),
		digest: sum[:], canonical: canonical, packageCount: int32(packages), batchCount: int32(len(batches)),
		encodedBytes: encoded, metadataBytes: metadata, reservedBytes: encoded + metadata, batches: batches,
	}, nil
}

func decodeBatch(rules protovalidate.Validator, payload []byte, count int) ([]*inventoryv1.Package, error) {
	batch := &inventoryv1.PackageBatch{}
	if err := proto.Unmarshal(payload, batch); err != nil {
		return nil, invalid("batch")
	}
	if err := protodata.ValidateClosed(batch.ProtoReflect()); err != nil || rules.Validate(batch) != nil {
		return nil, invalid("batch")
	}
	if len(batch.GetPackages()) != count {
		return nil, errInventoryConflict
	}
	for _, pkg := range batch.GetPackages() {
		if pkg == nil || hasNUL(
			pkg.GetName(), pkg.GetVersion(), pkg.GetArchitecture(), pkg.GetManager(), pkg.GetSourceName(), pkg.GetSourceVersion(),
			pkg.GetModule().GetName(), pkg.GetModule().GetStream(), pkg.GetModule().GetVersion(), pkg.GetModule().GetContext(),
		) {
			return nil, invalid("invalid_text")
		}
	}
	return batch.GetPackages(), nil
}

func sequenceInt(v uint64) (int64, error) {
	if v == 0 || v > uint64(math.MaxInt64) {
		return 0, invalid("sequence")
	}
	return int64(v), nil
}

func snapshotState(state string) (inventoryv1.SnapshotState, error) {
	switch state {
	case "staging":
		return inventoryv1.SnapshotState_SNAPSHOT_STATE_STAGING, nil
	case "committed":
		return inventoryv1.SnapshotState_SNAPSHOT_STATE_COMMITTED, nil
	case "superseded":
		return inventoryv1.SnapshotState_SNAPSHOT_STATE_SUPERSEDED, nil
	case "expired":
		return inventoryv1.SnapshotState_SNAPSHOT_STATE_EXPIRED, nil
	default:
		return 0, errInternalState
	}
}

func beginResponse(row devicedb.GetPackageSnapshotRow, packageSequence int64, now time.Time) (*devicev1.BeginPackageSnapshotResponse, error) {
	state, err := snapshotState(row.State)
	if err != nil || packageSequence < 0 {
		return nil, errInternalState
	}
	accepted, ok := finiteTime(row.AcceptedAt)
	if !ok {
		return nil, errInternalState
	}
	open, ok := finiteTime(row.OpenUntil)
	if !ok {
		return nil, errInternalState
	}
	expires, ok := finiteTime(row.ReceiptExpiresAt)
	if !ok {
		return nil, errInternalState
	}
	return &devicev1.BeginPackageSnapshotResponse{
		State: state, PackageSequence: uint64(packageSequence), AcceptedAt: timestamppb.New(accepted),
		OpenUntil: timestamppb.New(open), ReceiptExpiresAt: timestamppb.New(expires), ServerTime: timestamppb.New(now),
	}, nil
}

func putResponse(row devicedb.GetPackageSnapshotRow, now time.Time) (*devicev1.PutPackageBatchResponse, error) {
	state, err := snapshotState(row.State)
	if err != nil {
		return nil, err
	}
	accepted, ok := finiteTime(row.AcceptedAt)
	if !ok {
		return nil, errInternalState
	}
	return &devicev1.PutPackageBatchResponse{State: state, AcceptedAt: timestamppb.New(accepted), ServerTime: timestamppb.New(now)}, nil
}

func commitResponse(row devicedb.GetPackageSnapshotRow, packageSequence, published int64, now time.Time) (*devicev1.CommitPackageSnapshotResponse, error) {
	state, err := snapshotState(row.State)
	if err != nil || packageSequence < 0 || published < 0 {
		return nil, errInternalState
	}
	accepted, ok := finiteTime(row.AcceptedAt)
	if !ok {
		return nil, errInternalState
	}
	expires, ok := finiteTime(row.ReceiptExpiresAt)
	if !ok {
		return nil, errInternalState
	}
	return &devicev1.CommitPackageSnapshotResponse{
		State: state, PackageSequence: uint64(packageSequence), PublishedSequence: uint64(published),
		AcceptedAt: timestamppb.New(accepted), ReceiptExpiresAt: timestamppb.New(expires), ServerTime: timestamppb.New(now),
	}, nil
}

func activateIfPending(ctx context.Context, q *devicedb.Queries, device devicedb.GetDeviceForUpdateRow) (string, error) {
	if device.State != statePending {
		return device.State, nil
	}
	if device.CurrentGenerationID == nil {
		return "", errInternalState
	}
	if err := q.ActivateGeneration(ctx, *device.CurrentGenerationID); err != nil {
		return "", err
	}
	if err := insertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{ID: uuid.New(), Action: actionDeviceActivate, ResourceID: device.ID.String(), TargetDeviceID: &device.ID}, auditDetails("status", "activated")); err != nil {
		return "", err
	}
	return stateActive, nil
}
