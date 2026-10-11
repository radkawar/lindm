//go:build integration

package device

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lindm/internal/device/inventory"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/identity"
	"lindm/internal/testdb"
)

type enrolledFixture struct {
	ctx        context.Context
	svc        *Service
	conn       *pgx.Conn
	principal  core.DevicePrincipal
	key        ed25519.PrivateKey
	generation string
	deviceID   string
	ownerCtx   context.Context
	now        time.Time
}

func newEnrolled(t *testing.T, budget int64) *enrolledFixture {
	t.Helper()
	f := &enrolledFixture{ctx: t.Context(), now: time.Now().UTC().Truncate(time.Microsecond)}
	pool, conn := testdb.Open(t)
	f.conn = conn
	ca, caKey := testCA(t, f.now.Add(90*24*time.Hour))
	svc, err := New(pool, core.Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: caKey, InventoryBudgetBytes: budget, Identity: localIdentity(t, pool)})
	if err != nil {
		t.Fatal(err)
	}
	svc.Clock = func() time.Time { return f.now }
	f.svc = svc
	f.ownerCtx = identity.WithPrincipal(f.ctx, insertPrincipal(t, f.ctx, conn, identity.RoleOwner))
	f.key = ed25519Key(t)
	_, _, _, enrolled := enrollDevice(t, f.ctx, svc, f.ownerCtx, f.key)
	leaf := parseCertPEM(t, enrolled.Msg.GetCertificatePem())
	principal, err := svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), leaf)
	if err != nil {
		t.Fatal(err)
	}
	f.principal = principal
	f.generation = enrolled.Msg.GetEnrollmentGeneration()
	f.deviceID = enrolled.Msg.GetDeviceId()
	acquireTestSession(t, f.ctx, svc, principal, f.key, 0)
	return f
}

func (f *enrolledFixture) deviceCtx() context.Context {
	return core.WithDevicePrincipal(f.ctx, f.principal)
}

func TestSnapshotResumeAcrossSessionEpoch(t *testing.T) {
	f := newEnrolled(t, 0)
	first := packageBatch(t, &inventoryv1.Package{Name: "alpha", Version: "1", Architecture: "amd64", Manager: "apt"})
	second := packageBatch(t, &inventoryv1.Package{Name: "beta", Version: "1", Architecture: "amd64", Manager: "apt"})
	manifest := snapshotManifest(t, f.generation, 1, f.now, [][]byte{first, second})
	begun, err := f.begin(t, manifest, 1)
	if err != nil || begun.GetState() != inventoryv1.SnapshotState_SNAPSHOT_STATE_STAGING {
		t.Fatalf("begin: %v %+v", err, begun)
	}
	if _, err := f.put(t, manifest.GetSnapshotId(), 0, first, 1); err != nil {
		t.Fatal(err)
	}
	acquireTestSession(t, f.ctx, f.svc, f.principal, f.key, 1)
	if _, err := f.begin(t, manifest, 1); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("old epoch begin: %v", err)
	}
	if _, err := f.put(t, manifest.GetSnapshotId(), 1, second, 1); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("old epoch put: %v", err)
	}
	if _, err := f.commit(t, manifest, 1); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("old epoch commit: %v", err)
	}
	resumed, err := f.begin(t, manifest, 2)
	if err != nil || resumed.GetState() != inventoryv1.SnapshotState_SNAPSHOT_STATE_STAGING || !resumed.GetAcceptedAt().AsTime().Equal(begun.GetAcceptedAt().AsTime()) {
		t.Fatalf("resume changed receipt: %v %+v", err, resumed)
	}
	if _, err := f.put(t, manifest.GetSnapshotId(), 0, first, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := f.put(t, manifest.GetSnapshotId(), 1, second, 2); err != nil {
		t.Fatal(err)
	}
	committed, err := f.commit(t, manifest, 2)
	if err != nil || committed.GetState() != inventoryv1.SnapshotState_SNAPSHOT_STATE_COMMITTED || committed.GetPublishedSequence() != 1 {
		t.Fatalf("commit after resume: %v %+v", err, committed)
	}
}

func TestOfflineGapAdmissionDoesNotRequireSequenceRewind(t *testing.T) {
	f := newEnrolled(t, 0)
	stale := snapshotManifest(t, f.generation, 1, f.now.Add(-25*time.Hour), nil)
	if _, err := f.begin(t, stale, 1); connect.CodeOf(err) != connect.CodeFailedPrecondition || rpcReason(err) != "snapshot_expired" {
		t.Fatalf("stale unsent manifest: %v", err)
	}
	state, err := f.svc.GetSyncState(f.deviceCtx(), connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: 1}))
	if err != nil || state.Msg.GetPackageSequence() != 0 {
		t.Fatalf("rejected manifest consumed a sequence: %v %+v", err, state)
	}
	fresh := snapshotManifest(t, f.generation, 3, f.now, nil)
	begun, err := f.begin(t, fresh, 1)
	if err != nil || begun.GetPackageSequence() != 3 {
		t.Fatalf("gapped sequence was not admitted: %v %+v", err, begun)
	}
	committed, err := f.commit(t, fresh, 1)
	if err != nil || committed.GetPublishedSequence() != 3 {
		t.Fatalf("gapped snapshot did not publish: %v %+v", err, committed)
	}
	older := snapshotManifest(t, f.generation, 2, f.now, nil)
	if _, err := f.begin(t, older, 1); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("older sequence published: %v", err)
	}
	if got := publishedSequence(t, f); got != 3 {
		t.Fatalf("older begin changed published sequence to %d", got)
	}
}

func TestPackageFailurePreservesEmptySnapshot(t *testing.T) {
	f := newEnrolled(t, 0)
	manifest := snapshotManifest(t, f.generation, 1, f.now, nil)
	if _, err := f.begin(t, manifest, 1); err != nil {
		t.Fatal(err)
	}
	committed, err := f.commit(t, manifest, 1)
	if err != nil || committed.GetState() != inventoryv1.SnapshotState_SNAPSHOT_STATE_COMMITTED {
		t.Fatal(err)
	}
	f.now = f.now.Add(inventory.SnapshotAttemptInterval)
	if _, err := f.svc.ReportPackageAttempt(f.deviceCtx(), connect.NewRequest(&devicev1.ReportPackageAttemptRequest{
		EnrollmentGeneration: f.generation, SessionEpoch: 1, Sequence: 4,
		StartedAt: timestamppb.New(f.now), FinishedAt: timestamppb.New(f.now),
		Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE, Backend: "apt",
	})); err != nil {
		t.Fatal(err)
	}
	detail, err := f.svc.GetDevice(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	if detail.Msg.GetCurrentSnapshot().GetPackageCount() != 0 || !detail.Msg.GetCurrentSnapshot().GetPackagesAvailable() {
		t.Fatalf("empty snapshot was not preserved: %+v", detail.Msg.GetCurrentSnapshot())
	}
	if detail.Msg.GetPackageAttempt().GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE || detail.Msg.GetPackageAttempt().GetSequence() != 4 {
		t.Fatalf("failure did not become the latest attempt: %+v", detail.Msg.GetPackageAttempt())
	}
	if !detail.Msg.GetCurrentSnapshot().GetReceivedAt().AsTime().Equal(committed.GetAcceptedAt().AsTime()) {
		t.Fatal("failure refreshed snapshot receipt time")
	}
}

func TestUnavailableHostFieldDoesNotClearProjection(t *testing.T) {
	f := newEnrolled(t, 0)
	first := hostObservation(f.generation, 1, "alpha")
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(first)); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(inventory.SnapshotAttemptInterval)
	second := hostObservation(f.generation, 2, "ignored")
	second.Observation.Hostname = observed(inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE, "")
	if _, err := f.svc.ReportHostObservation(f.deviceCtx(), connect.NewRequest(second)); err != nil {
		t.Fatal(err)
	}
	detail, err := f.svc.GetDevice(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	if detail.Msg.GetDevice().GetHostname() != "alpha" {
		t.Fatalf("failed hostname cleared projection %q", detail.Msg.GetDevice().GetHostname())
	}
	host := detail.Msg.GetHost().GetObservation()
	if host.GetHostname().GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE || host.GetHostname().GetValue() != "" {
		t.Fatalf("detail did not retain unavailable hostname: %+v", host.GetHostname())
	}
	if host.GetHardwareSerial().GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE || host.GetHardwareSerial().GetValue() != "" {
		t.Fatal("unavailable serial was stored as a successful empty value")
	}
}

func TestPackagePageTokenFreezesSnapshot(t *testing.T) {
	f := newEnrolled(t, 0)
	prefix := make([]byte, 512)
	for i := range prefix {
		prefix[i] = 'a'
	}
	first := f.publishPackages(t, 1, string(prefix), "zzz")
	page, err := f.svc.ListDevicePackages(f.ownerCtx, connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: f.deviceID, PageSize: 1, NamePrefix: string(prefix)}))
	if err != nil {
		t.Fatal(err)
	}
	if page.Msg.GetPageToken() == "" || len(page.Msg.GetPageToken()) > 64 || page.Msg.GetPackages()[0].GetName() != string(prefix) {
		t.Fatalf("first page cursor: %+v", page.Msg)
	}
	expires := page.Msg.GetCursorExpiresAt().AsTime()
	f.now = f.now.Add(inventory.SnapshotAttemptInterval)
	f.publishPackages(t, 2, "other")
	revisited, err := f.svc.ListDevicePackages(f.ownerCtx, connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: f.deviceID, PageSize: 1, PageToken: page.Msg.GetPageToken()}))
	if err != nil {
		t.Fatal(err)
	}
	if revisited.Msg.GetSnapshotId() != first || revisited.Msg.GetPackages()[0].GetName() != string(prefix) || !revisited.Msg.GetCursorExpiresAt().AsTime().Equal(expires) {
		t.Fatalf("echoed token switched snapshot or extended expiry: %+v", revisited.Msg)
	}
	f.now = expires
	if _, err := f.svc.ListDevicePackages(f.ownerCtx, connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: f.deviceID, PageToken: page.Msg.GetPageToken()})); connect.CodeOf(err) != connect.CodeFailedPrecondition || rpcReason(err) != "page_expired" {
		t.Fatalf("expired cursor: %v", err)
	}
	latest, err := f.svc.ListDevicePackages(f.ownerCtx, connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: f.deviceID}))
	if err != nil || latest.Msg.GetPackages()[0].GetName() != "other" {
		t.Fatalf("latest snapshot: %v %+v", err, latest)
	}
}

func TestCleanupRetainsPinnedAndCurrentSnapshots(t *testing.T) {
	f := newEnrolled(t, 0)
	first := f.publishPackages(t, 1, "kept")
	page, err := f.svc.ListDevicePackages(f.ownerCtx, connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: f.deviceID}))
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(inventory.SnapshotAttemptInterval)
	f.publishPackages(t, 2, "current")
	f.now = f.now.Add(time.Minute)
	if err := f.svc.CleanupSnapshots(f.ctx); err != nil {
		t.Fatal(err)
	}
	revisited, err := f.svc.ListDevicePackages(f.ownerCtx, connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: f.deviceID, PageToken: page.Msg.GetPageToken()}))
	if err != nil || revisited.Msg.GetSnapshotId() != first {
		t.Fatalf("pinned snapshot was deleted or switched: %v %+v", err, revisited)
	}
	var current int
	if err := f.conn.QueryRow(f.ctx, `SELECT count(*) FROM snapshot_packages WHERE snapshot_id = (SELECT current_snapshot_id FROM enrollment_generations WHERE id = $1)`, f.principal.GenerationID).Scan(&current); err != nil || current != 1 {
		t.Fatalf("current snapshot bulk = %d (%v)", current, err)
	}
}

func TestReceiptExpiryRefusesWithoutRepublish(t *testing.T) {
	f := newEnrolled(t, 0)
	manifest := snapshotManifest(t, f.generation, 1, f.now, nil)
	if _, err := f.begin(t, manifest, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.commit(t, manifest, 1); err != nil {
		t.Fatal(err)
	}
	var seconds int64
	if err := f.conn.QueryRow(f.ctx, `SELECT EXTRACT(EPOCH FROM (receipt_expires_at - accepted_at))::bigint FROM package_snapshots WHERE id = $1`, manifest.GetSnapshotId()).Scan(&seconds); err != nil || time.Duration(seconds)*time.Second != inventory.SnapshotReceiptTTL {
		t.Fatalf("receipt lifetime = %s (%v)", time.Duration(seconds)*time.Second, err)
	}
	if _, err := f.conn.Exec(f.ctx, `UPDATE package_snapshots SET accepted_at = accepted_at - interval '2160 hours', open_until = open_until - interval '2160 hours', receipt_expires_at = receipt_expires_at - interval '2160 hours' WHERE id = $1`, manifest.GetSnapshotId()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.begin(t, manifest, 1); connect.CodeOf(err) != connect.CodeFailedPrecondition || rpcReason(err) != "snapshot_expired" {
		t.Fatalf("expired receipt republished: %v", err)
	}
	if got := publishedSequence(t, f); got != 1 {
		t.Fatalf("expired retry changed published sequence to %d", got)
	}
}

func TestInventoryBudgetAndOpenUpload(t *testing.T) {
	f := newEnrolled(t, core.MinInventoryBudget)
	if _, err := f.begin(t, declaredManifest(t, f.generation, 1, f.now, 80, core.MaxBatchBytes), 1); err != nil {
		t.Fatal(err)
	}
	secondKey := ed25519Key(t)
	_, _, _, enrolled := enrollDevice(t, f.ctx, f.svc, f.ownerCtx, secondKey)
	leaf := parseCertPEM(t, enrolled.Msg.GetCertificatePem())
	principal, err := f.svc.authenticateDeviceRequest(httptest.NewRequest(http.MethodPost, "/", nil), leaf)
	if err != nil {
		t.Fatal(err)
	}
	acquireTestSession(t, f.ctx, f.svc, principal, secondKey, 0)
	otherCtx := core.WithDevicePrincipal(f.ctx, principal)
	if _, err := f.svc.BeginPackageSnapshot(otherCtx, connect.NewRequest(&devicev1.BeginPackageSnapshotRequest{
		EnrollmentGeneration: enrolled.Msg.GetEnrollmentGeneration(), SessionEpoch: 1,
		Manifest: declaredManifest(t, enrolled.Msg.GetEnrollmentGeneration(), 1, f.now, 8, core.MaxBatchBytes),
	})); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("second device ignored deployment budget: %v", err)
	}
	f.now = f.now.Add(inventory.SnapshotAttemptInterval)
	if _, err := f.begin(t, snapshotManifest(t, f.generation, 2, f.now, nil), 1); connect.CodeOf(err) != connect.CodeFailedPrecondition || rpcReason(err) != "open_upload" {
		t.Fatalf("second open upload: %v", err)
	}
}

func (f *enrolledFixture) begin(t *testing.T, manifest *devicev1.PackageSnapshotManifest, epoch uint64) (*devicev1.BeginPackageSnapshotResponse, error) {
	t.Helper()
	resp, err := f.svc.BeginPackageSnapshot(f.deviceCtx(), connect.NewRequest(&devicev1.BeginPackageSnapshotRequest{
		EnrollmentGeneration: f.generation, SessionEpoch: epoch, Manifest: manifest,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (f *enrolledFixture) put(t *testing.T, snapshotID string, index uint32, batch []byte, epoch uint64) (*devicev1.PutPackageBatchResponse, error) {
	t.Helper()
	resp, err := f.svc.PutPackageBatch(f.deviceCtx(), connect.NewRequest(&devicev1.PutPackageBatchRequest{
		EnrollmentGeneration: f.generation, SessionEpoch: epoch, SnapshotId: snapshotID, BatchIndex: index, Batch: batch,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (f *enrolledFixture) commit(t *testing.T, manifest *devicev1.PackageSnapshotManifest, epoch uint64) (*devicev1.CommitPackageSnapshotResponse, error) {
	t.Helper()
	resp, err := f.svc.CommitPackageSnapshot(f.deviceCtx(), connect.NewRequest(&devicev1.CommitPackageSnapshotRequest{
		EnrollmentGeneration: f.generation, SessionEpoch: epoch, Manifest: manifest,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (f *enrolledFixture) publishPackages(t *testing.T, seq uint64, names ...string) string {
	t.Helper()
	pkgs := make([]*inventoryv1.Package, len(names))
	for i, name := range names {
		pkgs[i] = &inventoryv1.Package{Name: name, Version: "1", Architecture: "amd64", Manager: "apt"}
	}
	raw := packageBatch(t, pkgs...)
	manifest := snapshotManifest(t, f.generation, seq, f.now, [][]byte{raw})
	if _, err := f.begin(t, manifest, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.put(t, manifest.GetSnapshotId(), 0, raw, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.commit(t, manifest, 1); err != nil {
		t.Fatal(err)
	}
	return manifest.GetSnapshotId()
}

func publishedSequence(t *testing.T, f *enrolledFixture) int64 {
	t.Helper()
	var seq int64
	if err := f.conn.QueryRow(f.ctx, `SELECT published_sequence FROM devices WHERE id = $1`, f.principal.DeviceID).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	return seq
}

func packageBatch(t *testing.T, pkgs ...*inventoryv1.Package) []byte {
	t.Helper()
	raw, err := proto.Marshal(&inventoryv1.PackageBatch{Packages: pkgs})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func snapshotManifest(t *testing.T, generation string, seq uint64, when time.Time, batches [][]byte) *devicev1.PackageSnapshotManifest {
	t.Helper()
	descriptors := make([]*devicev1.PackageBatchDescriptor, len(batches))
	for i, batch := range batches {
		decoded := &inventoryv1.PackageBatch{}
		if err := proto.Unmarshal(batch, decoded); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(batch)
		descriptors[i] = &devicev1.PackageBatchDescriptor{Index: uint32(i), Sha256: sum[:], Count: uint32(len(decoded.GetPackages())), EncodedSize: uint32(len(batch))}
	}
	return &devicev1.PackageSnapshotManifest{
		SnapshotId: uuidV7At(when).String(), CreatedAt: timestamppb.New(when), EnrollmentGeneration: generation,
		Sequence: seq, StartedAt: timestamppb.New(when), FinishedAt: timestamppb.New(when), Backend: "apt", Batches: descriptors,
	}
}

func declaredManifest(t *testing.T, generation string, seq uint64, when time.Time, batches int, size uint32) *devicev1.PackageSnapshotManifest {
	t.Helper()
	descriptors := make([]*devicev1.PackageBatchDescriptor, batches)
	digest := sha256.Sum256([]byte("declared"))
	for i := range descriptors {
		descriptors[i] = &devicev1.PackageBatchDescriptor{Index: uint32(i), Sha256: digest[:], Count: 1, EncodedSize: size}
	}
	return &devicev1.PackageSnapshotManifest{
		SnapshotId: uuidV7At(when).String(), CreatedAt: timestamppb.New(when), EnrollmentGeneration: generation,
		Sequence: seq, StartedAt: timestamppb.New(when), FinishedAt: timestamppb.New(when), Backend: "apt", Batches: descriptors,
	}
}

func uuidV7At(when time.Time) uuid.UUID {
	id := uuid.New()
	ms := uint64(when.UnixMilli())
	id[0] = byte(ms >> 40)
	id[1] = byte(ms >> 32)
	id[2] = byte(ms >> 24)
	id[3] = byte(ms >> 16)
	id[4] = byte(ms >> 8)
	id[5] = byte(ms)
	id[6] = (id[6] & 0x0f) | 0x70
	id[8] = (id[8] & 0x3f) | 0x80
	return id
}
