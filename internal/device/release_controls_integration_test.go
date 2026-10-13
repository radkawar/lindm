//go:build integration

package device

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	releasemanagementv1 "lindm/gen/lindm/releasemanagement/v1"
	updatev1 "lindm/gen/lindm/update/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/releaseupdate"
)

// Fail at the actual timestamp signing boundary after the audited intent commits;
// successful calls still use the real cryptographic signer and repository.
type releaseFailingSigner struct {
	signature.Signer
	unavailable bool
}

func (s *releaseFailingSigner) SignMessage(message io.Reader, options ...signature.SignOption) ([]byte, error) {
	if s.unavailable {
		return nil, errors.New("test timestamp custody unavailable")
	}
	return s.Signer.SignMessage(message, options...)
}

func registerTestRelease(t *testing.T, f *enrolledFixture, minor uint32) *releasemanagementv1.RegisterReleaseSeriesRequest {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	req := &releasemanagementv1.RegisterReleaseSeriesRequest{RequestId: uuid.NewString(), Reason: "Admit tested release series", Series: &releasemanagementv1.ReleaseSeries{Major: 1, Minor: minor, ReleasedAt: timestamppb.New(now.Add(-time.Hour)), SupportUntil: timestamppb.New(now.Add(91 * 24 * time.Hour)), MinimumProtocol: 1, MaximumProtocol: 1}}
	if _, err := f.svc.RegisterReleaseSeries(f.ownerCtx, connect.NewRequest(req)); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestReleasePolicyPersistsAndFencesUnknownSession(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newEnrolled(t, 0)
	f.svc.RequireCompatibility = true
	f.svc.ServerRelease = "1.3.0"
	f.svc.ServerProtocol = 1
	registered := registerTestRelease(t, f, 3)
	if _, err := f.svc.RegisterReleaseSeries(f.ownerCtx, connect.NewRequest(registered)); err != nil {
		t.Fatal(err)
	}
	changed := proto.CloneOf(registered)
	changed.Series.SupportUntil = timestamppb.New(time.Now().Add(100 * 24 * time.Hour))
	if _, err := f.svc.RegisterReleaseSeries(f.ownerCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("changed receipt accepted: %v", err)
	}
	changed.RequestId = uuid.NewString()
	changed.Series.ReleasedAt = timestamppb.New(registered.Series.ReleasedAt.AsTime().Add(-time.Hour))
	if _, err := f.svc.RegisterReleaseSeries(f.ownerCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("history rewrite accepted: %v", err)
	}
	denied := func(epoch uint64) {
		t.Helper()
		if _, err := f.svc.GetResourceWork(f.deviceCtx(), connect.NewRequest(&devicev1.GetResourceWorkRequest{SessionEpoch: epoch})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Fatalf("unsupported session got executable work: %v", err)
		}
	}
	denied(1)
	// The same unsupported session still synchronizes and can fetch public updates.
	if _, err := f.svc.GetSyncState(f.deviceCtx(), connect.NewRequest(&devicev1.GetSyncStateRequest{SessionEpoch: 1})); err != nil {
		t.Fatal(err)
	}
	claim := &agentv1.SessionAcquisition{DeploymentId: f.svc.DeploymentID.String(), DeviceId: f.deviceID, EnrollmentGeneration: f.generation, RequestId: uuid.NewString(), PredecessorEpoch: 1, Incarnation: uuid.NewString(), BootId: uuid.NewString(), InstallationId: f.deviceID, AgentRelease: "1.3.7", AgentProtocolVersion: 1}
	proof, err := f.svc.Authority.Sign(f.ctx, claim, f.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AcquireSession(f.deviceCtx(), connect.NewRequest(&devicev1.AcquireSessionRequest{AuthorityProof: proof})); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.RequireReleaseCompatibility(f.ctx, devicedb.New(f.svc.Pool), f.principal.GenerationID, 2); err != nil {
		t.Fatalf("signed supported claim denied: %v", err)
	}
	if _, err := f.svc.GetResourceWork(f.deviceCtx(), connect.NewRequest(&devicev1.GetResourceWorkRequest{SessionEpoch: 2})); err != nil {
		t.Fatalf("supported session dispatch denied: %v", err)
	}
	report, err := devicedb.New(f.svc.Pool).GetDeviceReleaseReport(f.ctx, f.principal.GenerationID)
	if err != nil || report.AgentRelease != "1.3.7" || report.ProtocolVersion != 1 || report.SessionEpoch != 2 {
		t.Fatalf("signed report not persisted: %+v %v", report, err)
	}
	if err := f.svc.RequireReleaseCompatibility(f.ctx, devicedb.New(f.svc.Pool), f.principal.GenerationID, 1); !errors.Is(err, core.ErrSessionFenced) {
		t.Fatalf("old epoch admitted: %v", err)
	}
	// Permission is separate from execution-root custody and requires global scope.
	actor, _ := identity.PrincipalFromContext(f.ownerCtx)
	actor.Bindings = nil
	actor.Role = identity.RoleAuditor
	if _, err := f.svc.GetCompatibility(identity.WithPrincipal(f.ctx, actor), connect.NewRequest(&releasemanagementv1.GetCompatibilityRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("missing release permission: %v", err)
	}
	var audits int
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE action = 'release.series.register'").Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("release history audit/idempotency: %d %v", audits, err)
	}
}

func TestReleasePromotionAnnouncesRetirementForNinetyDays(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newEnrolled(t, 0)
	now := time.Now().UTC().Truncate(time.Microsecond)
	q := devicedb.New(f.svc.Pool)
	for minor := int32(1); minor <= 3; minor++ {
		if err := q.PutReleasedAgentSeries(f.ctx, devicedb.PutReleasedAgentSeriesParams{Major: 1, Minor: minor, ReleasedAt: core.Timestamptz(now.Add(-200 * 24 * time.Hour)), SupportUntil: core.Timestamptz(now.Add(-100 * 24 * time.Hour)), MinimumProtocol: 1, MaximumProtocol: 1}); err != nil {
			t.Fatal(err)
		}
	}
	registerTestRelease(t, f, 4)
	rows, err := q.ListReleasedAgentSeries(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 || rows[3].SupportUntil.Time.Before(now.Add(90*24*time.Hour)) {
		t.Fatalf("previous third series lost notice: %+v", rows)
	}
	if !core.ReleaseSupported(rows, "1.1.1", 1, "1.4.0", 1, now.Add(89*24*time.Hour)) {
		t.Fatal("previous third prematurely unsupported")
	}
}

func TestRolloutPendingPublicationResumesAndAudits(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newEnrolled(t, 0)
	directory, custody := t.TempDir(), t.TempDir()
	for _, path := range []string{directory, custody} {
		if err := os.Chmod(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := releaseupdate.GenerateDevelopmentKeys(custody); err != nil {
		t.Fatal(err)
	}
	signers, err := releaseupdate.LoadRoleSigners(custody, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg := releaseupdate.PublisherConfig{Directory: directory, Signers: signers, Now: time.Now}
	publisher, err := releaseupdate.CreateRepository(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(t.TempDir(), "agent.deb")
	if err := os.WriteFile(artifact, []byte("opaque authenticated target; not native install evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	target := "packages/lindm-agent/1.3.0/amd64.deb"
	now := time.Now().UTC()
	channel := &updatev1.AgentUpdateChannel{Ring: "canary", Generation: 1, EligiblePercentage: 100, IssuedAt: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(now.Add(time.Hour)), Artifacts: []*updatev1.AgentUpdateArtifact{{Version: "1.3.0", NativeVersion: "1.3.0-1", Architecture: "amd64", PackageFormat: "deb", TargetPath: target, MinimumAgentVersion: "1.0.0", MaximumAgentVersion: "1.3.0", MinimumProtocolVersion: 1, MaximumProtocolVersion: 1}}}
	if err := publisher.Publish(f.ctx, channel, map[string]string{target: artifact}); err != nil {
		t.Fatal(err)
	}
	// Management receives only online custody, never the offline package signer.
	cfg.Signers.Root = nil
	cfg.Signers.Targets = nil
	timestampSigner := &releaseFailingSigner{Signer: cfg.Signers.Timestamp[0], unavailable: true}
	cfg.Signers.Timestamp = []signature.Signer{timestampSigner}
	f.svc.ReleasePublisher, err = releaseupdate.NewPublisher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	request := &releasemanagementv1.SetRolloutRequest{RequestId: uuid.NewString(), Ring: "canary", ExpectedGeneration: 1, Paused: true, EligiblePercentage: 25, Reason: "Pause actual signed rollout"}
	// Fail timestamp signing, after the durable intent/audit commit.
	if _, err := f.svc.SetRollout(f.ownerCtx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("publication failure hidden: %v", err)
	}
	view, err := f.svc.GetRollout(f.ownerCtx, connect.NewRequest(&releasemanagementv1.GetRolloutRequest{Ring: "canary"}))
	if err != nil {
		t.Fatal(err)
	}
	if view.Msg.GetPendingRequestId() != request.RequestId || view.Msg.GetChannel().GetPaused() {
		t.Fatal("intent falsely reported as publication")
	}
	timestampSigner.unavailable = false
	// Simulate process replacement and publication completed before DB acknowledgment.
	f.svc.ReleasePublisher, err = releaseupdate.NewPublisher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ReleasePublisher.SetRolloutRequest(f.ctx, "canary", true, 25, 1, request.RequestId); err != nil {
		t.Fatal(err)
	}
	result, err := f.svc.SetRollout(f.ownerCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Msg.GetChannel().GetPaused() || result.Msg.GetChannel().GetGeneration() != 2 || result.Msg.GetChannel().GetEligiblePercentage() != 25 {
		t.Fatal("signed publication not reconciled")
	}
	replay, err := f.svc.SetRollout(f.ownerCtx, connect.NewRequest(request))
	if err != nil || !proto.Equal(result.Msg, replay.Msg) {
		t.Fatalf("exact durable receipt failed: %v", err)
	}
	changed := proto.CloneOf(request)
	changed.Paused = false
	if _, err := f.svc.SetRollout(f.ownerCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("changed rollout replay accepted: %v", err)
	}
	if _, err := devicedb.New(f.svc.Pool).GetPendingReleaseRollout(f.ctx, "canary"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("published rollout left pending: %v", err)
	}
	var requested, published int
	if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FILTER (WHERE action='release.rollout.request'), count(*) FILTER (WHERE action='release.rollout.published') FROM audit_events").Scan(&requested, &published); err != nil || requested != 1 || published != 1 {
		t.Fatalf("audit publication truth: %d %d %v", requested, published, err)
	}
}

func TestUnsupportedReleasePreservesIssuedServiceRecovery(t *testing.T) {
	parallelDeviceIntegration(t)
	f := newDispatchFixture(t)
	f.assign(t, nil)
	work := f.work(t)
	request, envelope := f.start(t, work)
	f.service.RequireCompatibility = true
	f.service.ServerRelease = "1.3.0"
	f.service.ServerProtocol = 1
	// The legacy fixture has no reported release. It cannot obtain fresh plans,
	// but already-issued authority and its result nonce remain recoverable.
	recovered := f.work(t)
	if recovered.GetActionId() != work.GetActionId() || len(recovered.GetResultNonce()) == 0 {
		t.Fatal("release gate suppressed issued action recovery")
	}
	response, err := f.service.AuthorizeResourceStart(f.deviceCtx, connect.NewRequest(request))
	if err != nil || !bytes.Equal(response.Msg.GetStartGrantEnvelope(), envelope) {
		t.Fatalf("release gate suppressed exact start receipt: %v", err)
	}
}
