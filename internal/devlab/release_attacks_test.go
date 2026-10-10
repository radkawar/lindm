package devlab

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	updatev1 "lindm/gen/lindm/update/v1"
	"lindm/internal/releaseupdate"
)

func TestReleaseAttacksUseAuthenticDistinctRoleGenerations(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	custody := filepath.Join(root, "release-custody")
	if err := releaseupdate.GenerateDevelopmentKeys(custody); err != nil {
		t.Fatal(err)
	}
	signers, err := releaseupdate.LoadRoleSigners(custody, true)
	if err != nil {
		t.Fatal(err)
	}
	repository := filepath.Join(root, "release-repository")
	publisher, err := releaseupdate.CreateRepository(t.Context(), releaseupdate.PublisherConfig{Directory: repository, Signers: signers})
	if err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(root, "payload.deb")
	// Packages exceed the separate one-MiB development configuration-file cap.
	payloadBytes := bytes.Repeat([]byte("owned fixture bytes, not a claimed native package"), 1<<16)
	if err := os.WriteFile(payload, payloadBytes, 0600); err != nil {
		t.Fatal(err)
	}
	const target = "packages/lindm-agent/amd64/lindm-agent_0.2.0_amd64.deb"
	now := time.Now().UTC().Truncate(time.Second)
	channel := &updatev1.AgentUpdateChannel{Ring: "canary", Paused: true, EligiblePercentage: 100, Generation: 1, IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Hour)), Artifacts: []*updatev1.AgentUpdateArtifact{{Version: "0.2.0", Architecture: "amd64", PackageFormat: "deb", TargetPath: target, MinimumAgentVersion: "0.0.0", MaximumAgentVersion: "1.0.0", MinimumProtocolVersion: 1, MaximumProtocolVersion: 1, NativeVersion: "0.2.0"}}}
	if err := publisher.Publish(t.Context(), channel, map[string]string{target: payload}); err != nil {
		t.Fatal(err)
	}
	fixture := &AuthorityFixture{directory: root}
	old, err := fixture.CaptureReleaseMetadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.SetRollout(t.Context(), "canary", false, 0); err != nil {
		t.Fatal(err)
	}
	current, err := fixture.CaptureReleaseMetadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if current.TargetsVersion != old.TargetsVersion || current.RolloutVersion <= old.RolloutVersion {
		t.Fatal("rollout must advance delegated authority without re-signing offline artifact authority")
	}
	restore, err := fixture.ReplayReleaseTimestamp(t.Context(), old)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := fixture.CaptureReleaseMetadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replayed.timestamp, old.timestamp) {
		t.Fatal("rollback fixture did not serve authentic old signed bytes")
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	if err := restore(); err != nil {
		t.Fatal("restoration must be idempotent:", err)
	}
	restore, err = fixture.MixReleaseRollout(t.Context(), old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.CaptureReleaseMetadata(t.Context()); err == nil {
		t.Fatal("mixed delegated bytes still satisfied snapshot hash")
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	restored, err := fixture.CaptureReleaseMetadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.rollout, current.rollout) || !bytes.Equal(restored.timestamp, current.timestamp) {
		t.Fatal("mix restoration changed valid public generation")
	}
	restore, err = fixture.TamperReleaseTarget(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payloadBytes)
	targetFile := filepath.Join(repository, "targets", filepath.Dir(target), fmt.Sprintf("%x.%s", digest, filepath.Base(target)))
	tampered, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(tampered) != len(payloadBytes) || tampered[0] != payloadBytes[0]^1 || !bytes.Equal(tampered[1:], payloadBytes[1:]) {
		t.Fatal("tamper fixture must alter exactly one byte of the owned large target")
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	restoredTarget, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restoredTarget, payloadBytes) {
		t.Fatal("target restoration did not recover original signed bytes")
	}
	if _, err := fixture.BeginReleaseFreeze(t.Context(), 10*time.Second); err != nil {
		t.Fatal(err)
	}
	frozen, err := fixture.CaptureReleaseMetadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	timestamp, err := metadata.Timestamp().FromBytes(frozen.timestamp)
	if err != nil {
		t.Fatal(err)
	}
	remaining := time.Until(timestamp.Signed.Expires)
	if frozen.TimestampVersion <= current.TimestampVersion || remaining <= 0 || remaining > 10*time.Second {
		t.Fatal("freeze fixture must publish newer authentic briefly valid timestamp")
	}
}
