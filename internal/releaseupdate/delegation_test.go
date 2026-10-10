package releaseupdate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	updatev1 "lindm/gen/lindm/update/v1"
)

func onlinePublisher(t *testing.T, fixture *repositoryFixture) *Publisher {
	t.Helper()
	cfg := fixture.publisher.cfg
	cfg.Signers.Root, cfg.Signers.Targets = nil, nil
	publisher, err := NewPublisher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return publisher
}

func TestOnlineCustodyCannotPublishOrReinterpretOfflineRelease(t *testing.T) {
	fixture := newRepositoryFixture(t)
	online := onlinePublisher(t, fixture)
	before := mustRead(t, filepath.Join(fixture.directory, "metadata/2.targets.json"))
	channel, err := online.SetRollout(context.Background(), "stable", true, 15)
	if err != nil {
		t.Fatal(err)
	}
	if !channel.GetPaused() || channel.GetEligiblePercentage() != 15 {
		t.Fatal("online rollout was not applied")
	}
	if !bytes.Equal(before, mustRead(t, filepath.Join(fixture.directory, "metadata/2.targets.json"))) {
		t.Fatal("online rollout changed offline targets")
	}
	if _, err = os.Stat(filepath.Join(fixture.directory, "metadata/3.targets.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("online rollout resigned top-level targets")
	}
	promotion := proto.CloneOf(fixture.channel)
	promotion.Ring = "canary"
	if err = online.Promote(context.Background(), promotion); err != nil {
		t.Fatal(err)
	}
	request := fixtureRequest()
	request.Ring = "canary"
	if _, err = fixture.client(t, "", nil).Select(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	promotion.Generation++
	if err = online.Publish(context.Background(), promotion, nil); err == nil {
		t.Fatal("online publisher acquired offline publication authority")
	}
	packageFile := filepath.Join(t.TempDir(), "replacement")
	mustWrite(t, packageFile, []byte("replacement native bytes"))
	if err = online.Publish(context.Background(), promotion, map[string]string{promotion.Artifacts[0].TargetPath: packageFile}); err == nil {
		t.Fatal("online publisher replaced offline package bytes")
	}
	for _, mutate := range []func(*updatev1.AgentUpdateArtifact){
		func(a *updatev1.AgentUpdateArtifact) { a.Version = "9.9.9" },
		func(a *updatev1.AgentUpdateArtifact) { a.NativeVersion = "9.9.9-1" },
		func(a *updatev1.AgentUpdateArtifact) { a.MinimumAgentVersion = "0.0.0" },
		func(a *updatev1.AgentUpdateArtifact) { a.MaximumAgentVersion = "9.9.9" },
		func(a *updatev1.AgentUpdateArtifact) { a.MaximumProtocolVersion = 99 },
		func(a *updatev1.AgentUpdateArtifact) { a.Architecture = "arm64" },
		func(a *updatev1.AgentUpdateArtifact) { a.SignatureTargetPath = a.TargetPath + ".sig" },
	} {
		changed := proto.CloneOf(promotion)
		mutate(changed.Artifacts[0])
		if err = online.Promote(context.Background(), changed); err == nil {
			t.Fatal("online signer changed complete offline artifact contract")
		}
	}
	root, err := fixture.publisher.root()
	if err != nil {
		t.Fatal(err)
	}
	current, err := fixture.publisher.current(root)
	if err != nil {
		t.Fatal(err)
	}
	if current.targets.Signed.Targets[fixture.channel.Artifacts[0].TargetPath].Custom == nil {
		t.Fatal("offline artifact protobuf contract missing")
	}
}

// Sign a malicious online generation directly with genuine role keys, bypassing
// publisher safety so rejection is proved at the root verifier trust boundary.
func publishMaliciousOnline(t *testing.T, fixture *repositoryFixture, current *publication) {
	t.Helper()
	next := current.version + 1
	current.rollout.Signed.Version = next
	current.rollout.Signatures = nil
	for _, signer := range fixture.publisher.cfg.Signers.Rollout {
		if _, err := current.rollout.Sign(signer); err != nil {
			t.Fatal(err)
		}
	}
	rolloutBytes, err := current.rollout.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	root, err := fixture.publisher.root()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := metadata.Snapshot(fixture.now.Add(time.Hour))
	snapshot.Signed.Version = next
	snapshot.Signed.Meta = map[string]*metadata.MetaFiles{"targets.json": metaInfo(current.targets.Signed.Version, current.targetBytes), "rollout.json": metaInfo(next, rolloutBytes)}
	snapshotBytes, err := signMetadata(root, metadata.SNAPSHOT, snapshot, fixture.publisher.cfg.Signers.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := metadata.Timestamp(fixture.now.Add(time.Hour))
	timestamp.Signed.Version = next
	timestamp.Signed.Meta = map[string]*metadata.MetaFiles{"snapshot.json": metaInfo(next, snapshotBytes)}
	timestampBytes, err := signMetadata(root, metadata.TIMESTAMP, timestamp, fixture.publisher.cfg.Signers.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(fixture.directory, fmt.Sprintf("metadata/%d.rollout.json", next)), rolloutBytes)
	mustWrite(t, filepath.Join(fixture.directory, fmt.Sprintf("metadata/%d.snapshot.json", next)), snapshotBytes)
	mustWrite(t, filepath.Join(fixture.directory, "metadata/timestamp.json"), timestampBytes)
}

func TestGenuineOnlineSignaturesCannotChangeArtifactAuthority(t *testing.T) {
	for _, attack := range []string{"version", "native_version", "agent_window", "protocol_window", "injected_package", "shadow_package", "native_signature"} {
		t.Run(attack, func(t *testing.T) {
			fixture := newRepositoryFixture(t)
			root, err := fixture.publisher.root()
			if err != nil {
				t.Fatal(err)
			}
			current, err := fixture.publisher.current(root)
			if err != nil {
				t.Fatal(err)
			}
			channel := proto.CloneOf(fixture.channel)
			channel.Generation++
			artifact := channel.Artifacts[0]
			switch attack {
			case "version":
				artifact.Version = "9.9.9"
			case "native_version":
				artifact.NativeVersion = "9.9.9-1"
			case "agent_window":
				artifact.MinimumAgentVersion = "0.0.0"
			case "protocol_window":
				artifact.MaximumProtocolVersion = 99
			case "injected_package":
				artifact.TargetPath = "packages/lindm-agent/injected.deb"
			case "native_signature":
				artifact.SignatureTargetPath = artifact.TargetPath + ".sig"
			}
			if attack == "injected_package" || attack == "shadow_package" || attack == "native_signature" {
				name := artifact.TargetPath
				if attack == "native_signature" {
					name = artifact.SignatureTargetPath
				}
				info, err := metadata.TargetFile().FromBytes(name, []byte("online malicious target"), "sha256")
				if err != nil {
					t.Fatal(err)
				}
				current.rollout.Signed.Targets[name] = info
			}
			data, err := protojson.Marshal(channel)
			if err != nil {
				t.Fatal(err)
			}
			info, err := metadata.TargetFile().FromBytes("channels/stable.json", data, "sha256")
			if err != nil {
				t.Fatal(err)
			}
			if err = fixture.publisher.immutable("targets/"+hashPath(info.Path, info.Hashes["sha256"]), data); err != nil {
				t.Fatal(err)
			}
			current.rollout.Signed.Targets[info.Path] = info
			publishMaliciousOnline(t, fixture, current)
			if _, err = fixture.client(t, "", nil).Select(context.Background(), fixtureRequest()); err == nil {
				t.Fatal("genuine online signature expanded offline authority")
			}
		})
	}
}

func TestDelegatedRollbackAndInterruptedRefreshPersist(t *testing.T) {
	fixture := newRepositoryFixture(t)
	stateDir := filepath.Join(t.TempDir(), "state")
	client := fixture.client(t, stateDir, nil)
	if _, err := client.Select(context.Background(), fixtureRequest()); err != nil {
		t.Fatal(err)
	}
	if _, err := onlinePublisher(t, fixture).SetRollout(context.Background(), "stable", false, 100); err != nil {
		t.Fatal(err)
	}
	fetch := DirectoryFetch(fixture.directory)
	interrupted := fixture.client(t, stateDir, func(ctx context.Context, name string, limit int64) ([]byte, error) {
		if strings.HasPrefix(name, "targets/channels/") {
			return nil, errors.New("channel stream interrupted")
		}
		return fetch(ctx, name, limit)
	})
	if _, err := interrupted.Select(context.Background(), fixtureRequest()); err == nil {
		t.Fatal("interrupted channel accepted")
	}
	state, err := interrupted.loadState()
	if err != nil {
		t.Fatal(err)
	}
	rollout, err := metadata.Targets().FromBytes(state.RolloutJson)
	if err != nil {
		t.Fatal(err)
	}
	if rollout.Signed.Version != 3 {
		t.Fatal("delegated high-water not durable before channel fetch")
	}
	root, err := fixture.publisher.root()
	if err != nil {
		t.Fatal(err)
	}
	current, err := fixture.publisher.current(root)
	if err != nil {
		t.Fatal(err)
	}
	oldBytes := mustRead(t, filepath.Join(fixture.directory, "metadata/2.rollout.json"))
	snapshot := metadata.Snapshot(fixture.now.Add(time.Hour))
	snapshot.Signed.Version = 4
	snapshot.Signed.Meta = map[string]*metadata.MetaFiles{"targets.json": metaInfo(current.targets.Signed.Version, current.targetBytes), "rollout.json": metaInfo(2, oldBytes)}
	snapshotBytes, err := signMetadata(root, metadata.SNAPSHOT, snapshot, fixture.publisher.cfg.Signers.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := metadata.Timestamp(fixture.now.Add(time.Hour))
	timestamp.Signed.Version = 4
	timestamp.Signed.Meta = map[string]*metadata.MetaFiles{"snapshot.json": metaInfo(4, snapshotBytes)}
	timestampBytes, err := signMetadata(root, metadata.TIMESTAMP, timestamp, fixture.publisher.cfg.Signers.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(fixture.directory, "metadata/4.snapshot.json"), snapshotBytes)
	mustWrite(t, filepath.Join(fixture.directory, "metadata/timestamp.json"), timestampBytes)
	if _, err = fixture.client(t, stateDir, nil).Select(context.Background(), fixtureRequest()); err == nil {
		t.Fatal("signed delegated rollback survived restart")
	}
}

func TestOnlineKeyLoaderRejectsOfflineExposure(t *testing.T) {
	offline := filepath.Join(t.TempDir(), "offline")
	if err := GenerateDevelopmentKeys(offline); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOnlineSigners(offline); err == nil {
		t.Fatal("online custody accepted offline private keys")
	}
	online := filepath.Join(t.TempDir(), "online")
	if err := os.Mkdir(online, 0700); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{rolloutRole, "snapshot", "timestamp"} {
		mustWrite(t, filepath.Join(online, role+".pem"), mustRead(t, filepath.Join(offline, role+".pem")))
	}
	keys, err := LoadOnlineSigners(online)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.Root) != 0 || len(keys.Targets) != 0 || len(keys.Rollout) != 1 {
		t.Fatal("online signer boundary wrong")
	}
	if err = os.Symlink(filepath.Join(offline, "targets.pem"), filepath.Join(online, "targets.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadOnlineSigners(online); err == nil {
		t.Fatal("offline symlink exposure accepted")
	}
}

func TestDelegatedFreezeMixAndSignatureRejection(t *testing.T) {
	for _, attack := range []string{"freeze", "mix", "signature"} {
		t.Run(attack, func(t *testing.T) {
			fixture := newRepositoryFixture(t)
			root, err := fixture.publisher.root()
			if err != nil {
				t.Fatal(err)
			}
			current, err := fixture.publisher.current(root)
			if err != nil {
				t.Fatal(err)
			}
			switch attack {
			case "freeze":
				current.rollout.Signed.Expires = time.Now().Add(-time.Hour)
			case "signature":
				fixture.publisher.cfg.Signers.Rollout = fixtureSigners(t).Rollout
			}
			publishMaliciousOnline(t, fixture, current)
			fetch := DirectoryFetch(fixture.directory)
			client := fixture.client(t, "", func(ctx context.Context, name string, limit int64) ([]byte, error) {
				if attack == "mix" && name == "metadata/3.rollout.json" {
					return fetch(ctx, "metadata/2.rollout.json", limit)
				}
				return fetch(ctx, name, limit)
			})
			if _, err = client.Select(context.Background(), fixtureRequest()); err == nil {
				t.Fatal("delegated attack accepted")
			}
		})
	}
}

func TestRolloutCustodyCannotReuseTopLevelKeys(t *testing.T) {
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		t.Run(role, func(t *testing.T) {
			keys := fixtureSigners(t)
			keys.Rollout = keys.roles()[role]
			if _, err := CreateRepository(context.Background(), PublisherConfig{Directory: filepath.Join(t.TempDir(), "repository"), Signers: keys}); err == nil {
				t.Fatal("rollout shared a top-level signing identity")
			}
		})
	}
}

func TestOfflineTargetsCannotShadowDelegatedChannel(t *testing.T) {
	fixture := newRepositoryFixture(t)
	root, err := fixture.publisher.root()
	if err != nil {
		t.Fatal(err)
	}
	current, err := fixture.publisher.current(root)
	if err != nil {
		t.Fatal(err)
	}
	current.targets.Signed.Targets["channels/stable.json"] = current.rollout.Signed.Targets["channels/stable.json"]
	if err = validateRolloutDelegation(root, current.targets); err == nil {
		t.Fatal("offline channel shadow accepted")
	}
}

func TestRolloutValidityUsesOneClockObservation(t *testing.T) {
	fixture := newRepositoryFixture(t)
	online := onlinePublisher(t, fixture)
	now := fixture.now
	online.cfg.Now = func() time.Time { now = now.Add(time.Millisecond); return now }
	channel, err := online.SetRollout(context.Background(), "stable", false, 100)
	if err != nil {
		t.Fatal(err)
	}
	if channel.GetExpiresAt().AsTime().Sub(channel.GetIssuedAt().AsTime()) != 7*24*time.Hour {
		t.Fatal("advancing clock expanded signed catalog validity")
	}
}
