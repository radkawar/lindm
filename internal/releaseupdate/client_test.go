// SPDX-License-Identifier: Apache-2.0

package releaseupdate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestVerifiedStreamingTargetBoundary(t *testing.T) {
	f := newRepositoryFixture(t)
	client := f.client(t, "", nil)
	selection, err := client.Select(context.Background(), fixtureRequest())
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "private", "agent.deb")
	// Writable transport hints cannot replace the signed descriptor held by Stage.
	selection.Length = 1
	selection.SHA256 = strings.Repeat("0", 64)
	selection.TargetPath = "targets/attacker.deb"
	if !selection.Deadline().Equal(f.now.Add(24 * time.Hour)) {
		t.Fatal("stream deadline is not the immutable earliest metadata expiry")
	}
	if err = client.Stage(context.Background(), selection, bytes.NewReader(f.payload), destination); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, destination); !bytes.Equal(got, f.payload) {
		t.Fatal("verified bytes changed")
	}
	for _, payload := range [][]byte{append(bytes.Clone(f.payload), 0), f.payload[:len(f.payload)-1], bytes.Repeat([]byte("x"), len(f.payload))} {
		if err = client.Stage(context.Background(), selection, bytes.NewReader(payload), destination); err == nil {
			t.Fatal("tampered payload accepted")
		}
		if got := mustRead(t, destination); !bytes.Equal(got, f.payload) {
			t.Fatal("failed target replaced previous verified file")
		}
	}
	other := f.client(t, "", nil)
	if err = other.Stage(context.Background(), selection, bytes.NewReader(f.payload), destination); err == nil {
		t.Fatal("selection transplanted between clients")
	}
	if err = client.Stage(context.Background(), &Selection{Length: int64(len(f.payload))}, bytes.NewReader(f.payload), destination); err == nil {
		t.Fatal("forged selection accepted")
	}
}

func TestSignedMetadataAttacks(t *testing.T) {
	for _, attack := range []string{"signature", "freeze", "snapshot_mix", "targets_mix", "oversize", "missing_snapshot", "null_target", "catalog_tamper"} {
		t.Run(attack, func(t *testing.T) {
			f := newRepositoryFixture(t)
			fetch := DirectoryFetch(f.directory)
			timestampBytes := mustRead(t, filepath.Join(f.directory, "metadata/timestamp.json"))
			timestamp, err := metadata.Timestamp().FromBytes(timestampBytes)
			if err != nil {
				t.Fatal(err)
			}
			switch attack {
			case "signature":
				timestamp.Signatures[0].Signature[0] ^= 0xff
			case "freeze":
				timestamp.Signed.Expires = time.Now().Add(-time.Hour)
				timestamp.Signatures = nil
				if _, err = timestamp.Sign(f.publisher.cfg.Signers.Timestamp[0]); err != nil {
					t.Fatal(err)
				}
			case "missing_snapshot":
				timestamp.Signed.Meta["snapshot.json"] = nil
			}
			modified, err := timestamp.ToBytes(false)
			if err != nil {
				t.Fatal(err)
			}
			client := f.client(t, "", func(ctx context.Context, name string, limit int64) ([]byte, error) {
				switch {
				case name == "metadata/timestamp.json" && (attack == "signature" || attack == "freeze" || attack == "missing_snapshot"):
					return modified, nil
				case name == "metadata/timestamp.json" && attack == "oversize":
					return make([]byte, MaxMetadataBytes+1), nil
				case strings.HasSuffix(name, ".snapshot.json") && attack == "snapshot_mix":
					return fetch(ctx, "metadata/1.snapshot.json", limit)
				case strings.HasSuffix(name, ".targets.json") && attack == "targets_mix":
					return fetch(ctx, "metadata/1.targets.json", limit)
				case strings.HasSuffix(name, ".targets.json") && attack == "null_target":
					return []byte(`{"signed":{"_type":"targets","version":2,"expires":"2099-01-01T00:00:00Z","targets":{"packages/lindm-agent/bad.deb":null}},"signatures":[]}`), nil
				case strings.HasPrefix(name, "targets/channels/") && attack == "catalog_tamper":
					data, err := fetch(ctx, name, limit)
					if err != nil {
						return nil, err
					}
					data[len(data)/2] ^= 1
					return data, nil
				default:
					return fetch(ctx, name, limit)
				}
			})
			if _, err = client.Select(context.Background(), fixtureRequest()); err == nil {
				t.Fatal("attack accepted")
			}
		})
	}
}

func TestTimestampRollbackSurvivesRestartAndFailedRefresh(t *testing.T) {
	f := newRepositoryFixture(t)
	state := filepath.Join(t.TempDir(), "state")
	old := mustRead(t, filepath.Join(f.directory, "metadata/timestamp.json"))
	client := f.client(t, state, nil)
	if _, err := client.Select(context.Background(), fixtureRequest()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.publisher.SetRollout(context.Background(), "stable", false, 99); err != nil {
		t.Fatal(err)
	}
	fetch := DirectoryFetch(f.directory)
	interrupted := f.client(t, state, func(ctx context.Context, name string, limit int64) ([]byte, error) {
		if strings.HasSuffix(name, ".snapshot.json") {
			return nil, errors.New("transport interrupted after timestamp")
		}
		return fetch(ctx, name, limit)
	})
	if _, err := interrupted.Select(context.Background(), fixtureRequest()); err == nil {
		t.Fatal("interrupted refresh succeeded")
	}
	// Inspect the checkpoint at the actual boundary, then start a new verifier.
	checkpoint, err := interrupted.loadState()
	if err != nil {
		t.Fatal(err)
	}
	high, err := metadata.Timestamp().FromBytes(checkpoint.TimestampJson)
	if err != nil {
		t.Fatal(err)
	}
	if high.Signed.Version != 3 {
		t.Fatalf("timestamp high-water = %d, want 3", high.Signed.Version)
	}
	restarted := f.client(t, state, func(ctx context.Context, name string, limit int64) ([]byte, error) {
		if name == "metadata/timestamp.json" {
			return old, nil
		}
		return fetch(ctx, name, limit)
	})
	if _, err = restarted.Select(context.Background(), fixtureRequest()); err == nil {
		t.Fatal("rollback after failed refresh/restart accepted")
	}
}

func TestCheckpointPrecedesNextUntrustedRead(t *testing.T) {
	f := newRepositoryFixture(t)
	stateDir := filepath.Join(t.TempDir(), "state")
	fetch := DirectoryFetch(f.directory)
	var client *Client
	sawSnapshot := false
	client = f.client(t, stateDir, func(ctx context.Context, name string, limit int64) ([]byte, error) {
		if strings.HasSuffix(name, ".snapshot.json") {
			sawSnapshot = true
			state, err := client.loadState()
			if err != nil {
				return nil, err
			}
			timestamp, err := metadata.Timestamp().FromBytes(state.TimestampJson)
			if err != nil {
				return nil, err
			}
			if timestamp.Signed.Version != 2 {
				return nil, fmt.Errorf("timestamp not durable before snapshot transport")
			}
		}
		return fetch(ctx, name, limit)
	})
	if _, err := client.Select(context.Background(), fixtureRequest()); err != nil {
		t.Fatal(err)
	}
	if !sawSnapshot {
		t.Fatal("snapshot transfer did not execute")
	}
}

func TestRootRotationAndRollback(t *testing.T) {
	f := newRepositoryFixture(t)
	state := filepath.Join(t.TempDir(), "state")
	client := f.client(t, state, nil)
	if _, err := client.Select(context.Background(), fixtureRequest()); err != nil {
		t.Fatal(err)
	}
	next := fixtureSigners(t)
	if err := f.publisher.RotateRoot(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	restarted := f.client(t, state, nil)
	if _, err := restarted.Select(context.Background(), fixtureRequest()); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := restarted.loadState()
	if err != nil {
		t.Fatal(err)
	}
	root, err := metadata.Root().FromBytes(checkpoint.RootJson)
	if err != nil {
		t.Fatal(err)
	}
	if root.Signed.Version != 2 {
		t.Fatalf("root rotation version %d", root.Signed.Version)
	}
	fetch := DirectoryFetch(f.directory)
	rollback := f.client(t, state, func(ctx context.Context, name string, limit int64) ([]byte, error) {
		if name == "metadata/3.root.json" {
			return f.root, nil
		}
		return fetch(ctx, name, limit)
	})
	if _, err = rollback.Select(context.Background(), fixtureRequest()); err == nil {
		t.Fatal("old root accepted as next root")
	}
	foreign := fixtureSigners(t)
	f.publisher.cfg.Signers.Root = foreign.Root
	if err = f.publisher.RotateRoot(context.Background(), fixtureSigners(t)); err == nil {
		t.Fatal("rotation without predecessor quorum accepted")
	}
}

func TestChannelBindingStrictJSONAndSelectionPolicy(t *testing.T) {
	f := newRepositoryFixture(t)
	for _, change := range []func(*SelectionRequest){func(r *SelectionRequest) { r.CurrentVersion = "1.2.3" }, func(r *SelectionRequest) { r.Architecture = "arm64" }, func(r *SelectionRequest) { r.ProtocolVersion = 2 }, func(r *SelectionRequest) { r.CurrentVersion = "0.9.0" }} {
		request := fixtureRequest()
		change(&request)
		if _, err := f.client(t, "", nil).Select(context.Background(), request); !errors.Is(err, ErrNoUpdate) {
			t.Fatalf("policy result = %v", err)
		}
	}
	if _, err := f.publisher.SetRollout(context.Background(), "stable", true, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := f.client(t, "", nil).Select(context.Background(), fixtureRequest()); !errors.Is(err, ErrNoUpdate) {
		t.Fatalf("paused channel result = %v", err)
	}
	raw, err := protojson.Marshal(f.channel)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw[:len(raw)-1], []byte(`,"untrustedCommand":"sh"}`)...)
	if _, err = decodeChannel(f.publisher.validator, raw, f.now); err == nil {
		t.Fatal("unknown catalog field accepted")
	}
	// Independent SHA-256 vectors pin domain separation, ring/device binding,
	// byte order, and threshold boundaries instead of comparing a call to itself.
	for _, cohort := range []struct {
		ring    string
		buckets []uint32
	}{
		{ring: "stable", buckets: []uint32{43, 32, 52, 43, 83, 91}},
		{ring: "canary", buckets: []uint32{6, 8, 3, 33, 72, 13}},
	} {
		for i, bucket := range cohort.buckets {
			id := fmt.Sprintf("device-%d", i)
			for percentage := range uint32(101) {
				if got, want := eligible(id, cohort.ring, percentage), percentage > bucket; got != want {
					t.Fatalf("cohort %s/%s at %d%%: got %t, want %t", cohort.ring, id, percentage, got, want)
				}
			}
		}
	}
}

func TestChannelReplayAndBindingAreRejectedWithValidTUFSignatures(t *testing.T) {
	for _, attack := range []string{"rollback", "equivocation", "ring"} {
		t.Run(attack, func(t *testing.T) {
			f := newRepositoryFixture(t)
			state := filepath.Join(t.TempDir(), "state")
			if _, err := f.publisher.SetRollout(context.Background(), "stable", false, 100); err != nil {
				t.Fatal(err)
			}
			client := f.client(t, state, nil)
			if _, err := client.Select(context.Background(), fixtureRequest()); err != nil {
				t.Fatal(err)
			}
			root, err := f.publisher.root()
			if err != nil {
				t.Fatal(err)
			}
			current, err := f.publisher.current(root)
			if err != nil {
				t.Fatal(err)
			}
			channel := proto.CloneOf(f.channel)
			switch attack {
			case "rollback":
				channel.Generation = 1
			case "equivocation":
				channel.Generation = 2
				channel.Paused = true
			case "ring":
				channel.Generation = 3
				channel.Ring = "canary"
			}
			data, err := protojson.Marshal(channel)
			if err != nil {
				t.Fatal(err)
			}
			info, err := metadata.TargetFile().FromBytes("channels/stable.json", data, "sha256")
			if err != nil {
				t.Fatal(err)
			}
			if err = f.publisher.immutable("targets/"+hashPath("channels/stable.json", info.Hashes["sha256"]), data); err != nil {
				t.Fatal(err)
			}
			current.rollout.Signed.Targets["channels/stable.json"] = info
			if err = f.publisher.commit(context.Background(), root, current, false); err != nil {
				t.Fatal(err)
			}
			if _, err = f.client(t, state, nil).Select(context.Background(), fixtureRequest()); err == nil {
				t.Fatal("signed invalid catalog accepted")
			}
		})
	}
}

func TestClockAndBootstrapCheckpointBinding(t *testing.T) {
	f := newRepositoryFixture(t)
	state := filepath.Join(t.TempDir(), "state")
	client := f.client(t, state, nil)
	if _, err := client.Select(context.Background(), fixtureRequest()); err != nil {
		t.Fatal(err)
	}
	client.cfg.Now = func() time.Time { return f.now }
	if _, err := client.Select(context.Background(), fixtureRequest()); err == nil {
		t.Fatal("clock rollback accepted")
	}
	other := newRepositoryFixture(t)
	foreign := other.client(t, state, nil)
	if _, err := foreign.Select(context.Background(), fixtureRequest()); err == nil {
		t.Fatal("checkpoint rebound to different bootstrap")
	}
}

func TestStageContextCancellationRetainsPreviousFile(t *testing.T) {
	f := newRepositoryFixture(t)
	client := f.client(t, "", nil)
	selection, err := client.Select(context.Background(), fixtureRequest())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "stage")
	if err = os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "package.deb")
	mustWrite(t, destination, []byte("previous"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = client.Stage(ctx, selection, io.NopCloser(bytes.NewReader(f.payload)), destination); err == nil {
		t.Fatal("cancelled stream published")
	}
	if string(mustRead(t, destination)) != "previous" {
		t.Fatal("cancellation replaced target")
	}
}

func TestMissingCheckpointCannotResetRollbackState(t *testing.T) {
	for _, removed := range []string{"state.pb", "initialized"} {
		t.Run(removed, func(t *testing.T) {
			f := newRepositoryFixture(t)
			directory := filepath.Join(t.TempDir(), "state")
			client := f.client(t, directory, nil)
			if _, err := client.Select(context.Background(), fixtureRequest()); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(directory, removed)); err != nil {
				t.Fatal(err)
			}
			restarted := f.client(t, directory, func(context.Context, string, int64) ([]byte, error) {
				t.Fatal("network contacted after checkpoint loss")
				return nil, ErrNotFound
			})
			if _, err := restarted.Select(context.Background(), fixtureRequest()); err == nil {
				t.Fatal("missing protected state reset trust")
			}
		})
	}
}

func TestValidlySignedSnapshotRollback(t *testing.T) {
	f := newRepositoryFixture(t)
	directory := filepath.Join(t.TempDir(), "state")
	client := f.client(t, directory, nil)
	if _, err := client.Select(context.Background(), fixtureRequest()); err != nil {
		t.Fatal(err)
	}
	oldSnapshot := mustRead(t, filepath.Join(f.directory, "metadata/1.snapshot.json"))
	timestamp := metadata.Timestamp(f.now.Add(time.Hour))
	timestamp.Signed.Version = 3
	timestamp.Signed.Meta = map[string]*metadata.MetaFiles{"snapshot.json": metaInfo(1, oldSnapshot)}
	if _, err := timestamp.Sign(f.publisher.cfg.Signers.Timestamp[0]); err != nil {
		t.Fatal(err)
	}
	data, err := timestamp.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	fetch := DirectoryFetch(f.directory)
	restarted := f.client(t, directory, func(ctx context.Context, name string, limit int64) ([]byte, error) {
		if name == "metadata/timestamp.json" {
			return data, nil
		}
		return fetch(ctx, name, limit)
	})
	if _, err = restarted.Select(context.Background(), fixtureRequest()); err == nil {
		t.Fatal("signed newer timestamp rolled snapshot backward")
	}
}
