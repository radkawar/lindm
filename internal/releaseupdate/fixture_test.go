// SPDX-License-Identifier: Apache-2.0

package releaseupdate

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/types/known/timestamppb"

	updatev1 "lindm/gen/lindm/update/v1"
)

type repositoryFixture struct {
	publisher *Publisher
	directory string
	root      []byte
	now       time.Time
	channel   *updatev1.AgentUpdateChannel
	payload   []byte
}

func fixtureSigners(t *testing.T) RoleSigners {
	t.Helper()
	keys := make([]signature.Signer, 5)
	for i := range keys {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[i], err = signature.LoadSigner(key, crypto.Hash(0))
		if err != nil {
			t.Fatal(err)
		}
	}
	return RoleSigners{Root: []signature.Signer{keys[0]}, Targets: []signature.Signer{keys[1]}, Snapshot: []signature.Signer{keys[2]}, Timestamp: []signature.Signer{keys[3]}, Rollout: []signature.Signer{keys[4]}}
}
func newRepositoryFixture(t *testing.T) *repositoryFixture {
	t.Helper()
	now := time.Now().UTC().Add(-time.Second)
	directory := filepath.Join(t.TempDir(), "repository")
	publisher, err := CreateRepository(context.Background(), PublisherConfig{Directory: directory, Signers: fixtureSigners(t), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.ReadFile(filepath.Join(directory, "metadata/1.root.json"))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("signed native package test payload: not a native transaction fixture\n")
	source := filepath.Join(t.TempDir(), "lindm-agent.deb")
	if err = os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	channel := &updatev1.AgentUpdateChannel{Ring: "stable", Generation: 1, EligiblePercentage: 100, IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(7 * 24 * time.Hour)), Artifacts: []*updatev1.AgentUpdateArtifact{{Version: "1.2.3", Architecture: "amd64", PackageFormat: "deb", TargetPath: "packages/lindm-agent/1.2.3/amd64.deb", NativeVersion: "1.2.3-1", MinimumAgentVersion: "1.0.0", MaximumAgentVersion: "1.2.2", MinimumProtocolVersion: 1, MaximumProtocolVersion: 1}}}
	if err = publisher.Publish(context.Background(), channel, map[string]string{channel.Artifacts[0].TargetPath: source}); err != nil {
		t.Fatal(err)
	}
	return &repositoryFixture{publisher: publisher, directory: directory, root: root, now: now, channel: channel, payload: payload}
}
func (f *repositoryFixture) client(t *testing.T, state string, fetch FetchFunc) *Client {
	t.Helper()
	if state == "" {
		state = filepath.Join(t.TempDir(), "client")
	}
	if fetch == nil {
		fetch = DirectoryFetch(f.directory)
	}
	client, err := NewClient(ClientConfig{StateDir: state, BootstrapRoot: f.root, Fetch: fetch, Now: func() time.Time { return f.now.Add(time.Second) }})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
func fixtureRequest() SelectionRequest {
	return SelectionRequest{Ring: "stable", DeviceID: "owned-device", CurrentVersion: "1.1.0", Architecture: "amd64", PackageFormat: "deb", ProtocolVersion: 1}
}
func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func mustWrite(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
}
