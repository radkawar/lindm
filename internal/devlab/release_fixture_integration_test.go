//go:build integration

package devlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"

	"lindm/internal/trust"
)

// This runs a real private PostgreSQL/server fixture and validates the signed
// provisioning bytes. It is not a mock of the vmlab constructor's routing.
func TestReleaseFixtureReturnsResignedBootstrap(t *testing.T) {
	binary := os.Getenv("LINDM_NATIVE_SERVER_BINARY")
	repository := os.Getenv("LINDM_NATIVE_REPOSITORY")
	if binary == "" || repository == "" {
		t.Skip("requires LINDM_NATIVE_SERVER_BINARY (stamped lindmd) and LINDM_NATIVE_REPOSITORY (initialized development trust/database)")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	sharedBefore, err := ReadPublicAgentFixture(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	fixture, _, err := OpenReleaseAuthorityFixture(ctx, repository, binary)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixture.Close(); err != nil {
			t.Error(err)
		}
	}()
	material, err := fixture.ReadAgentFixture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(filepath.Join(fixture.directory, "bootstrap.dsse.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(material.BootstrapEnvelope, persisted) || bytes.Equal(material.BootstrapEnvelope, sharedBefore.BootstrapEnvelope) {
		t.Fatal("live fixture did not return its exact privately re-signed bootstrap")
	}
	sharedAfter, err := ReadPublicAgentFixture(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sharedBefore.BootstrapEnvelope, sharedAfter.BootstrapEnvelope) || !bytes.Equal(sharedBefore.ExecutionRootJSON, sharedAfter.ExecutionRootJSON) {
		t.Fatal("release fixture mutated shared provisioning authority")
	}
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := authority.VerifyBootstrap(ctx, material.ExecutionRootJSON, material.BootstrapEnvelope, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	repositoryRoot, err := os.ReadFile(filepath.Join(fixture.directory, "release-repository", "metadata", "1.root.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(verified.Bundle.GetReleaseRootJson(), repositoryRoot) {
		t.Fatal("signed bootstrap release pin differs from isolated repository root")
	}
	root, err := metadata.Root().FromBytes(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.VerifyDelegate(metadata.ROOT, root); err != nil {
		t.Fatal(err)
	}
	snapshot, err := fixture.CaptureReleaseMetadata(ctx)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := metadata.Targets().FromBytes(snapshot.targets)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.VerifyDelegate(metadata.TARGETS, targets); err != nil {
		t.Fatal(err)
	}
	delegation := targets.Signed.Delegations
	if delegation == nil || len(delegation.Roles) != 1 || delegation.Roles[0].Name != "rollout" {
		t.Fatal("missing isolated channels-only rollout delegation")
	}
	rollout, err := metadata.Targets().FromBytes(snapshot.rollout)
	if err != nil {
		t.Fatal(err)
	}
	if err := targets.VerifyDelegate("rollout", rollout); err != nil {
		t.Fatal(err)
	}
	seen := make(map[[32]byte]string)
	checkKey := func(role string, key *metadata.Key) {
		t.Helper()
		if key == nil {
			t.Fatalf("missing %s public key", role)
		}
		public, err := key.ToPublicKey()
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(der)
		if previous, ok := seen[digest]; ok {
			t.Fatalf("roles %s and %s reuse a public key", previous, role)
		}
		seen[digest] = role
	}
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		definition := root.Signed.Roles[role]
		if definition == nil || len(definition.KeyIDs) != 1 || definition.Threshold != 1 {
			t.Fatalf("unexpected generated %s role quorum", role)
		}
		checkKey(role, root.Signed.Keys[definition.KeyIDs[0]])
	}
	for _, id := range delegation.Roles[0].KeyIDs {
		checkKey("rollout", delegation.Keys[id])
	}
	if len(seen) != 5 {
		t.Fatalf("generated fixture has %d distinct role keys, want five", len(seen))
	}
}
