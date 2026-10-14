// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func approvedAptSource() *agentv1.NativePackageSource {
	key := sha256.Sum256([]byte("approved signing key"))
	return &agentv1.NativePackageSource{
		Repository: &resourcev1.RepositoryDesired{
			RepositoryId: uuid.NewString(),
			Presence:     resourcev1.Presence_PRESENCE_PRESENT,
			Source: &resourcev1.RepositoryDesired_Apt{Apt: &resourcev1.AptRepository{
				Uri: "https://packages.example.test/ubuntu", Suite: "noble", Components: []string{"main"}, Architectures: []string{"amd64"},
				SigningKey: &resourcev1.ArtifactRef{Sha256: key[:], SizeBytes: 20, ArtifactId: uuid.NewString()},
			}},
		},
		SigningKeyFile:   "/etc/lindm/keys/packages.asc",
		SigningKeySha256: key[:],
	}
}

func TestApprovedConfigurationPublishesEffectiveApprovals(t *testing.T) {
	roots := []*agentv1.NativeApprovedHomeRoot{{RootId: uuid.NewString(), Path: "/srv/homes"}}
	source := approvedAptSource()
	c := newCapabilityFixture(t, nil)
	// The effective snapshot normally comes from executor.json plus the
	// accepted policy; a local package source needs a root-owned key file, so
	// install the snapshot directly.
	c.svc.providers.Store(&providerSnapshot{
		config:   new(agentv1.AgentConfig),
		packages: &agentv1.NativePackageProviderConfig{Sources: []*agentv1.NativePackageSource{source}},
		native:   NativeResourceProviders{Accounts: &agentv1.NativeAccountProviderConfig{ApprovedHomeRoots: roots}},
	})
	got := approvedConfiguration(t, c.svc)
	if !got.GetObservedAt().AsTime().Equal(c.now) || len(got.GetHomeRoots()) != 1 || !proto.Equal(got.GetHomeRoots()[0], roots[0]) {
		t.Fatalf("home roots = %v, want the effective approvals", got.GetHomeRoots())
	}
	if len(got.GetPackageSources()) != 1 || !proto.Equal(got.GetPackageSources()[0], source.GetRepository()) {
		t.Fatalf("package sources = %v, want only the approved repository", got.GetPackageSources())
	}
	// The local signing key path and digest are not part of the repository report.
	if strings.Contains(got.String(), source.GetSigningKeyFile()) {
		t.Fatal("approved configuration leaked the local signing key path")
	}
}

func TestApprovedConfigurationIncludesPolicyDerivedHomeRoot(t *testing.T) {
	c := newCapabilityFixture(t, nil)
	if got := approvedConfiguration(t, c.svc); len(got.GetHomeRoots()) != 0 {
		t.Fatalf("home roots before any policy = %v", got.GetHomeRoots())
	}
	policy := c.policy(t, 1, agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_LOCAL_ACCOUNTS)
	if _, err := c.update(c.sign(t, policy, c.planKey)); err != nil {
		t.Fatal(err)
	}
	got := approvedConfiguration(t, c.svc)
	if len(got.GetHomeRoots()) != 1 || got.GetHomeRoots()[0].GetPath() != "/home" {
		t.Fatalf("home roots = %v, want the registry /home root derived from the policy", got.GetHomeRoots())
	}
}

func approvedConfiguration(t *testing.T, svc *Service) *agentv1.ApprovedConfigurationObservation {
	t.Helper()
	response, err := svc.GetApprovedConfiguration(t.Context(), connect.NewRequest(&agentv1.GetApprovedConfigurationRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.GetObservation()
}

func TestApprovedConfigurationWithoutProvidersIsEmpty(t *testing.T) {
	svc := openExecutor(t, time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC))
	response, err := svc.GetApprovedConfiguration(t.Context(), connect.NewRequest(&agentv1.GetApprovedConfigurationRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if got := response.Msg.GetObservation(); len(got.GetHomeRoots()) != 0 || len(got.GetPackageSources()) != 0 {
		t.Fatalf("unconfigured executor reported approvals: %v", got)
	}
}
