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

func TestApprovedConfigurationPublishesLocalApprovalsOnly(t *testing.T) {
	now := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	roots := []*agentv1.NativeApprovedHomeRoot{{RootId: uuid.NewString(), Path: "/home"}, {RootId: uuid.NewString(), Path: "/srv/homes"}}
	source := approvedAptSource()
	svc := openExecutor(t, now,
		WithNativeResourceProviders(NativeResourceProviders{Accounts: &agentv1.NativeAccountProviderConfig{ApprovedHomeRoots: roots}}),
		WithPackageProvider(&agentv1.NativePackageProviderConfig{Sources: []*agentv1.NativePackageSource{source}}),
	)
	response, err := svc.GetApprovedConfiguration(t.Context(), connect.NewRequest(&agentv1.GetApprovedConfigurationRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	got := response.Msg.GetObservation()
	if !got.GetObservedAt().AsTime().Equal(now) || len(got.GetHomeRoots()) != 2 || !proto.Equal(got.GetHomeRoots()[1], roots[1]) {
		t.Fatalf("home roots = %v, want the configured approvals", got.GetHomeRoots())
	}
	if len(got.GetPackageSources()) != 1 || !proto.Equal(got.GetPackageSources()[0], source.GetRepository()) {
		t.Fatalf("package sources = %v, want only the approved repository", got.GetPackageSources())
	}
	// The local signing key path and digest are not part of the repository report.
	if strings.Contains(got.String(), source.GetSigningKeyFile()) {
		t.Fatal("approved configuration leaked the local signing key path")
	}
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
