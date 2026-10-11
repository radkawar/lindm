//go:build linux

package packageprovider

import (
	"bytes"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestALPMSourceRequiresBoundKeyAndFingerprint(t *testing.T) {
	digest := bytes.Repeat([]byte{1}, 32)
	source := &agentv1.NativePackageSource{
		Repository: &resourcev1.RepositoryDesired{
			RepositoryId: "67e587cd-1fc8-4969-87b9-e569d5829c85",
			Presence:     resourcev1.Presence_PRESENCE_PRESENT,
			Source: &resourcev1.RepositoryDesired_Alpm{Alpm: &resourcev1.AlpmRepository{
				NativeName: "approved", SnapshotUri: "https://repo.example.test/20261002/", Architecture: "x86_64",
				SigningKeys: []*resourcev1.ArtifactRef{{ArtifactId: "d597683f-3bcb-4dbf-97f7-741b3921536c", Sha256: digest, SizeBytes: 100}},
			}},
		},
		SigningKeyFile: "/etc/lindm/repository.gpg", SigningKeySha256: digest,
		AlpmSigningKeyFingerprint: strings.Repeat("A", 40),
	}
	if err := validateMessage(source); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*agentv1.NativePackageSource){
		func(s *agentv1.NativePackageSource) { s.AlpmSigningKeyFingerprint = "" },
		func(s *agentv1.NativePackageSource) { s.RpmSigningKeyFingerprint = strings.Repeat("A", 40) },
		func(s *agentv1.NativePackageSource) { s.SigningKeySha256 = bytes.Repeat([]byte{2}, 32) },
		func(s *agentv1.NativePackageSource) { s.Repository.Presence = resourcev1.Presence_PRESENCE_ABSENT },
	} {
		invalid := proto.CloneOf(source)
		change(invalid)
		if err := validateMessage(invalid); err == nil {
			t.Fatal("unbound ALPM source accepted")
		}
	}
	if got := sourceRef(source).GetCanonicalKey(); got != "alpm/"+source.GetRepository().GetRepositoryId() {
		t.Fatalf("ALPM source routed through another ecosystem: %q", got)
	}
}
