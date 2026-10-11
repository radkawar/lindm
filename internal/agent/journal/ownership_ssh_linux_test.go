//go:build linux

package journal

import (
	"crypto/sha256"
	"testing"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativefile"
	"lindm/internal/resource"
)

func sshTestDigest(value string) []byte { sum := sha256.Sum256([]byte(value)); return sum[:] }
func sshTestSnapshot(present bool) *agentv1.ResourceOwnershipSnapshot {
	file := func(path string, inode uint64) *agentv1.SSHNativeFileSnapshot {
		state := &resourcev1.ManagedFileObservation{Path: path, AncestrySha256: sshTestDigest("ancestry"), NativeIdentitySha256: sshTestDigest("identity"), SecurityMetadataSha256: nativefile.XattrDigest(nil)}
		f := &agentv1.SSHNativeFileSnapshot{State: state, Continuity: &agentv1.NativeFileContinuity{InodeGenerationSha256: sshTestDigest("generation" + path), AncestryGenerationSha256: sshTestDigest("parent-generation" + path)}}
		if present {
			f.Content = []byte("public notice\n")
			state.Exists = true
			state.File = &resourcev1.FileIdentity{Path: path, Inode: inode, Mode: 0644, Sha256: sshTestDigest(string(f.Content))}
		}
		return f
	}
	private := &agentv1.SSHServerOwnership{Directive: file(resource.SSHBannerDirectivePath, 20), Banner: file(resource.SSHBannerPath, 21)}
	public := &resourcev1.SSHServerObservation{IncludeGraphSha256: sshTestDigest("includes"), EffectiveConfigurationSha256: sshTestDigest("effective"), ServiceUnit: "ssh.service", Effective: &resourcev1.SSHServerDesired{Port: proto.Uint32(22)}, BannerFile: proto.CloneOf(private.Banner.State), DirectiveFile: proto.CloneOf(private.Directive.State)}
	return &agentv1.ResourceOwnershipSnapshot{SshServer: private, Observation: &resourcev1.ResourceObservation{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SSH_SERVER, CanonicalKey: "system"}, Metadata: &resourcev1.ObservationMetadata{BootId: uuid.NewString(), ExecutorIncarnation: uuid.NewString(), ObservedAt: timestamppb.Now(), NativeRevision: sshTestDigest("revision"), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK, Backend: &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_OPENSSH, NativeVersion: "OpenSSH_9.6p1", ProviderVersion: "1", Product: &resourcev1.PlatformProduct{OsId: "ubuntu", Product: "Ubuntu", Version: "24.04", Architecture: "x86_64"}}}, Observed: &resourcev1.ResourceObservation_SshServer{SshServer: public}}}
}

func TestSSHBannerSnapshotsPassCompleteJournalAdmission(t *testing.T) {
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	store := &Store{validator: validator}
	for _, present := range []bool{false, true} {
		snapshot := sshTestSnapshot(present)
		if err := store.validateOwnershipSnapshot(snapshot, snapshot.GetObservation().GetRef()); err != nil {
			t.Fatal(err)
		}
		snapshot.SshServer = nil
		if store.validateOwnershipSnapshot(snapshot, snapshot.GetObservation().GetRef()) == nil {
			t.Fatal("public SSH state persisted without exact private files")
		}
	}
}
func TestSSHBannerJournalBindsBytesIdentityAndMetadata(t *testing.T) {
	last := sshTestSnapshot(true)
	for _, mutate := range []func(*agentv1.ResourceOwnershipSnapshot){
		func(s *agentv1.ResourceOwnershipSnapshot) { s.SshServer.Banner.Content = []byte("forged") },
		func(s *agentv1.ResourceOwnershipSnapshot) { s.SshServer.Banner.State.Path = "/etc/passwd" },
		func(s *agentv1.ResourceOwnershipSnapshot) {
			s.SshServer.Banner.Xattrs = []*agentv1.NativeFileXattr{{Name: "system.posix_acl_access", Value: []byte("forged")}}
		},
	} {
		s := proto.CloneOf(last)
		mutate(s)
		if sshOwnershipSnapshotValid(s) {
			t.Fatal("inconsistent private snapshot admitted")
		}
	}
	drift := proto.CloneOf(last)
	drift.SshServer.Banner.Content = []byte("local edit")
	if !SSHOwnershipIdentityMatches(last, drift) || SSHOwnershipMatches(last, drift) {
		t.Fatal("content drift cannot repair or can destructively release")
	}
	drift.SshServer.Banner.State.File.Inode++
	if SSHOwnershipIdentityMatches(last, drift) {
		t.Fatal("replacement transferred ownership")
	}
	if sshOwnershipDimensionKind(resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SSH_BANNER) {
		t.Fatal("banner custody claimed by generic file")
	}
}

func TestSSHOwnershipRejectsReusedInodeAndReplacedAncestor(t *testing.T) {
	last := sshTestSnapshot(true)
	for _, change := range []func(*agentv1.SSHNativeFileSnapshot){
		func(f *agentv1.SSHNativeFileSnapshot) {
			f.Continuity.InodeGenerationSha256 = sshTestDigest("different birth time")
			f.State.NativeIdentitySha256 = sshTestDigest("reused inode")
		},
		func(f *agentv1.SSHNativeFileSnapshot) {
			f.Continuity.AncestryGenerationSha256 = sshTestDigest("replaced protected parent")
		},
	} {
		for _, directive := range []bool{false, true} {
			replaced := proto.CloneOf(last)
			file := replaced.SshServer.Banner
			if directive {
				file = replaced.SshServer.Directive
			}
			change(file)
			if SSHOwnershipIdentityMatches(last, replaced) || SSHOwnershipMatches(last, replaced) {
				t.Fatal("replacement with identical inode number/bytes gained repair or release authority")
			}
		}
	}
	reboot := proto.CloneOf(last)
	reboot.Observation.Metadata.BootId = uuid.NewString()
	for _, file := range []*agentv1.SSHNativeFileSnapshot{reboot.SshServer.Banner, reboot.SshServer.Directive} {
		file.State.File.Device++
		file.State.NativeIdentitySha256 = sshTestDigest("renumbered device")
		file.State.AncestrySha256 = sshTestDigest("renumbered ancestor devices")
	}
	if !SSHOwnershipMatches(last, reboot) {
		t.Fatal("device renumbering discarded stable generation proof")
	}
}
