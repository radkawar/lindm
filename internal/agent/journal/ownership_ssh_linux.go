//go:build linux

package journal

import (
	"bytes"
	"crypto/sha256"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativefile"
	"lindm/internal/resource"
)

func sshOwnershipSnapshotValid(snapshot *agentv1.ResourceOwnershipSnapshot) bool {
	private, public := snapshot.GetSshServer(), snapshot.GetObservation().GetSshServer()
	if private == nil || public == nil {
		return false
	}
	return sshFileValid(private.GetDirective(), public.GetDirectiveFile(), resource.SSHBannerDirectivePath) && sshFileValid(private.GetBanner(), public.GetBannerFile(), resource.SSHBannerPath)
}

func sshFileValid(file *agentv1.SSHNativeFileSnapshot, public *resourcev1.ManagedFileObservation, path string) bool {
	state := file.GetState()
	if state == nil || !proto.Equal(state, public) || state.GetPath() != path || state.GetExists() != (file.Content != nil) || state.GetExists() != (state.GetFile() != nil) || len(state.GetNativeIdentitySha256()) != 32 || len(state.GetAncestrySha256()) != 32 || !bytes.Equal(state.GetSecurityMetadataSha256(), nativefile.XattrDigest(file.GetXattrs())) {
		return false
	}
	if !nativeOwnershipXattrsValid(state.GetExists(), file.GetXattrs()) {
		return false
	}
	if !state.GetExists() {
		return true
	}
	digest := sha256.Sum256(file.GetContent())
	return state.GetFile().GetPath() == path && state.GetFile().GetUid() == 0 && state.GetFile().GetMode()&0022 == 0 && bytes.Equal(digest[:], state.GetFile().GetSha256())
}

func sshOwnershipAcquisitionAllowed(intent *agentv1.ResourceExecutionIntent, snapshot *agentv1.ResourceOwnershipSnapshot) bool {
	if !sshOwnershipSnapshotValid(snapshot) || !resource.SSHBannerOnly(intent.GetDesired().GetSshServer()) || snapshot.GetSshServer().GetDirective().GetState().GetExists() {
		return false
	}
	// An existing issue.net belongs to the operator or distribution. Only an
	// exact approved adoption may capture it as a baseline; matching bytes do
	// not transfer ownership. The reserved drop-in is never adopted.
	return !snapshot.GetSshServer().GetBanner().GetState().GetExists() || intent.GetOwnership().GetPolicy().GetMode() == resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION
}

// SSHOwnershipIdentityMatches permits content drift repair only on the same
// protected inode generation and every recorded ancestor generation. Filesystem
// identities survive btrfs device-number reassignment at reboot without dropping
// the birth-time or ancestry continuity that excludes replaced native objects.
func SSHOwnershipIdentityMatches(left, right *agentv1.ResourceOwnershipSnapshot) bool {
	if left.GetSshServer() == nil || right.GetSshServer() == nil {
		return false
	}
	return sshFileIdentity(left.GetSshServer().GetDirective(), right.GetSshServer().GetDirective()) && sshFileIdentity(left.GetSshServer().GetBanner(), right.GetSshServer().GetBanner())
}

func sshFileIdentity(a, b *agentv1.SSHNativeFileSnapshot) bool {
	x, y := a.GetState(), b.GetState()
	if a.GetContinuity() == nil || !proto.Equal(a.GetContinuity(), b.GetContinuity()) {
		return false
	}
	return x != nil && y != nil && x.GetPath() == y.GetPath() && x.GetExists() == y.GetExists() && x.GetFile().GetInode() == y.GetFile().GetInode() && x.GetFile().GetUid() == y.GetFile().GetUid() && x.GetFile().GetGid() == y.GetFile().GetGid() && x.GetFile().GetMode() == y.GetFile().GetMode() && bytes.Equal(x.GetSecurityMetadataSha256(), y.GetSecurityMetadataSha256())
}

// SSHOwnershipMatches binds release to the exact last applied public bytes and
// native identities. Release never overwrites a local edit, even an in-place one.
func SSHOwnershipMatches(left, right *agentv1.ResourceOwnershipSnapshot) bool {
	return SSHOwnershipIdentityMatches(left, right) && bytes.Equal(left.GetSshServer().GetDirective().GetContent(), right.GetSshServer().GetDirective().GetContent()) && bytes.Equal(left.GetSshServer().GetBanner().GetContent(), right.GetSshServer().GetBanner().GetContent())
}

func sshOwnershipDimensionKind(kind resourcev1.ResourceKind, dimension agentv1.ResourceOwnedDimension) bool {
	return kind == resourcev1.ResourceKind_RESOURCE_KIND_SSH_SERVER && dimension == agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_SSH_BANNER
}
