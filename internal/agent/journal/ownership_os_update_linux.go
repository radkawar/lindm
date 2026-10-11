//go:build linux

package journal

import (
	"bytes"
	"crypto/sha256"
	"strings"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

// osUpdateOwnershipSnapshotValid binds the private update policy evidence to the
// closed owned paths of its backend in canonical order, exact private bytes
// behind each public digest and the same timer runtime state.
func osUpdateOwnershipSnapshotValid(snapshot *agentv1.ResourceOwnershipSnapshot) bool {
	observation, private := snapshot.GetObservation().GetOsUpdate(), snapshot.GetOsUpdate()
	if observation == nil {
		return private == nil
	}
	if private == nil || private.GetTimerActive() != observation.GetTimerActive() {
		return false
	}
	kinds := osUpdateBackendFiles(observation.GetBackend())
	files := private.GetFiles()
	if kinds == nil || len(files) != len(kinds) || len(observation.GetFiles()) != len(kinds) {
		return false
	}
	for i, file := range files {
		public := observation.GetFiles()[i]
		path := resource.OSUpdateNativePath(file.GetKind())
		state := file.GetState()
		if file.GetKind() != kinds[i] || path == "" || public.GetKind() != file.GetKind() || !proto.Equal(public.GetState(), state) {
			return false
		}
		if state.GetPath() != path || state.GetExists() != (file.Content != nil) || state.GetExists() != (state.GetFile() != nil) || len(state.GetAncestrySha256()) != 32 || len(state.GetNativeIdentitySha256()) != 32 || len(state.GetSecurityMetadataSha256()) != 32 {
			return false
		}
		if !nativeOwnershipXattrsValid(state.GetExists(), file.GetXattrs()) {
			return false
		}
		if !state.GetExists() {
			if len(public.GetContentSha256()) != 0 {
				return false
			}
			continue
		}
		digest := sha256.Sum256(file.GetContent())
		if state.GetFile().GetPath() != path || !bytes.Equal(digest[:], state.GetFile().GetSha256()) || !bytes.Equal(digest[:], public.GetContentSha256()) || state.GetFile().GetUid() != 0 || state.GetFile().GetMode()&0022 != 0 {
			return false
		}
	}
	return true
}

// osUpdateBackendFiles is the closed owned object set of each backend in
// canonical order; only the native-configuration object differs.
func osUpdateBackendFiles(backend resourcev1.OSUpdateBackend) []resourcev1.OSUpdateNativeFile {
	files := []resourcev1.OSUpdateNativeFile{resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_POLICY, resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_TIMER, resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_TIMER_WANTS}
	switch backend {
	case resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES:
		return append(files, resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_APT_PERIODIC)
	case resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF5_AUTOMATIC:
		return append(files, resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_DNF5_AUTOMATIC)
	case resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC:
		return files
	default:
		return nil
	}
}

func nativeOwnershipXattrsValid(exists bool, attrs []*agentv1.NativeFileXattr) bool {
	if !exists && len(attrs) != 0 {
		return false
	}
	previous, size := "", 0
	for _, attr := range attrs {
		if attr.GetName() <= previous || (!strings.HasPrefix(attr.GetName(), "user.") && attr.GetName() != "security.selinux") {
			return false
		}
		previous = attr.GetName()
		size += len(attr.GetName()) + len(attr.GetValue())
	}
	return size <= 32768
}

func osUpdateOwnershipDimensionKind(kind resourcev1.ResourceKind, dimension agentv1.ResourceOwnedDimension) bool {
	return kind == resourcev1.ResourceKind_RESOURCE_KIND_OS_UPDATE_POLICY && osUpdateDimension(dimension)
}

func osUpdateDimension(dimension agentv1.ResourceOwnedDimension) bool {
	return dimension >= agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OS_UPDATE_POLICY && dimension <= agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OS_UPDATE_NATIVE_CONFIGURATION
}

// Every update policy effect owns the complete closed object set: the runner
// policy, the window schedule and the native periodic-upgrade override.
func osUpdateOwnershipDimensionAllowed(action *agentv1.ResourceExecutionRecord, dimension agentv1.ResourceOwnedDimension) bool {
	return action.GetNativePlan().GetOsUpdate() != nil && osUpdateDimension(dimension)
}

func osUpdateNativeFile(snapshot *agentv1.ResourceOwnershipSnapshot, kind resourcev1.OSUpdateNativeFile) *agentv1.OSUpdateNativeFileSnapshot {
	for _, file := range snapshot.GetOsUpdate().GetFiles() {
		if file.GetKind() == kind {
			return file
		}
	}
	return nil
}

// Owned file state is compared by boot-stable identity: presence, exact bytes,
// mode/owner, security metadata and inode. The device number is not: btrfs
// (Fedora's root) assigns subvolume st_dev anonymously per boot, so the device-
// bearing native-identity and ancestry digests change across a reboot without
// any change to the file. Ancestry safety is re-proven by native custody on
// every write; an inode change still reveals a replacement.
func osUpdateFilesMatch(left, right *agentv1.ResourceOwnershipSnapshot, kinds ...resourcev1.OSUpdateNativeFile) bool {
	for _, kind := range kinds {
		if !osUpdateFileStable(osUpdateNativeFile(left, kind), osUpdateNativeFile(right, kind)) {
			return false
		}
	}
	return true
}

func osUpdateFileStable(a, b *agentv1.OSUpdateNativeFileSnapshot) bool {
	if a == nil || b == nil {
		return a == b
	}
	x, y := a.GetState(), b.GetState()
	return x.GetPath() == y.GetPath() && x.GetExists() == y.GetExists() && bytes.Equal(a.GetContent(), b.GetContent()) &&
		x.GetFile().GetMode() == y.GetFile().GetMode() && x.GetFile().GetUid() == y.GetFile().GetUid() && x.GetFile().GetGid() == y.GetFile().GetGid() &&
		x.GetFile().GetInode() == y.GetFile().GetInode() && bytes.Equal(x.GetFile().GetSha256(), y.GetFile().GetSha256()) &&
		bytes.Equal(x.GetSecurityMetadataSha256(), y.GetSecurityMetadataSha256()) &&
		proto.Equal(&agentv1.OSUpdateNativeFileSnapshot{Xattrs: a.GetXattrs()}, &agentv1.OSUpdateNativeFileSnapshot{Xattrs: b.GetXattrs()})
}

// OSUpdateOwnershipDifference names the first differing owned component for
// refusal diagnostics ("" when the dimensions match). It grants nothing.
func OSUpdateOwnershipDifference(left, right *agentv1.ResourceOwnershipSnapshot, dimensions []agentv1.ResourceOwnedDimension) string {
	for _, dimension := range dimensions {
		if osUpdateOwnershipDimensionMatches(left, right, dimension) {
			continue
		}
		for _, kind := range resource.OSUpdateNativeFiles() {
			a, b := osUpdateNativeFile(left, kind), osUpdateNativeFile(right, kind)
			if osUpdateFileStable(a, b) {
				continue
			}
			x, y := a.GetState(), b.GetState()
			field := "presence"
			switch {
			case (a == nil) != (b == nil) || x.GetExists() != y.GetExists():
			case !bytes.Equal(a.GetContent(), b.GetContent()):
				field = "content"
			case x.GetFile().GetMode() != y.GetFile().GetMode() || x.GetFile().GetUid() != y.GetFile().GetUid() || x.GetFile().GetGid() != y.GetFile().GetGid():
				field = "mode_owner"
			case !bytes.Equal(x.GetSecurityMetadataSha256(), y.GetSecurityMetadataSha256()) || !proto.Equal(&agentv1.OSUpdateNativeFileSnapshot{Xattrs: a.GetXattrs()}, &agentv1.OSUpdateNativeFileSnapshot{Xattrs: b.GetXattrs()}):
				field = "security_metadata"
			case !bytes.Equal(x.GetNativeIdentitySha256(), y.GetNativeIdentitySha256()) || x.GetFile().GetInode() != y.GetFile().GetInode():
				field = "native_identity"
			case !bytes.Equal(x.GetAncestrySha256(), y.GetAncestrySha256()):
				field = "ancestry"
			default:
				field = "file_state"
			}
			return dimension.String() + ":" + kind.String() + ":" + field
		}
		if left.GetOsUpdate().GetTimerActive() != right.GetOsUpdate().GetTimerActive() {
			return dimension.String() + ":timer_active"
		}
		return dimension.String() + ":timer_calendar"
	}
	return ""
}

func osUpdateOwnershipDimensionMatches(left, right *agentv1.ResourceOwnershipSnapshot, dimension agentv1.ResourceOwnedDimension) bool {
	a, b := left.GetObservation().GetOsUpdate(), right.GetObservation().GetOsUpdate()
	if a == nil || b == nil || left.GetOsUpdate() == nil || right.GetOsUpdate() == nil || a.GetBackend() != b.GetBackend() {
		return false
	}
	switch dimension {
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OS_UPDATE_POLICY:
		return osUpdateFilesMatch(left, right, resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_POLICY)
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OS_UPDATE_SCHEDULE:
		return osUpdateFilesMatch(left, right, resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_TIMER, resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_TIMER_WANTS) && left.GetOsUpdate().GetTimerActive() == right.GetOsUpdate().GetTimerActive() && a.GetTimerCalendar() == b.GetTimerCalendar()
	case agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_OS_UPDATE_NATIVE_CONFIGURATION:
		return osUpdateFilesMatch(left, right, resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_APT_PERIODIC, resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_DNF5_AUTOMATIC)
	default:
		return false
	}
}

// The provider never adopts: ownership starts only from a baseline in which
// every owned path is absent and no lindm-os-update.timer is loaded.
func osUpdateOwnershipAcquisitionAllowed(snapshot *agentv1.ResourceOwnershipSnapshot) bool {
	observation := snapshot.GetObservation().GetOsUpdate()
	if !osUpdateOwnershipSnapshotValid(snapshot) || observation == nil || observation.GetTimerActive() || observation.GetTimerCalendar() != "" {
		return false
	}
	for _, file := range snapshot.GetOsUpdate().GetFiles() {
		if file.GetState().GetExists() {
			return false
		}
	}
	return true
}

// OSUpdateOwnershipMatches compares only the captured ownership dimensions.
func OSUpdateOwnershipMatches(left, right *agentv1.ResourceOwnershipSnapshot, dimensions []agentv1.ResourceOwnedDimension) bool {
	if left == nil || right == nil || len(dimensions) == 0 {
		return false
	}
	for _, dimension := range dimensions {
		if !osUpdateOwnershipDimensionMatches(left, right, dimension) {
			return false
		}
	}
	return true
}
