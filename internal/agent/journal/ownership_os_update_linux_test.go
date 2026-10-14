// SPDX-License-Identifier: Apache-2.0

//go:build linux

package journal

import (
	"crypto/sha256"
	"testing"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativefile"
	"lindm/internal/resource"
)

func osUpdateDigest(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

func osUpdateSnapshot(backend resourcev1.OSUpdateBackend, present bool) *agentv1.ResourceOwnershipSnapshot {
	private := &agentv1.OSUpdateOwnership{TimerActive: present}
	observation := &resourcev1.OSUpdateObservation{Backend: backend, NativeVersion: "tool 1.0", TimerActive: present}
	for i, kind := range osUpdateBackendFiles(backend) {
		path := resource.OSUpdateNativePath(kind)
		state := &resourcev1.ManagedFileObservation{Path: path, AncestrySha256: osUpdateDigest("ancestry"), NativeIdentitySha256: osUpdateDigest("absent"), SecurityMetadataSha256: nativefile.XattrDigest(nil)}
		file := &agentv1.OSUpdateNativeFileSnapshot{Kind: kind, State: state}
		public := &resourcev1.OSUpdateFileObservation{Kind: kind}
		if present {
			content := []byte("owned " + path)
			sum := sha256.Sum256(content)
			state.Exists = true
			state.NativeIdentitySha256 = osUpdateDigest(path)
			state.File = &resourcev1.FileIdentity{Path: path, Inode: uint64(10 + i), Mode: 0644, Sha256: sum[:]}
			file.Content = content
			public.ContentSha256 = sum[:]
		}
		public.State = proto.CloneOf(state)
		private.Files = append(private.Files, file)
		observation.Files = append(observation.Files, public)
	}
	if present {
		observation.TimerCalendar = "Mon *-*-* 02:00:00 UTC"
	}
	return &agentv1.ResourceOwnershipSnapshot{Observation: &resourcev1.ResourceObservation{Observed: &resourcev1.ResourceObservation_OsUpdate{OsUpdate: observation}}, OsUpdate: private}
}

// Every baseline, before-effect and after-image the provider produces passes
// the store's complete snapshot admission for this kind and backend.
func TestOSUpdateSnapshotsPassJournalAdmission(t *testing.T) {
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	s := &Store{validator: validator}
	ref := &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_OS_UPDATE_POLICY, CanonicalKey: "system"}
	backends := map[resourcev1.OSUpdateBackend]resourcev1.Backend{
		1: resourcev1.Backend_BACKEND_APT,
		2: resourcev1.Backend_BACKEND_DNF5,
		3: resourcev1.Backend_BACKEND_DNF4,
		4: resourcev1.Backend_BACKEND_ALPM,
		5: resourcev1.Backend_BACKEND_ZYPPER,
	}
	for update, native := range backends {
		for _, present := range []bool{false, true} {
			snapshot := osUpdateSnapshot(update, present)
			snapshot.Observation.Ref = proto.CloneOf(ref)
			snapshot.Observation.Metadata = &resourcev1.ObservationMetadata{
				BootId: uuid.NewString(), ExecutorIncarnation: uuid.NewString(), ObservedAt: timestamppb.Now(), NativeRevision: osUpdateDigest("revision"),
				Backend:           &resourcev1.BackendSelection{Backend: native, NativeVersion: "tool 1.0", ProviderVersion: "1", Product: &resourcev1.PlatformProduct{OsId: "linux", Product: "Linux", Version: "1", Architecture: "x86_64"}},
				ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK,
			}
			if err := s.validateOwnershipSnapshot(snapshot, ref); err != nil {
				t.Fatalf("%v present=%v snapshot refused by the journal: %v", update, present, err)
			}
			snapshot.OsUpdate = nil
			if s.validateOwnershipSnapshot(snapshot, ref) == nil {
				t.Fatal("public update observation stored without private evidence")
			}
		}
	}
}

func TestOSUpdateSnapshotBindsBackendFileSet(t *testing.T) {
	for _, backend := range []resourcev1.OSUpdateBackend{1, 2, 3, 4, 5} {
		if !osUpdateOwnershipSnapshotValid(osUpdateSnapshot(backend, true)) || !osUpdateOwnershipSnapshotValid(osUpdateSnapshot(backend, false)) {
			t.Fatalf("valid %v snapshot rejected", backend)
		}
	}
	// A DNF5 ledger cannot carry the APT override in place of automatic.conf.
	swapped := osUpdateSnapshot(resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF5_AUTOMATIC, false)
	swapped.OsUpdate.Files[3].Kind = resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_APT_PERIODIC
	swapped.OsUpdate.Files[3].State.Path = resource.OSUpdateAPTPeriodPath
	swapped.Observation.GetOsUpdate().Files[3].Kind = swapped.OsUpdate.Files[3].Kind
	swapped.Observation.GetOsUpdate().Files[3].State = proto.CloneOf(swapped.OsUpdate.Files[3].State)
	if osUpdateOwnershipSnapshotValid(swapped) {
		t.Fatal("foreign native configuration object accepted for the backend")
	}
	forged := osUpdateSnapshot(resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES, true)
	forged.OsUpdate.Files[0].Content = []byte("other bytes")
	if osUpdateOwnershipSnapshotValid(forged) {
		t.Fatal("private bytes not bound to the public digest")
	}
}

func TestOSUpdateAcquisitionRequiresAbsentBaseline(t *testing.T) {
	if !osUpdateOwnershipAcquisitionAllowed(osUpdateSnapshot(resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC, false)) {
		t.Fatal("absent baseline was not acquirable")
	}
	if osUpdateOwnershipAcquisitionAllowed(osUpdateSnapshot(resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC, true)) {
		t.Fatal("existing native objects were adopted")
	}
}

func TestOSUpdateDimensionsDetectReplacement(t *testing.T) {
	last := osUpdateSnapshot(resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES, true)
	current := proto.CloneOf(last)
	dimensions := []agentv1.ResourceOwnedDimension{60, 61, 62}
	if !OSUpdateOwnershipMatches(last, current, dimensions) {
		t.Fatal("unchanged owned objects reported as drift")
	}
	current.OsUpdate.Files[3].State.File.Inode = 99
	if !osUpdateOwnershipDimensionMatches(last, current, 60) || osUpdateOwnershipDimensionMatches(last, current, 62) {
		t.Fatal("native configuration replacement not isolated to its dimension")
	}
	current = proto.CloneOf(last)
	current.OsUpdate.TimerActive = false
	if osUpdateOwnershipDimensionMatches(last, current, 61) {
		t.Fatal("stopped owned timer not reported as schedule drift")
	}
}

// Fedora's btrfs root assigns subvolume st_dev per boot: the same owned files
// after a reboot differ only in device-bearing digests and must not block
// release, while changed bytes, owner or mode still do.
func TestOSUpdateDimensionsIgnoreBootDeviceNumbers(t *testing.T) {
	last := osUpdateSnapshot(resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF5_AUTOMATIC, true)
	dimensions := []agentv1.ResourceOwnedDimension{60, 61, 62}
	rebooted := proto.CloneOf(last)
	for _, file := range rebooted.GetOsUpdate().GetFiles() {
		file.State.File.Device = 77
		file.State.NativeIdentitySha256 = osUpdateDigest("new boot device " + file.GetState().GetPath())
		file.State.AncestrySha256 = osUpdateDigest("new boot ancestry")
	}
	if !OSUpdateOwnershipMatches(last, rebooted, dimensions) {
		t.Fatalf("boot-only device change reported as drift: %s", OSUpdateOwnershipDifference(last, rebooted, dimensions))
	}
	for name, mutate := range map[string]func(*agentv1.OSUpdateNativeFileSnapshot){
		"content": func(f *agentv1.OSUpdateNativeFileSnapshot) { f.Content = []byte("edited") },
		"mode":    func(f *agentv1.OSUpdateNativeFileSnapshot) { f.State.File.Mode = 0666 },
		"owner":   func(f *agentv1.OSUpdateNativeFileSnapshot) { f.State.File.Uid = 1000 },
		"label":   func(f *agentv1.OSUpdateNativeFileSnapshot) { f.State.SecurityMetadataSha256 = osUpdateDigest("label") },
	} {
		changed := proto.CloneOf(rebooted)
		mutate(changed.GetOsUpdate().GetFiles()[0])
		if OSUpdateOwnershipMatches(last, changed, dimensions) {
			t.Errorf("%s change of the owned policy file not reported as drift", name)
		}
	}
}
