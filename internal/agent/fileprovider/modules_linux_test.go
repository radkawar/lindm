//go:build linux

package fileprovider

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativefile"
	"lindm/internal/resource"
)

func moduleFixture(t *testing.T) (*Provider, *resourcev1.ResourceDesiredState, *agentv1.ResourceOwnershipSnapshot) {
	t.Helper()
	id := "986173ba-4472-4d62-ae38-81e742a3297e"
	d := &resourcev1.ManagedFileDesired{Path: ModuleBlocklistPath, Presence: resourcev1.Presence_PRESENCE_PRESENT, KernelModuleBlocklist: &resourcev1.KernelModuleBlocklist{Modules: []string{"usb_storage", "uas"}}}
	desired := &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, CanonicalKey: ModuleBlocklistPath}, State: &resourcev1.ResourceDesiredState_ManagedFile{ManagedFile: d}}
	backend := &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_POSIX_FILE, NativeVersion: "6.8.0", ProviderVersion: "1", Product: &resourcev1.PlatformProduct{OsId: "ubuntu", Product: "Ubuntu", Version: "24.04", Architecture: "x86_64"}}
	content := moduleTemplate(d).GetContent()
	digest := sha256.Sum256(content)
	observation := &resourcev1.ManagedFileObservation{Path: ModuleBlocklistPath, Exists: true, File: &resourcev1.FileIdentity{Path: ModuleBlocklistPath, Mode: 0644, Sha256: digest[:], Device: 1, Inode: 2}, AncestrySha256: make([]byte, 32), NativeIdentitySha256: make([]byte, 32), SecurityMetadataSha256: nativefile.XattrDigest(nil), KernelModuleBlocklist: &resourcev1.KernelModuleBlocklistObservation{Modules: []*resourcev1.KernelModuleObservation{{Name: "usb_storage", ModprobeBlocked: true}, {Name: "uas", ModprobeBlocked: true}}, Initramfs: []*resourcev1.ModuleInitramfsObservation{{KernelRelease: "6.8.0", Path: "/boot/initrd.img-6.8.0", Sha256: make([]byte, 32), BlocklistSha256: digest[:]}}}}
	snapshot := &agentv1.ResourceOwnershipSnapshot{Observation: &resourcev1.ResourceObservation{Ref: proto.CloneOf(desired.GetRef()), Metadata: &resourcev1.ObservationMetadata{BootId: id, ExecutorIncarnation: id, ObservedAt: timestamppb.New(time.Unix(1700000000, 0)), Backend: backend, NativeRevision: make([]byte, 32), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK}, Observed: &resourcev1.ResourceObservation_ManagedFile{ManagedFile: observation}}, ManagedFileContent: content}
	return &Provider{backend: backend}, desired, snapshot
}

func TestModuleDependencyProofRejectsEveryLoadingCommand(t *testing.T) {
	for _, output := range []string{"install /bin/false\n", "install /bin/false\ninstall /bin/false\n"} {
		if !moduleInstallCommandsBlocked([]byte(output)) {
			t.Fatal("closed false-only dependency chain rejected")
		}
	}
	for _, output := range []string{"", "insmod /lib/modules/usb-storage.ko\ninstall /bin/false\n", "install /bin/true\n", "builtin uas\n", "install /bin/false\n\ninstall /bin/false\n", "install /bin/false; /bin/true\n"} {
		if moduleInstallCommandsBlocked([]byte(output)) {
			t.Fatalf("unproven module loading accepted: %q", output)
		}
	}
}

func TestModuleTemplateDoesNotDelegateFileAuthority(t *testing.T) {
	_, desired, _ := moduleFixture(t)
	config := &agentv1.NativeFileProviderConfig{AllowedRoots: []string{"/etc/modprobe.d"}, KernelModuleBlocklist: true}
	if err := allowedPath(config, ModuleBlocklistPath); err == nil {
		t.Fatal("raw modprobe file bypassed protected namespace")
	}
	file := moduleTemplate(desired.GetManagedFile())
	want := "# Managed by lindm. Active and built-in modules are never unloaded.\nblacklist uas\ninstall uas /bin/false\nblacklist usb_storage\ninstall usb_storage /bin/false\n"
	if string(file.Content) != want || file.GetMode() != 0644 || file.GetUid() != 0 || file.GetGid() != 0 {
		t.Fatal("template changed fixed directives or metadata")
	}
	if desired.GetManagedFile().Content != nil {
		t.Fatal("rendering mutated desired authority")
	}
}

func TestModuleVerificationDistinguishesLoadedBuiltinAndDrift(t *testing.T) {
	p, desired, snapshot := moduleFixture(t)
	plan, err := p.makePlan(desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, snapshot, snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		change func(*agentv1.ResourceOwnershipSnapshot)
		want   resourcev1.VerificationDisposition
	}{
		"blocked": {func(*agentv1.ResourceOwnershipSnapshot) {}, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED},
		"loaded": {func(s *agentv1.ResourceOwnershipSnapshot) {
			s.Observation.GetManagedFile().KernelModuleBlocklist.Modules[0].Loaded = true
		}, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_PENDING_REBOOT},
		"built-in": {func(s *agentv1.ResourceOwnershipSnapshot) {
			m := s.Observation.GetManagedFile().KernelModuleBlocklist.Modules[0]
			m.BuiltIn = true
			m.ModprobeBlocked = false
		}, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE},
		"archive drift": {func(s *agentv1.ResourceOwnershipSnapshot) {
			s.Observation.GetManagedFile().KernelModuleBlocklist.Initramfs[0].BlocklistSha256 = nil
		}, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED},
		"native override": {func(s *agentv1.ResourceOwnershipSnapshot) {
			s.Observation.GetManagedFile().KernelModuleBlocklist.Modules[0].ModprobeBlocked = false
		}, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED},
		"failed rebuild": {func(s *agentv1.ResourceOwnershipSnapshot) { s.ModuleInitramfsRebuildSucceeded = proto.Bool(false) }, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED},
		"loaded and file drift": {func(s *agentv1.ResourceOwnershipSnapshot) {
			s.Observation.GetManagedFile().KernelModuleBlocklist.Modules[0].Loaded = true
			s.Observation.GetManagedFile().File.Mode = 0600
		}, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED},
	} {
		t.Run(name, func(t *testing.T) {
			after := proto.CloneOf(snapshot)
			test.change(after)
			verification, err := fileVerification(plan, after, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if verification.GetDisposition() != test.want {
				t.Fatalf("got %s, want %s", verification.GetDisposition(), test.want)
			}
			if err := resource.ValidateReadOnlyVerification(plan, verification); err != nil {
				t.Fatalf("read-only module finding rejected: %v", err)
			}
		})
	}
	without := proto.CloneOf(snapshot)
	without.Observation.GetManagedFile().KernelModuleBlocklist = nil
	if _, err := fileVerification(plan, without, snapshot); err == nil {
		t.Fatal("legacy file-only evidence accepted as blocklist evidence")
	}
}

func TestModulePlanRepairsInitramfsDespiteEqualFile(t *testing.T) {
	p, desired, target := moduleFixture(t)
	before := proto.CloneOf(target)
	before.Observation.GetManagedFile().KernelModuleBlocklist.Initramfs[0].BlocklistSha256 = nil
	plan, err := p.makePlan(desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, before, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !resource.PlanRequiresEffect(plan) {
		t.Fatal("equal file skipped stale initramfs")
	}
	plan, err = p.makePlan(desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, target, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resource.PlanRequiresEffect(plan) {
		t.Fatal("matching file and boot image requested another rebuild")
	}
}

func TestModuleKnownFailedRebuildRemainsOwed(t *testing.T) {
	p, desired, snapshot := moduleFixture(t)
	last := proto.CloneOf(snapshot)
	last.ModuleInitramfsRebuildSucceeded = proto.Bool(false)
	ledger := &agentv1.ResourceOwnershipLedger{State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED, Revision: 1, LastApplied: last}
	plan, err := p.makePlan(desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE, snapshot, snapshot, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if !resource.PlanRequiresEffect(plan) {
		t.Fatal("matching file and image erased a known failed rebuild")
	}
	stripped := moduleFileImage(last)
	if stripped.ModuleInitramfsRebuildSucceeded != nil || stripped.GetObservation().GetManagedFile().GetKernelModuleBlocklist() != nil {
		t.Fatal("module helper outcome leaked into generic file transaction")
	}
}

// Synthetic independent observations exercise custody ordering, not host effects.
func TestModuleReleaseRetainsCustodyWhenSuccessfulCommandLeavesStaleImage(t *testing.T) {
	p, desired, current := moduleFixture(t)
	id := current.GetObservation().GetMetadata().GetExecutorIncarnation()
	owner := &agentv1.ResourceOwnershipBinding{AssignmentId: id, ResourceId: id, Sources: []*agentv1.ResourceOwnershipSource{{ProfileId: id, ProfileRevision: id, ResourceId: id}}, Policy: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED}}
	baseline := proto.CloneOf(current)
	baseline.ManagedFileContent = nil
	baseline.Observation.GetManagedFile().Exists = false
	baseline.Observation.GetManagedFile().File = nil
	baseline.Observation.GetManagedFile().KernelModuleBlocklist.Initramfs[0].BlocklistSha256 = nil
	store := &memoryOwnership{owner: owner, release: true, ledger: &agentv1.ResourceOwnershipLedger{Ref: proto.CloneOf(desired.Ref), Owner: owner, Revision: 1, State: agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_APPLIED, Baseline: baseline, LastApplied: proto.CloneOf(current), OwnedDimensions: []agentv1.ResourceOwnedDimension{agentv1.ResourceOwnedDimension_RESOURCE_OWNED_DIMENSION_MANAGED_FILE_PRESENCE}}}
	p.journal = store
	p.config = Config{Native: &agentv1.NativeFileProviderConfig{KernelModuleBlocklist: true}, Platform: p.backend.Product, Ownership: owner, ActionID: id, ExecutorIncarnation: id, DeploymentID: id, DeviceID: id, EnrollmentGeneration: id}
	p.config.NativeObserve = func(context.Context, *resourcev1.ResourceDesiredState) (*agentv1.ResourceOwnershipSnapshot, error) {
		return proto.CloneOf(current), nil
	}
	p.config.ExecuteNative = func(ctx context.Context, request *agentv1.NativeResourceTransactionRequest, gate func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error) {
		if err := gate(ctx); err != nil {
			return nil, err
		}
		current = proto.CloneOf(request.Target)
		reported := proto.CloneOf(current)
		reported.ModuleInitramfsRebuildSucceeded = proto.Bool(true)
		return reported, nil
	}
	plan, err := p.Plan(t.Context(), desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil {
		t.Fatal(err)
	}
	gates := 0
	verification, err := p.Apply(t.Context(), plan, func(context.Context) error { gates++; return nil })
	if !errors.Is(err, ErrOutcomeUnknown) || verification.GetManagedFile().GetInitramfsMatches() || gates != 1 {
		t.Fatalf("stale release did not retain uncertainty: %v %v gates=%d", verification, err, gates)
	}
	if store.ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		t.Fatal("stale boot image permanently relinquished release custody")
	}
}

func archiveEntry(name string, content []byte, mode uint32) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x", 1, mode, 0, 0, 1, 0, len(content), 0, 0, 0, 0, len(name)+1, 0)
	b.WriteString(name)
	b.WriteByte(0)
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
	b.Write(content)
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
	return b.Bytes()
}

func TestInitramfsReadsBoundedNativeArchives(t *testing.T) {
	content := []byte("blacklist usb_storage\ninstall usb_storage /bin/false\n")
	directories := bytes.Join([][]byte{archiveEntry(".", nil, 0040755), archiveEntry("./etc", nil, 0040755), archiveEntry("etc/modprobe.d", nil, 0040755)}, nil)
	file := archiveEntry("etc/modprobe.d/99-lindm-blocklist.conf", content, 0100644)
	trailer := archiveEntry("TRAILER!!!", nil, 0)
	archive := bytes.Join([][]byte{directories, file, trailer}, nil)
	var gzipBytes bytes.Buffer
	gz := gzip.NewWriter(&gzipBytes)
	if _, err := gz.Write(archive); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	z, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	compressed := z.EncodeAll(archive, nil)
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	microcode := append(archiveEntry("kernel/x86/microcode/GenuineIntel.bin", []byte("fixture"), 0100644), archiveEntry("TRAILER!!!", nil, 0)...)
	safeAliases := bytes.Join([][]byte{directories, archiveEntry("lib", []byte("usr/lib"), 0120777), archiveEntry("etc/os-release", []byte("../usr/lib/os-release"), 0120777), file, trailer}, nil)
	for name, data := range map[string][]byte{"newc": archive, "gzip": gzipBytes.Bytes(), "zstd": compressed, "early-microcode": append(microcode, compressed...), "distro-symlinks": safeAliases} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "image")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			image, blocklist, err := initramfsBlocklist(path)
			if err != nil {
				t.Fatal(err)
			}
			wantImage, wantContent := sha256.Sum256(data), sha256.Sum256(content)
			if !bytes.Equal(image, wantImage[:]) || !bytes.Equal(blocklist, wantContent[:]) {
				t.Fatal("archive digest or embedded content differs")
			}
		})
	}
	for name, data := range map[string][]byte{
		"truncated":                 archive[:len(archive)-5],
		"symlink":                   bytes.Join([][]byte{directories, archiveEntry("etc/modprobe.d/99-lindm-blocklist.conf", []byte("/etc/shadow"), 0120777), trailer}, nil),
		"duplicate":                 bytes.Join([][]byte{directories, file, file, trailer}, nil),
		"interior-NUL":              bytes.Join([][]byte{directories, file, archiveEntry("etc/modprobe.d/99-lindm-blocklist.conf\x00junk", []byte("alternate"), 0100644), trailer}, nil),
		"noncanonical-parent":       bytes.Join([][]byte{directories, file, archiveEntry("etc/modprobe.d/../modprobe.d/99-lindm-blocklist.conf", []byte("alternate"), 0100644), trailer}, nil),
		"subtree-alias":             bytes.Join([][]byte{directories, file, archiveEntry("etc/modprobe.d/also", []byte("."), 0120777), archiveEntry("etc/modprobe.d/also/99-lindm-blocklist.conf", []byte("alternate"), 0100644), trailer}, nil),
		"parent-alias":              bytes.Join([][]byte{directories, file, archiveEntry("etc/also", []byte("modprobe.d"), 0120777), archiveEntry("etc/also/99-lindm-blocklist.conf", []byte("alternate"), 0100644), trailer}, nil),
		"forward-alias-traversal":   bytes.Join([][]byte{directories, file, archiveEntry("alias", []byte("later/../modprobe.d"), 0120777), archiveEntry("later", []byte("etc/other"), 0120777), archiveEntry("alias/99-lindm-blocklist.conf", []byte("alternate"), 0100644), trailer}, nil),
		"missing-parents":           bytes.Join([][]byte{file, trailer}, nil),
		"duplicate-across-archives": bytes.Join([][]byte{archive, archive}, nil),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "image")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := initramfsBlocklist(path); err == nil {
				t.Fatal("unsafe or incomplete archive accepted")
			}
		})
	}
}
