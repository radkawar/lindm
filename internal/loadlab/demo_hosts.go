package loadlab

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/platform"
	"lindm/internal/resource"
)

// serviceOutcome is the simulated executor's genuine result kind for an
// assigned systemd service. Other kinds are answered from host evidence.
type serviceOutcome uint8

const (
	// serviceApplies starts and converges the unit: drift remediated.
	serviceApplies serviceOutcome = iota
	// serviceConverged finds the unit already converged: read-only compliance.
	serviceConverged
	// serviceFails starts the unit, which reports a native failure.
	serviceFails
)

type encryptionState uint8

const (
	encryptionUnknown encryptionState = iota
	encryptionNone
	encryptionLUKS
)

// demoDevice is one deterministic synthetic host. Values are plain data; the
// simulated executor has no native providers, so kinds it cannot observe are
// refused as unsupported rather than reported compliant.
type demoDevice struct {
	hostname, kernel string
	// key names the platform registry row; versionID overrides its VERSION_ID.
	key, versionID string
	release        *platform.Release
	state          string // enrolled, awaiting-inventory, stale or revoked once seeded
	sessions       uint64
	encryption     encryptionState
	service        serviceOutcome
	profile        int // index into demoProfiles; -1 is unassigned
	historical     bool
	proposal       bool // carries the advisory risk-acceptance proposal; needs a complete feed
	// factsWithheld never reports host inventory, so platform-limited items
	// wait for its facts while unrestricted items still apply.
	factsWithheld bool
	labels        []string
	platform      *inventoryv1.PlatformDetails
	backend       string
	packages      packageData
	serial, luks  string
}

func dpkg(name, version, source, sourceVersion string) *inventoryv1.Package {
	return &inventoryv1.Package{Name: name, Version: version, Architecture: "amd64", Manager: string(platform.PackageDBDpkg), SourceName: source, SourceVersion: sourceVersion}
}

func rpm(name, version string, module bool) *inventoryv1.Package {
	p := &inventoryv1.Package{Name: name, Version: version, Architecture: "x86_64", Manager: string(platform.PackageDBRPM)}
	if module {
		p.Module = &inventoryv1.ModuleObservation{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS}
	}
	return p
}

// Affected versions match the checked-in vendor feed fixtures served by
// devlab.ConfigureConsoleDemo: USN-6859-1, DSA-5724-1, FEDORA sudo and
// RHSA-2024:6783. Only the Fedora source is complete, so only Fedora's sudo
// 0:1.9.17-7.p2.fc44 (fixed 0:1.9.17-10.p2.fc44) evaluates AFFECTED; the
// others' matches stay UNKNOWN under partial coverage.
func ubuntuPackages(openssh string) []*inventoryv1.Package {
	return []*inventoryv1.Package{
		dpkg("base-files", "13ubuntu10.3", "base-files", "13ubuntu10.3"), dpkg("bash", "5.2.21-2ubuntu4", "bash", "5.2.21-2ubuntu4"),
		dpkg("coreutils", "9.4-3ubuntu6", "coreutils", "9.4-3ubuntu6"), dpkg("cups", "2.4.7-1.2ubuntu7.4", "cups", "2.4.7-1.2ubuntu7.4"),
		dpkg("curl", "8.5.0-2ubuntu10.6", "curl", "8.5.0-2ubuntu10.6"), dpkg("libc6", "2.39-0ubuntu8.6", "glibc", "2.39-0ubuntu8.6"),
		dpkg("openssh-client", openssh, "openssh", openssh), dpkg("openssh-server", openssh, "openssh", openssh),
		dpkg("openssl", "3.0.13-0ubuntu3.6", "openssl", "3.0.13-0ubuntu3.6"), dpkg("sudo", "1.9.15p5-3ubuntu5.24.04.1", "sudo", "1.9.15p5-3ubuntu5.24.04.1"),
		dpkg("systemd", "255.4-1ubuntu8.10", "systemd", "255.4-1ubuntu8.10"),
	}
}

func debianPackages(openssh string) []*inventoryv1.Package {
	return []*inventoryv1.Package{
		dpkg("base-files", "12.4+deb12u11", "base-files", "12.4+deb12u11"), dpkg("bash", "5.2.15-2+b8", "bash", "5.2.15-2"),
		dpkg("coreutils", "9.1-1", "coreutils", "9.1-1"), dpkg("curl", "7.88.1-10+deb12u12", "curl", "7.88.1-10+deb12u12"),
		dpkg("libc6", "2.36-9+deb12u10", "glibc", "2.36-9+deb12u10"), dpkg("openssh-client", openssh, "openssh", openssh),
		dpkg("openssh-server", openssh, "openssh", openssh), dpkg("openssl", "3.0.16-1~deb12u1", "openssl", "3.0.16-1~deb12u1"),
		dpkg("sudo", "1.9.13p3-1+deb12u1", "sudo", "1.9.13p3-1+deb12u1"), dpkg("systemd", "252.38-1~deb12u1", "systemd", "252.38-1~deb12u1"),
	}
}

func fedoraPackages() []*inventoryv1.Package {
	return []*inventoryv1.Package{
		rpm("bash", "0:5.3.0-2.fc44", false), rpm("coreutils", "0:9.7-5.fc44", false), rpm("cups", "1:2.5.0-3.fc44", false),
		rpm("curl", "0:8.15.0-2.fc44", false), rpm("glibc", "0:2.42-4.fc44", false), rpm("kernel", "0:6.17.1-300.fc44", false),
		rpm("openssh-server", "0:10.0p1-5.fc44", false), rpm("openssl-libs", "1:3.5.1-2.fc44", false),
		rpm("sudo", "0:1.9.17-7.p2.fc44", false), rpm("systemd", "0:258.1-1.fc44", false),
	}
}

func rhelPackages() []*inventoryv1.Package {
	return []*inventoryv1.Package{
		rpm("audit", "0:3.1.2-2.el9", true), rpm("bash", "0:5.1.8-9.el9", true), rpm("coreutils", "0:8.32-36.el9", true),
		rpm("curl", "0:7.76.1-29.el9_4", true), rpm("glibc", "0:2.34-100.el9_4.2", true), rpm("kernel", "0:5.14.0-427.13.1.el9_4", true),
		rpm("openssh-server", "0:8.7p1-38.el9_4.1", true), rpm("openssl-libs", "1:3.0.7-27.el9_4", true),
		rpm("sudo", "0:1.9.5p2-10.el9_3", true), rpm("systemd", "0:252-32.el9_4", true),
	}
}

// demoDevices returns the deterministic fleet in enrollment order. Index 0
// is the richest device; the pending enrollment is provisioned separately.
// Operating systems are registry rows, never os-release literals.
func demoDevices() ([]*demoDevice, error) {
	el9, ok := platform.Lookup("rhel-9")
	if !ok {
		return nil, errors.New("load: demo release rhel-9 is not registered")
	}
	// An entitled standard-stream host; its CPE is the registry's advisory product.
	el := &inventoryv1.PlatformDetails{
		Cpe:            observed(el9.Advisory.Ecosystem + "::baseos"),
		ReleaseverLock: &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE},
		Repositories:   &inventoryv1.RepositoryObservation{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, Backend: string(el9.Packages.Backend), Ids: []string{"rhel-9-for-x86_64-appstream-rpms", "rhel-9-for-x86_64-baseos-rpms"}},
	}
	devices := []*demoDevice{
		{hostname: "ubuntu-ws-01", key: "ubuntu-24.04", kernel: "6.8.0-90-generic", sessions: 1, encryption: encryptionLUKS, service: serviceConverged, profile: 0, labels: []string{"workstation", "engineering"}},
		{hostname: "ubuntu-ws-02", key: "ubuntu-24.04", kernel: "6.8.0-90-generic", sessions: 1, encryption: encryptionNone, service: serviceApplies, profile: 0, labels: []string{"workstation", "engineering"}},
		{hostname: "fedora-ws-03", key: "fedora-44", kernel: "6.17.1-300.fc44.x86_64", sessions: 1, encryption: encryptionLUKS, service: serviceConverged, profile: 0, labels: []string{"workstation", "design"}, proposal: true},
		{hostname: "debian-srv-04", key: "debian-12", kernel: "6.1.0-37-amd64", encryption: encryptionUnknown, service: serviceFails, profile: 1, labels: []string{"server", "build"}},
		{hostname: "rhel-srv-05", key: "rhel-9", versionID: "9.4", kernel: "5.14.0-427.13.1.el9_4.x86_64", encryption: encryptionNone, service: serviceApplies, profile: 1, labels: []string{"server", "database"}, platform: el},
		{hostname: "ubuntu-kiosk-06", key: "ubuntu-24.04", kernel: "6.8.0-90-generic", sessions: 1, encryption: encryptionUnknown, service: serviceConverged, profile: 2, labels: []string{"kiosk", "lobby"}, state: "stale"},
		{hostname: "fedora-ws-07", key: "fedora-44", kernel: "6.17.1-300.fc44.x86_64", encryption: encryptionNone, profile: -1, labels: []string{"workstation", "retired"}, state: "revoked"},
		{hostname: "debian-ws-08", key: "debian-12", kernel: "6.1.0-37-amd64", sessions: 1, encryption: encryptionNone, profile: -1, labels: []string{"workstation", "support"}, historical: true},
		{hostname: demoScaleHostname, key: "fedora-44", kernel: "6.17.1-300.fc44.x86_64", encryption: encryptionLUKS, profile: -1, labels: []string{"server", "ci-runner", "gpu"}},
		{hostname: "ubuntu-ws-09", key: "ubuntu-24.04", kernel: "6.8.0-90-generic", sessions: 1, encryption: encryptionLUKS, service: serviceConverged, profile: 0, labels: []string{"workstation", "new-hire"}, state: "awaiting-inventory", factsWithheld: true},
	}
	inventories := [][]*inventoryv1.Package{
		slices.Concat(ubuntuPackages("1:9.6p1-3ubuntu13"), bulkPackages("dpkg", demoRoutePackages)), ubuntuPackages("1:9.6p1-3ubuntu13.19"), fedoraPackages(), debianPackages("1:9.2p1-2+deb12u2"),
		rhelPackages(), ubuntuPackages("1:9.6p1-3ubuntu13.19"), fedoraPackages(), debianPackages("1:9.2p1-2+deb12u3"),
		slices.Concat(fedoraPackages(), affectedPackages(), bulkPackages("rpm", demoScalePackages)),
		ubuntuPackages("1:9.6p1-3ubuntu13.19"),
	}
	for i, device := range devices {
		if device.release, ok = platform.Lookup(device.key); !ok {
			return nil, fmt.Errorf("load: demo release %s is not registered", device.key)
		}
		if device.versionID == "" {
			device.versionID = device.release.Version.Value
		}
		device.backend = string(device.release.Native().Packages.Backend.PackageDB())
		var err error
		if device.packages, err = packages(len(inventories[i]), inventories[i]); err != nil {
			return nil, err
		}
		if device.state == "" {
			device.state = "enrolled"
		}
		device.serial, device.luks = fmt.Sprintf("DEMO%04d%08X", i+1, uuid.New().ID()), uuid.NewString()
	}
	return devices, nil
}

// observation is this host's synthetic report, labelled exactly as the
// capacity simulator labels hardware, or the captured historical replay.
func (s *demoDevice) observation(historical *inventoryv1.HostObservation, boot string, now *timestamppb.Timestamp) *inventoryv1.HostObservation {
	if s.historical && historical != nil {
		return historical
	}
	host := &inventoryv1.HostObservation{StartedAt: now, FinishedAt: now, BootId: observed(boot), Hostname: observed(s.hostname), OsId: observed(s.release.ID), OsVersion: observed(s.versionID), Architecture: observed("x86_64"), KernelRelease: observed(s.kernel), HardwareVendor: observed("Lindm capacity simulator"), HardwareModel: observed("Synthetic, not native inventory"), HardwareSerial: observed(s.serial)}
	host.Details = syntheticNativeDetails()
	host.Details.Sessions.Users.Value, host.Details.Sessions.Sessions.Value = s.sessions, s.sessions
	host.Details.Platform = s.platform
	if s.encryption == encryptionUnknown {
		return host
	}
	const disk, root = 512110190592, 510962909184
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	block := func(name, kind, parent, filesystem, mountpoint, encryption, luks string, size uint64, rootBacking bool) *inventoryv1.BlockDevice {
		text := func(value string) *inventoryv1.ObservedString {
			if value == "" {
				return &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE}
			}
			return observed(value)
		}
		number := &inventoryv1.ObservedUint64{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE}
		return &inventoryv1.BlockDevice{Name: name, Type: observed(kind), Parent: text(parent), SizeBytes: &inventoryv1.ObservedUint64{Status: success, Value: size}, Filesystem: text(filesystem), Mountpoint: text(mountpoint), Encryption: observed(encryption), Identity: &inventoryv1.StorageIdentity{
			Transport: observed("nvme"), Model: observed("Synthetic NVMe, not native"), Serial: observed(s.serial), Firmware: observed("1.0"), Wwn: observed("eui." + s.serial), Eui: text(""),
			PartitionUuid: text(""), PartitionType: text(""), FilesystemUuid: text(""), LuksUuid: text(luks), LuksVersion: text(""),
			LuksKeyslotCount: number, LuksTokenCount: number, LuksTokenTypes: text(""), BackingDisk: observed("nvme0n1"),
			RootBacking: &inventoryv1.ObservedBool{Status: success, Value: rootBacking}, Nvme: &inventoryv1.ObservedNVMeScope{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE}, GptDiskGuid: text(""),
		}}
	}
	devices := []*inventoryv1.BlockDevice{block("nvme0n1", "disk", "", "", "", "none", "", disk, false), block("nvme0n1p1", "part", "nvme0n1", "vfat", "/boot/efi", "none", "", 1073741824, false)}
	if s.encryption == encryptionLUKS {
		container := block("nvme0n1p2", "part", "nvme0n1", "crypto_LUKS", "", "luks", s.luks, root, true)
		container.Identity.LuksVersion = observed("2")
		devices = append(devices, container, block("luks-"+s.luks, "crypt", "nvme0n1p2", "ext4", "/", "dm-crypt", "", root-16777216, true))
	} else {
		devices = append(devices, block("nvme0n1p2", "part", "nvme0n1", "ext4", "/", "none", "", root, true))
	}
	host.Details.Storage = &inventoryv1.StorageDetails{Status: success, Devices: devices}
	return host
}

// immediateResult is the simulated executor's terminal answer for intents
// it settles without start authority: read-only systemd and encryption
// compliance findings, or an admission refusal for kinds it cannot observe.
// Nil means the intent proceeds through the normal start protocol.
func (s *demoDevice) immediateResult(intent *agentv1.ResourceExecutionIntent, intentDigest []byte, service *resourcev1.ResourceObservation) (*agentv1.ResourceExecutionStatus, error) {
	desired := intent.GetDesired()
	accepted := service.GetMetadata().GetObservedAt()
	status := &agentv1.ResourceExecutionStatus{ActionId: intent.GetActionId(), IntentSha256: intentDigest, State: agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED, AcceptedAt: accepted, CompletedAt: accepted}
	verification := new(resourcev1.ResourceVerification)
	var observation *resourcev1.ResourceObservation
	switch {
	case desired.GetSystemdService() != nil:
		if s.service != serviceConverged {
			return nil, nil
		}
		observation = proto.CloneOf(service)
		observation.GetSystemdService().ActiveState = "active"
		verification.Disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED
		verification.Checks = &resourcev1.ResourceVerification_SystemdService{SystemdService: &resourcev1.SystemdServiceChecks{Observation: proto.CloneOf(observation.GetSystemdService()), RuntimeMatches: true, EnablementMatches: true, DefinitionMatches: true, JobCompleted: true, Converged: true}}
	case desired.GetEncryptionCompliance() != nil:
		observation = &resourcev1.ResourceObservation{Ref: desired.GetRef(), Metadata: proto.CloneOf(service.GetMetadata())}
		observation.Metadata.Backend.Backend = resourcev1.Backend_BACKEND_LUKS_COMPLIANCE
		evidence := sha256.Sum256([]byte(s.serial + s.luks))
		compliance := &resourcev1.EncryptionComplianceObservation{EvidenceSha256: evidence[:]}
		checks := &resourcev1.EncryptionComplianceChecks{EscrowRequirementMet: true, TpmRequirementMet: true, EvidenceComplete: true}
		verification.Disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED
		switch s.encryption {
		case encryptionLUKS:
			compliance.LuksRoot, compliance.RootLuksUuid, compliance.RootIdentityBasis = proto.Bool(true), proto.String(s.luks), resourcev1.RootStorageIdentityBasis_ROOT_STORAGE_IDENTITY_BASIS_WWN_SERIAL
			compliance.RootWwn, compliance.RootSerial, compliance.RootSizeBytes = "eui."+s.serial, s.serial, 510962909184
			checks.LuksRootRequirementMet, checks.Converged = true, true
			verification.Disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED
		case encryptionNone:
			compliance.LuksRoot = proto.Bool(false)
		default:
			observation.Metadata.ObservationStatus = resourcev1.ObservationStatus_OBSERVATION_STATUS_UNAVAILABLE
			checks.EvidenceComplete = false
			verification.Disposition = resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_UNKNOWN
		}
		observation.Observed = &resourcev1.ResourceObservation_EncryptionCompliance{EncryptionCompliance: compliance}
		verification.Checks = &resourcev1.ResourceVerification_EncryptionCompliance{EncryptionCompliance: checks}
	default:
		status.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_UNSUPPORTED
		status.AdmissionRefusal = &agentv1.ResourceAdmissionRefusal{Ref: desired.GetRef(), Operation: intent.GetOperation(), Reason: agentv1.ResourceAdmissionRefusalReason_RESOURCE_ADMISSION_REFUSAL_REASON_UNSUPPORTED_NATIVE, BootId: service.GetMetadata().GetBootId(), ExecutorIncarnation: service.GetMetadata().GetExecutorIncarnation(), NativeEvidenceUnavailable: true}
		return status, nil
	}
	desiredDigest, err := resource.DesiredDigest(desired)
	if err != nil {
		return nil, err
	}
	observed, err := resource.ObservationDigest(observation)
	if err != nil {
		return nil, err
	}
	verification.Ref, verification.DesiredSha256, verification.PlanSha256, verification.After = desired.GetRef(), desiredDigest[:], observed[:], proto.CloneOf(observation)
	status.Before, status.Verification, status.ReadOnly = observation, verification, true
	status.Failure = agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_POSTCONDITION
	if verification.GetDisposition() == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED {
		status.State, status.Failure = agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED, agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_NONE
	}
	return status, nil
}
