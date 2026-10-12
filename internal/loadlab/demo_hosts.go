package loadlab

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
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
	// sessions counts local graphical logins, or SSH logins on a headless host.
	// Session inventory is complete: a desktop with none shows its login screen.
	sessions uint64
	headless bool
	// assistance is the executor setting reported with every assistance sync;
	// UNSPECIFIED models an agent that predates the report.
	assistance        agentv1.AssistancePolicy
	encryption        encryptionState
	service           serviceOutcome
	department        string // provisioning token name in lab/demo/org.json
	provisioningToken string // cleared after enrollment; never evidence
	historical        bool
	proposal          bool // carries the pending advisory risk-acceptance proposal
	bulk              int  // synthetic scale packages beside the captured baseline
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

func rpm(name, version string) *inventoryv1.Package {
	return &inventoryv1.Package{Name: name, Version: version, Architecture: "x86_64", Manager: string(platform.PackageDBRPM)}
}

const (
	assistanceOn  = agentv1.AssistancePolicy_ASSISTANCE_POLICY_ENABLED
	assistanceOff = agentv1.AssistancePolicy_ASSISTANCE_POLICY_DISABLED
)

// demoDevices returns the deterministic fleet in enrollment order. Index 0
// is the richest device; the pending enrollment is provisioned separately.
// Operating systems are registry rows, never os-release literals.
func demoDevices(source string) ([]*demoDevice, error) {
	raw, err := os.ReadFile(filepath.Join(source, "internal", "advisory", "testdata", "rhel98-platform.json"))
	if err != nil {
		return nil, err
	}
	el := new(inventoryv1.PlatformDetails)
	if err := protojson.Unmarshal(raw, el); err != nil {
		return nil, err
	}
	devices := []*demoDevice{
		{hostname: "ubuntu-ws-01", key: "ubuntu-24.04", kernel: "6.8.0-90-generic", sessions: 1, assistance: assistanceOn, encryption: encryptionLUKS, service: serviceConverged, department: "engineering", labels: []string{"workstation"}, bulk: demoRoutePackages},
		// An older agent: it does not report its assistance setting, which is off.
		{hostname: "ubuntu-ws-02", key: "ubuntu-24.04", kernel: "6.8.0-90-generic", sessions: 1, encryption: encryptionNone, service: serviceApplies, department: "engineering", labels: []string{"workstation"}, proposal: true},
		{hostname: "fedora-ws-03", key: "fedora-44", kernel: "6.17.1-300.fc44.x86_64", sessions: 1, assistance: assistanceOn, encryption: encryptionLUKS, service: serviceConverged, department: "finance", labels: []string{"workstation"}},
		{hostname: "ubuntu-srv-04", key: "ubuntu-24.04", kernel: "6.8.0-142-generic", headless: true, assistance: assistanceOff, encryption: encryptionUnknown, service: serviceFails, department: "it-helpdesk", labels: []string{"server", "build"}},
		// The owner's report: a headless RHEL server, assistance off, an admin on SSH.
		{hostname: "rhel-srv-05", key: "rhel-9", versionID: "9.8", kernel: "5.14.0-687.5.3.el9_8.x86_64", sessions: 1, headless: true, assistance: assistanceOff, encryption: encryptionNone, service: serviceApplies, department: "finance", labels: []string{"server", "database"}, platform: el},
		{hostname: "ubuntu-kiosk-06", key: "ubuntu-24.04", kernel: "6.8.0-90-generic", sessions: 1, assistance: assistanceOn, encryption: encryptionUnknown, service: serviceConverged, department: "contractors", labels: []string{"kiosk", "lobby"}, state: "stale"},
		{hostname: "fedora-ws-07", key: "fedora-44", kernel: "6.17.1-300.fc44.x86_64", assistance: assistanceOn, encryption: encryptionNone, department: "contractors", labels: []string{"workstation", "retired"}, state: "revoked"},
		{hostname: "ubuntu-ws-08", key: "ubuntu-24.04", kernel: "6.8.0-142-generic", sessions: 1, encryption: encryptionNone, department: "it-helpdesk", labels: []string{"workstation", "support"}, historical: true},
		{hostname: demoScaleHostname, key: "fedora-44", kernel: "6.17.1-300.fc44.x86_64", headless: true, assistance: assistanceOff, encryption: encryptionLUKS, department: "it-helpdesk", labels: []string{"server", "ci-runner", "gpu"}, bulk: demoScalePackages},
		// A new Engineering laptop that has not reported inventory: Engineering
		// tools' platform-limited package rows wait for its facts.
		{hostname: "ubuntu-ws-09", key: "ubuntu-24.04", kernel: "6.8.0-90-generic", sessions: 1, encryption: encryptionLUKS, service: serviceConverged, department: "engineering", labels: []string{"workstation", "new-hire"}, state: "awaiting-inventory", factsWithheld: true},
	}
	baselines := make(map[string][]*inventoryv1.Package)
	inventories := make(map[string]packageData)
	for i, device := range devices {
		var ok bool
		if device.release, ok = platform.Lookup(device.key); !ok {
			return nil, fmt.Errorf("load: demo release %s is not registered", device.key)
		}
		if device.versionID == "" {
			device.versionID = device.release.Version.Value
		}
		device.backend = string(device.release.Native().Packages.Backend.PackageDB())
		baseline, ok := baselines[device.key]
		if !ok {
			raw, err := os.ReadFile(filepath.Join(source, "lab", "demo", device.key+"-packages.json"))
			if err != nil {
				return nil, err
			}
			batch := new(inventoryv1.PackageBatch)
			if err := protojson.Unmarshal(raw, batch); err != nil {
				return nil, err
			}
			baseline = batch.GetPackages()
			baselines[device.key] = baseline
		}
		// Captured baselines are shared per release; scale devices add labelled
		// synthetic packages that no vendor feed claims.
		inventory := device.key
		if device.bulk > 0 {
			inventory = device.hostname
			manager := "rpm"
			if device.backend == string(platform.PackageDBDpkg) {
				manager = "dpkg"
			}
			baseline = slices.Concat(baseline, bulkPackages(manager, device.bulk))
		}
		data, ok := inventories[inventory]
		if !ok {
			var err error
			if data, err = packages(len(baseline), baseline); err != nil {
				return nil, err
			}
			inventories[inventory] = data
		}
		device.packages = data
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
	host.Details.Sessions = s.sessionInventory()
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

// sessionInventory is a complete logind session list, so the server can tell a
// desktop (a user's Wayland login, or its login screen) from a headless host.
func (s *demoDevice) sessionInventory() *inventoryv1.SessionCounts {
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	session := func(user, class, kind string, remote bool) *inventoryv1.ActiveSession {
		seat := observed("seat0")
		if remote {
			seat = &inventoryv1.ObservedString{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE}
		}
		return &inventoryv1.ActiveSession{UserName: observed(user), SessionClass: observed(class), SessionType: observed(kind), Seat: seat, Remote: &inventoryv1.ObservedBool{Status: success, Value: remote}}
	}
	active := &inventoryv1.ActiveSessions{Status: success}
	for range s.sessions {
		if s.headless {
			active.Sessions = append(active.Sessions, session("admin", "user", "tty", true))
		} else {
			active.Sessions = append(active.Sessions, session("demo", "user", "wayland", false))
		}
	}
	if !s.headless && s.sessions == 0 {
		active.Sessions = append(active.Sessions, session("gdm", "greeter", "wayland", false))
	}
	count := func() *inventoryv1.ObservedUint64 {
		return &inventoryv1.ObservedUint64{Status: success, Value: uint64(len(active.Sessions))}
	}
	return &inventoryv1.SessionCounts{Users: count(), Sessions: count(), ActiveSessions: active}
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
		simulateServiceState(observation.GetSystemdService(), desired.GetSystemdService())
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

// simulateServiceState is synthetic executor evidence, never native observation.
func simulateServiceState(observed *resourcev1.SystemdServiceObservation, desired *resourcev1.SystemdServiceDesired) {
	observed.ActiveState = "inactive"
	if desired.GetRuntime() == resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE {
		observed.ActiveState = "active"
	}
	switch desired.GetEnablement() {
	case resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED:
		observed.UnitFileState = "enabled"
	case resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED:
		observed.UnitFileState = "disabled"
	}
}
