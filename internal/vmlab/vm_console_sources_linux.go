// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/config"
	"lindm/internal/devlab"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

// VMPackageSourceEvidence binds native observations to the actual server grant,
// authenticated executor results and resource rows. No package fixture is used.
type VMPackageSourceEvidence struct {
	Grant                    *adminv1.CapabilityPolicy               `json:"grant"`
	Capabilities             *adminv1.DeviceCapabilityState          `json:"capabilities"`
	Resources                *adminv1.GetDeviceResourceStateResponse `json:"resources"`
	Native                   []VMResourceNativeRecord                `json:"native"`
	UnregisteredCapabilities *adminv1.DeviceCapabilityState          `json:"unregistered_capabilities,omitempty"`
	UnregisteredResources    *adminv1.GetDeviceResourceStateResponse `json:"unregistered_resources,omitempty"`
	ReregisteredCapabilities *adminv1.DeviceCapabilityState          `json:"reregistered_capabilities,omitempty"`
	ReregisteredResources    *adminv1.GetDeviceResourceStateResponse `json:"reregistered_resources,omitempty"`
	Reregistration           *VMRedHatEvidence                       `json:"reregistration,omitempty"`
	ReregisteredAt           *timestamppb.Timestamp                  `json:"reregistered_at,omitempty"`
}

func proveRegistryPackageSources(ctx context.Context, vm *guestVM, release *platform.Release, device string, options VMConsoleEnrollmentOptions, registration *vmRedHatRegistration) (_ *VMPackageSourceEvidence, err error) {
	if release.Key != "debian-12" && release.Key != "debian-13" && release.Key != "rhel-9" && release.Key != "rhel-10" {
		return nil, errors.New("package-source proof requires Debian12/13 or RHEL9/10")
	}
	if len(release.VendorRepositories) == 0 {
		return nil, errors.New("release has no registry package source")
	}
	fixture := options.PackageSourceFixture
	owner, err := fixture.OpenOwnerSession(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err = errors.Join(err, owner.Close(cleanup))
	}()
	result := new(VMPackageSourceEvidence)
	defer func() {
		if err != nil {
			err = errors.Join(err, capturePackageSourceFailure(ctx, vm, options.DiagnosticsDir, result))
		}
	}()
	local, err := resourceOracle(ctx, vm, "no-local-package-provider", "sudo -n python3 -c "+nativeQuote("import json; d=json.load(open('/etc/lindm/executor.json')); assert not d.get('packageProvider') and not d.get('package_provider'); print('no-local-package-provider')"))
	if err != nil {
		return nil, err
	}
	result.Native = append(result.Native, local)
	public, err := captureSourcePublicPaths(ctx, vm, release)
	if err != nil {
		return nil, err
	}
	result.Native = append(result.Native, public)
	policies, err := owner.Admin.ListCapabilityPolicies(ctx, connect.NewRequest(&adminv1.ListCapabilityPoliciesRequest{}))
	if err != nil {
		return nil, err
	}
	revision := policies.Msg.GetDeployment().GetRevision()
	updated, err := owner.Admin.SetCapabilityPolicy(ctx, connect.NewRequest(&adminv1.SetCapabilityPolicyRequest{RequestId: uuid.NewString(), Scope: &adminv1.CapabilityPolicyScope{Scope: &adminv1.CapabilityPolicyScope_Deployment{Deployment: true}}, ExpectedRevision: revision, Capabilities: []agentv1.ManagementCapability{agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES}, Reason: "native registry-derived package-source qualification"}))
	if err != nil {
		return nil, err
	}
	result.Grant = updated.Msg.GetPolicy()
	if result.Grant.GetUpdatedAt() == nil {
		return nil, errors.New("requested capability grant has no authoritative update timestamp")
	}
	notBefore := result.Grant.GetUpdatedAt().AsTime()
	result.Capabilities, err = waitSourceCapability(ctx, owner, device, agentv1.CapabilityStatus_CAPABILITY_STATUS_ENABLED, "", notBefore)
	if err != nil {
		return nil, err
	}
	cursor, err := resourceOracle(ctx, vm, "protected-capability-at-assignment", "sudo -n "+guestLifecycleProbe+" guest capability-state")
	if err != nil {
		return nil, err
	}
	result.Native = append(result.Native, cursor)
	names := []string{"git", "htop"}
	if release.Lab.Entitlement {
		names = []string{"git"}
	}
	backend := release.Native().Packages.Backend
	ecosystem, arch, prefix := resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, "amd64", "deb/"
	repository := "apt/" + release.VendorRepositories[0].RepositoryID
	if backend == platform.BackendDNF4 {
		ecosystem, arch, prefix = resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, "x86_64", "rpm/"
		repository = "rpm/" + release.VendorRepositories[0].RepositoryID
	}
	// Stock preinstalled packages must not substitute for a provider install.
	absent := "set -eu; for name in git htop; do if dpkg-query -W -f='${db:Status-Status}' \"$name\" 2>/dev/null | /usr/bin/grep -qx installed; then exit 1; fi; done; printf 'git and htop absent before product assignment\\n'"
	if backend == platform.BackendDNF4 {
		absent = "if rpm -q git >/dev/null 2>&1; then exit 1; fi; printf 'git absent before product assignment\\n'"
	}
	baseline, err := resourceOracle(ctx, vm, "package-absent-baseline", absent)
	if err != nil {
		return nil, err
	}
	result.Native = append(result.Native, baseline)
	resources := make([]*policyv1.ProfileResource, 0, len(names))
	for _, name := range names {
		desired := &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: prefix + name + "/" + arch}, State: &resourcev1.ResourceDesiredState_NativePackage{NativePackage: &resourcev1.NativePackageDesired{Package: &resourcev1.PackageIdentity{Ecosystem: ecosystem, NativeName: name, Architecture: arch}, Presence: resourcev1.Presence_PRESENCE_PRESENT, Repository: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: repository}, Removal: resourcev1.PackageRemovalPolicy_PACKAGE_REMOVAL_POLICY_PRESERVE_DATA, Version: &resourcev1.NativePackageDesired_Any{Any: &resourcev1.AnyApprovedVersion{}}}}}
		resources = append(resources, &policyv1.ProfileResource{ResourceId: uuid.NewString(), Desired: desired, Ownership: resourceCreatePolicy(), Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 300, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}}})
	}
	published, err := owner.Admin.PublishProfileRevision(ctx, connect.NewRequest(&adminv1.PublishProfileRevisionRequest{RequestId: uuid.NewString(), ProfileId: uuid.NewString(), Reason: "real vendor git and htop package-source proof", Spec: &policyv1.ResourceProfile{Name: "Vendor package-source proof", Resources: resources}}))
	if err != nil {
		return nil, err
	}
	assigned, err := owner.Admin.SetResourceAssignment(ctx, connect.NewRequest(&adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: device, Target: &adminv1.ResourceAssignmentTarget{ProfileId: published.Msg.GetRevision().GetProfileId(), RevisionId: published.Msg.GetRevision().GetRevisionId()}, ReconcileIntervalSeconds: proto.Uint32(dispatchReconcileIntervalSeconds), Reason: "real vendor package-source proof"}))
	if err != nil {
		return nil, err
	}
	result.Resources, err = waitSourceRows(ctx, owner, device, assigned.Msg.GetAssignment().GetAssignmentId(), len(names), false, nil, time.Time{})
	if err != nil {
		return nil, err
	}
	query := "set -eu; dpkg-query -W -f='${Package} ${Version} ${Architecture} ${db:Status-Status}\\n' git htop; test \"$(dpkg-query -W -f='${db:Status-Status}' git)\" = installed; test \"$(dpkg-query -W -f='${db:Status-Status}' htop)\" = installed"
	if backend == platform.BackendDNF4 {
		query = "rpm -q --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}\\n' git"
	}
	native, err := resourceOracle(ctx, vm, "vendor-package-database", query)
	if err != nil {
		return nil, err
	}
	result.Native = append(result.Native, native)
	if backend == platform.BackendAPT {
		// Read the provider's retained isolated APT workspace, not the image's
		// unrelated system sources. Every pocket must have native InRelease.
		suites := release.VendorRepositories[0].Suites
		var quoted []string
		for _, suite := range suites {
			quoted = append(quoted, fmt.Sprintf("%q", suite))
		}
		code := "import pathlib,hashlib; root=pathlib.Path(" + fmt.Sprintf("%q", packaging.ExecutorStatePath+"/packageprovider") + "); suites=[" + strings.Join(quoted, ",") + "]; found=False\nfor path in root.glob('*/sources.list'):\n text=path.read_text(); indexes=list((path.parent/'lists').glob('*InRelease'))\n if all((' '+s+' ') in text and any(('_dists_'+s+'_InRelease') in p.name for p in indexes) for s in suites):\n  found=True; print(text.strip()); [print(p.name,hashlib.sha256(p.read_bytes()).hexdigest()) for p in indexes]\nassert found, 'provider has no native metadata for every official pocket'"
		pockets, err := resourceOracle(ctx, vm, "provider-native-official-apt-pockets", "sudo -n python3 -c "+nativeQuote(code))
		if err != nil {
			return nil, err
		}
		result.Native = append(result.Native, pockets)
	} else {
		key, err := resourceOracle(ctx, vm, "installed-rhel-release-key", "rpm -q redhat-release; sha256sum "+nativeQuote(release.VendorRepositories[0].KeyFile))
		if err != nil {
			return nil, err
		}
		result.Native = append(result.Native, key)
	}
	if registration != nil {
		ids := release.VendorRepositories[0].Entitled.NativeIDs["x86_64"]
		if len(ids) != 2 {
			return nil, errors.New("native official htop query requires both registry-entitled repositories")
		}
		var enabled string
		for _, id := range ids {
			enabled += " --enablerepo=" + nativeQuote(id)
		}
		var absence VMResourceNativeRecord
		absence, err = resourceOracle(ctx, vm, "htop-absent-official-entitled-repositories", "set -eu; output=$(sudo -n dnf -q --refresh --setopt=skip_if_unavailable=False --disablerepo='*'"+enabled+" repoquery --available --qf '%{name}' htop); test -z \"$output\"; printf 'htop absent from official entitled BaseOS/AppStream; only registry repositories selected\\n'")
		if err != nil {
			return nil, err
		}
		result.Native = append(result.Native, absence)
		if err := registration.Close(); err != nil {
			return nil, err
		}
		cursor, err = resourceOracle(ctx, vm, "protected-capability-after-unregister", "sudo -n "+guestLifecycleProbe+" guest capability-state")
		if err != nil {
			return nil, err
		}
		result.Native = append(result.Native, cursor)
		result.UnregisteredCapabilities, err = waitSourceCapability(ctx, owner, device, agentv1.CapabilityStatus_CAPABILITY_STATUS_UNAVAILABLE, "rhsm_registration_required", notBefore)
		if err != nil {
			return nil, err
		}
		result.UnregisteredResources, err = waitSourceRows(ctx, owner, device, assigned.Msg.GetAssignment().GetAssignmentId(), len(names), true, nil, time.Time{})
		if err != nil {
			return nil, err
		}
		if options.VerifyPackageRegistrationGate == nil {
			return nil, errors.New("RHEL package-source proof requires console registration-gate observation")
		}
		if err := options.VerifyPackageRegistrationGate(ctx, device); err != nil {
			return nil, err
		}
		result.Reregistration = new(VMRedHatEvidence)
		var reregistered *vmRedHatRegistration
		reregistered, err = registerVMRedHat(ctx, vm, options.RedHatTokenFile, result.Reregistration)
		if err != nil {
			return nil, err
		}
		result.ReregisteredAt = timestamppb.Now()
		defer func() {
			cleanupErr := reregistered.Close()
			err = errors.Join(err, cleanupErr, captureSourceRHSMCleanup(options.DiagnosticsDir, result.Reregistration, cleanupErr))
		}()
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		closeErr := owner.Close(cleanup)
		cancel()
		if closeErr != nil {
			return nil, closeErr
		}
		nextOwner, err := fixture.OpenOwnerSession(ctx)
		if err != nil {
			return nil, err
		}
		owner = nextOwner
		cursor, err = resourceOracle(ctx, vm, "protected-capability-after-register", "sudo -n "+guestLifecycleProbe+" guest capability-state")
		if err != nil {
			return nil, err
		}
		result.Native = append(result.Native, cursor)
		result.ReregisteredCapabilities, err = waitSourceCapability(ctx, owner, device, agentv1.CapabilityStatus_CAPABILITY_STATUS_ENABLED, "", notBefore)
		if err != nil {
			return nil, err
		}
		for _, state := range []*adminv1.DeviceCapabilityState{result.UnregisteredCapabilities, result.ReregisteredCapabilities} {
			if state.GetIssuedVersion() != result.Capabilities.GetIssuedVersion() || !bytes.Equal(state.GetReported().GetAppliedSha256(), result.Capabilities.GetReported().GetAppliedSha256()) {
				return nil, errors.New("RHSM registration transition changed the signed policy")
			}
		}
		result.ReregisteredResources, err = waitSourceRows(ctx, owner, device, assigned.Msg.GetAssignment().GetAssignmentId(), len(names), false, result.UnregisteredResources, result.ReregisteredAt.AsTime())
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func waitSourceCapability(ctx context.Context, owner *devlab.OwnerSession, device string, status agentv1.CapabilityStatus, detail string, notBefore time.Time) (*adminv1.DeviceCapabilityState, error) {
	// Preserve ordinary inventory admission: an immutable pending host ahead of
	// a changed capability can consume two five-minute admission windows.
	ctx, cancel := context.WithTimeout(ctx, 12*time.Minute)
	defer cancel()
	var last *adminv1.DeviceCapabilityState
	for {
		response, err := owner.Admin.GetDevice(ctx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: device}))
		if err != nil {
			return last, err
		}
		last = response.Msg.GetCapabilities()
		if sourceCapabilityMatches(last, status, detail, notBefore) {
			return last, nil
		}
		if err := lifecycleDelay(ctx, time.Second); err != nil {
			return last, fmt.Errorf("signed package capability did not reach %s/%s: %w; last=%s", status, detail, err, last)
		}
	}
}

func waitSourceRows(ctx context.Context, owner *devlab.OwnerSession, device, assignment string, count int, unregistered bool, previous *adminv1.GetDeviceResourceStateResponse, notBefore time.Time) (*adminv1.GetDeviceResourceStateResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	var last *adminv1.GetDeviceResourceStateResponse
	for {
		response, err := owner.Admin.GetDeviceResourceState(ctx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: device}))
		if err != nil {
			return last, err
		}
		last = response.Msg
		var settled bool
		if previous == nil {
			settled = sourceRowsSettled(last, assignment, count, unregistered)
		} else {
			settled = sourceRowsRetried(last, previous, assignment, count, notBefore)
		}
		if settled {
			return last, nil
		}
		if err := lifecycleDelay(ctx, time.Second); err != nil {
			return last, fmt.Errorf("vendor package rows did not settle (unregistered=%t): %w; last=%s", unregistered, err, last)
		}
	}
}

func sourceCapabilityMatches(state *adminv1.DeviceCapabilityState, status agentv1.CapabilityStatus, detail string, notBefore time.Time) bool {
	if state.GetIssuedAt() == nil || state.GetIssuedAt().AsTime().Before(notBefore) {
		return false
	}
	if state.GetIssuedVersion() == 0 || len(state.GetReported().GetAppliedSha256()) != 32 ||
		state.GetReported().GetAppliedVersion() != state.GetIssuedVersion() ||
		state.GetReported().GetState() != agentv1.CapabilityPolicyState_CAPABILITY_POLICY_STATE_ACTIVE {
		return false
	}
	deploymentGrant := false
	for _, grant := range state.GetGranted() {
		if grant.GetCapability() != agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES {
			continue
		}
		for _, source := range grant.GetSources() {
			deploymentGrant = deploymentGrant || source.GetDeployment()
		}
	}
	if !deploymentGrant {
		return false
	}
	for _, observed := range state.GetReported().GetCapabilities() {
		if observed.GetCapability() == agentv1.ManagementCapability_MANAGEMENT_CAPABILITY_PACKAGES {
			return observed.GetStatus() == status && observed.GetDetail() == detail
		}
	}
	return false
}

func sourceRowsSettled(state *adminv1.GetDeviceResourceStateResponse, assignment string, count int, unregistered bool) bool {
	if count == 0 || state.GetAssignment().GetAssignmentId() != assignment || len(state.GetResources()) != count {
		return false
	}
	for _, row := range state.GetResources() {
		if unregistered {
			registrationReason := row.GetReason() == "rhsm_registration_required" || row.GetReason() == "capability_packages_not_enabled"
			blocked := row.GetDisposition() == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_UNSUPPORTED || row.GetDisposition() == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_BLOCKED
			if !blocked || !registrationReason {
				return false
			}
			continue
		}
		action := row.GetLatestAction()
		compliant := row.GetCompliance() == adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_COMPLIANT || row.GetCompliance() == adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_DRIFT_REMEDIATED
		if row.GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_SUCCEEDED || !compliant ||
			row.GetLastVerifiedAt() == nil || action.GetAttestedAt() == nil || action.GetReceivedAt() == nil ||
			action.GetClosedReason() != "result" || action.GetStatus().GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED ||
			action.GetStatus().GetVerification().GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED {
			return false
		}
	}
	return true
}

// A released registration hold is not a retry. Require a new attested action
// beyond the last observed gate and verification strictly after registration.
func sourceRowsRetried(state, previous *adminv1.GetDeviceResourceStateResponse, assignment string, count int, notBefore time.Time) bool {
	if notBefore.IsZero() || previous.GetAssignment().GetAssignmentId() != assignment || len(previous.GetResources()) != count ||
		!sourceRowsSettled(state, assignment, count, false) {
		return false
	}
	for _, row := range state.GetResources() {
		var before *adminv1.ResourceState
		for _, candidate := range previous.GetResources() {
			if candidate.GetResourceId() != "" && candidate.GetResourceId() == row.GetResourceId() {
				before = candidate
				break
			}
		}
		action := row.GetLatestAction()
		old := before.GetLatestAction()
		if before == nil || old.GetActionId() == "" || old.GetResourceSequence() == 0 ||
			action.GetActionId() == "" || action.GetActionId() == old.GetActionId() ||
			action.GetResourceSequence() <= old.GetResourceSequence() ||
			!row.GetLastVerifiedAt().AsTime().After(notBefore) || !action.GetAttestedAt().AsTime().After(notBefore) {
			return false
		}
	}
	return true
}

func capturePackageSourceFailure(ctx context.Context, vm *guestVM, diagnostics string, evidence *VMPackageSourceEvidence) error {
	if diagnostics == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	cursor, cursorErr := resourceOracle(ctx, vm, "protected-capability-at-failure", "sudo -n "+guestLifecycleProbe+" guest capability-state")
	if cursorErr == nil {
		evidence.Native = append(evidence.Native, cursor)
	}
	journal, journalErr := resourceOracle(ctx, vm, "package-agent-and-executor-failure-journal", "sudo -n journalctl --no-pager -u lindm-agent -u lindm-executor -u 'lindm-package-*' -n 1500 -o short-iso-precise")
	if journalErr == nil {
		evidence.Native = append(evidence.Native, journal)
	}
	data, err := json.Marshal(struct {
		Phase    string                   `json:"phase"`
		Evidence *VMPackageSourceEvidence `json:"evidence"`
	}{"registry-package-source-proof-failure", evidence})
	if err != nil {
		return errors.Join(cursorErr, journalErr, err)
	}
	_, err = saveGuestDiagnostics(diagnostics, data)
	return errors.Join(cursorErr, journalErr, err)
}

func captureSourceRHSMCleanup(diagnostics string, evidence *VMRedHatEvidence, cleanupErr error) error {
	data, err := json.Marshal(struct {
		Phase    string            `json:"phase"`
		Evidence *VMRedHatEvidence `json:"evidence"`
		Failed   bool              `json:"failed"`
	}{"registry-package-source-rhsm-cleanup", evidence, cleanupErr != nil})
	if err != nil {
		return err
	}
	_, err = saveGuestDiagnostics(diagnostics, data)
	return err
}

func captureSourcePublicPaths(ctx context.Context, vm *guestVM, release *platform.Release) (VMResourceNativeRecord, error) {
	key := release.VendorRepositories[0].KeyFile
	publicPaths := make([]string, 0, 12)
	publicPaths = append(publicPaths, key, "/etc/issue.d", "/etc/motd.d")
	for parent := filepath.Dir(key); ; parent = filepath.Dir(parent) {
		publicPaths = append(publicPaths, parent)
		if parent == "/" {
			break
		}
	}
	if release.Native().Packages.Backend == platform.BackendAPT && key != "/usr/share/keyrings/debian-archive-keyring.gpg" {
		publicPaths = append(publicPaths, "/usr/share/keyrings/debian-archive-keyring.gpg")
	}
	paths, err := json.Marshal(publicPaths)
	if err != nil {
		return VMResourceNativeRecord{}, err
	}
	configs, err := json.Marshal([]string{config.ExecutorConfigPath, config.NetworkConfigPath})
	if err != nil {
		return VMResourceNativeRecord{}, err
	}
	code := "import pathlib,os,json,hashlib; paths=" + string(paths) + "; configs=" + string(configs) + "; key=" + fmt.Sprintf("%q", key) + "\nfor path in paths:\n try:\n  s=os.lstat(path); print(json.dumps(dict(path=path,mode=oct(s.st_mode),uid=s.st_uid,gid=s.st_gid,nlink=s.st_nlink,size=s.st_size,link=os.readlink(path) if pathlib.Path(path).is_symlink() else None)))\n except FileNotFoundError: print(json.dumps(dict(path=path,missing=True)))\nprint(json.dumps(dict(key=key,sha256=hashlib.sha256(pathlib.Path(key).read_bytes()).hexdigest())))\nfor path in configs:\n d=json.loads(pathlib.Path(path).read_text()); allowed={'state_directory','runtime_directory','spool_directory','socket_name','stateDirectory','runtimeDirectory','spoolDirectory','socketName'}; print(json.dumps(dict(config=path,paths={k:v for k,v in d.items() if k in allowed})))\n"
	if release.Native().Packages.Backend == platform.BackendAPT {
		code += "import subprocess,tempfile\nwith tempfile.TemporaryDirectory(prefix='lindm-public-key-') as directory:\n r=subprocess.run(['gpg','--batch','--no-options','--homedir',directory,'--with-colons','--import-options','show-only','--import',key],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE); print(json.dumps(dict(fingerprints=[row.split(':')[9] for row in r.stdout.decode().splitlines() if row.startswith('fpr:')])))\n"
	}
	return resourceOracle(ctx, vm, "public-vendor-key-and-config-custody", "sudo -n python3 -c "+nativeQuote(code))
}

// Capture only the two public official definitions. Credential contents never
// leave the guest; certificate serials are consistently replaced in path names.
func captureSourceRHSMFixture(ctx context.Context, vm *guestVM, release *platform.Release, diagnostics string) error {
	if diagnostics == "" {
		return errors.New("RHEL package-source proof requires a private diagnostics directory")
	}
	entitled := release.VendorRepositories[0].Entitled
	if entitled == nil || len(entitled.NativeIDs["x86_64"]) != 2 {
		return errors.New("RHEL proof requires the exact registry-entitled source")
	}
	ids, err := json.Marshal(entitled.NativeIDs["x86_64"])
	if err != nil {
		return err
	}
	code := "import pathlib,re,urllib.parse; wanted=" + string(ids) + "; selected=False; out=[]\nfor line in pathlib.Path(" + fmt.Sprintf("%q", entitled.File) + ").read_text().splitlines():\n if line.startswith('['): selected=line[1:-1] in wanted\n if not selected: continue\n if '=' in line and not line.lstrip().startswith(('#',';')):\n  k,v=line.split('=',1); key=k.strip().lower()\n  if any(x in key for x in ['password','username','proxy']): continue\n  if key in ['sslclientcert','sslclientkey']: line=k+' = '+re.sub(r'/[0-9]+(-key)?[.]pem$', lambda m:'/10101'+('-key' if '-key' in m.group() else '')+'.pem',v.strip())\n  if key in ['baseurl','metalink','mirrorlist']:\n   u=urllib.parse.urlsplit(v.strip()); assert not u.username and not u.password and not u.query\n out.append(line)\nassert all('['+i+']' in out for i in wanted)\nprint('\\n'.join(out))"
	observed, err := resourceOracle(ctx, vm, "registered-rhsm-public-stanzas-redacted-paths", "sudo -n python3 -c "+nativeQuote(code))
	if err != nil {
		return err
	}
	data, err := json.Marshal(observed)
	if err != nil {
		return err
	}
	_, err = saveGuestDiagnostics(diagnostics, data)
	return err
}
