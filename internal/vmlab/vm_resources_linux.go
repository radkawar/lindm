//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/platform"
)

// resourceDispatch uses real immutable profiles, assignment CAS, online signer,
// relay, installed executor and authenticated result ingestion. SSH is used only
// for fixture setup, deliberate external edits and independent native oracles.
type resourceDispatch struct {
	vm                                        *guestVM
	control                                   *vmControlPlane
	device, head, profile, resource, revision string
	// diagnostics optionally adds lane-specific failure context.
	diagnostics func(context.Context) []VMResourceNativeRecord
	// reboot performs a real guest reboot and reopens the control-plane
	// forwards; it is nil outside the connected resource lane.
	reboot func(context.Context) error
	// awaitReboot waits for a guest-initiated reboot away from the previous
	// boot ID within timeout and reopens the forwards; nil like reboot.
	awaitReboot func(ctx context.Context, previousBoot string, timeout time.Duration) error
}

func (r *resourceDispatch) assign(ctx context.Context, desired *resourcev1.ResourceDesiredState, ownership *resourcev1.OwnershipPolicy) error {
	request := &adminv1.PublishProfileRevisionRequest{RequestId: uuid.NewString(), ProfileId: r.profile, Reason: "disposable signed native resource qualification", Spec: &policyv1.ResourceProfile{Name: "Native resource qualification", Resources: []*policyv1.ProfileResource{{ResourceId: r.resource, Desired: desired, Ownership: ownership, Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 300, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}}}}}}
	if r.revision != "" {
		request.ExpectedRevisionId = proto.String(r.revision)
	}
	published, err := r.control.session.Admin.PublishProfileRevision(ctx, connect.NewRequest(request))
	if err != nil {
		return err
	}
	r.revision = published.Msg.GetRevision().GetRevisionId()
	assignmentRequest := &adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: r.device, Target: &adminv1.ResourceAssignmentTarget{ProfileId: published.Msg.GetRevision().GetProfileId(), RevisionId: r.revision}, ReconcileIntervalSeconds: proto.Uint32(dispatchReconcileIntervalSeconds), Reason: "disposable signed native resource qualification"}
	if r.head != "" {
		assignmentRequest.ExpectedAssignmentId = proto.String(r.head)
	}
	if ownership.GetMode() == resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION {
		if r.control.approver == nil {
			approver, err := r.control.openApprover(ctx)
			if err != nil {
				return err
			}
			r.control.approver = approver
		}
		approval, err := r.control.approver.Approve(ctx, r.control.session, &adminv1.CreateApprovalRequest{LifetimeSeconds: 600, Payload: &adminv1.CreateApprovalRequest_SetResourceAssignment{SetResourceAssignment: assignmentRequest}})
		if err != nil {
			return err
		}
		assignmentRequest.ApprovalId = approval.GetId()
	}
	assignment, err := r.control.session.Admin.SetResourceAssignment(ctx, connect.NewRequest(assignmentRequest))
	if err != nil {
		return err
	}
	r.head = assignment.Msg.GetAssignment().GetAssignmentId()
	return nil
}

func (r *resourceDispatch) action(ctx context.Context, rejected bool) (*adminv1.ResourceActionSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	for {
		state, err := r.control.dispatchState(ctx, r.device)
		if err != nil {
			return nil, err
		}
		if state.GetAssignment().GetAssignmentId() != r.head || len(state.GetResources()) != 1 {
			return nil, errors.New("resource dispatch head/cardinality changed")
		}
		resource := state.GetResources()[0]
		action := resource.GetLatestAction()
		if action != nil && action.GetClosedAt() != nil && action.GetStatus() != nil {
			if action.GetAttestedAt() == nil || action.GetReceivedAt() == nil || action.GetClosedReason() != "result" {
				return nil, errors.New("resource outcome lacks authenticated installed executor history")
			}
			success := action.GetStatus().GetState() == agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED
			if success == rejected {
				return nil, fmt.Errorf("unexpected resource outcome: %s", action)
			}
			if !rejected && action.GetStatus().GetVerification().GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED {
				return nil, errors.New("native resource succeeded without convergence")
			}
			return action, nil
		}
		if resource.GetDisposition() == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_UNSUPPORTED {
			return nil, fmt.Errorf("native resource unsupported: %s", resource.GetReason())
		}
		if err := lifecycleDelay(ctx, 250*time.Millisecond); err != nil {
			return nil, fmt.Errorf("resource action did not terminate: %w; last=%s", err, state)
		}
	}
}

func (r *resourceDispatch) release(ctx context.Context, ref *resourcev1.ResourceRef, conflict bool) (*adminv1.ResourceRelease, error) {
	sourceHead := r.head
	response, err := r.control.session.Admin.SetResourceAssignment(ctx, connect.NewRequest(&adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: r.device, ExpectedAssignmentId: proto.String(r.head), Clear: true, Reason: "signed ownership-safe native resource release qualification"}))
	if err != nil {
		return nil, err
	}
	r.head = response.Msg.GetAssignment().GetAssignmentId()
	ctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	for {
		state, err := r.control.dispatchState(ctx, r.device)
		if err != nil {
			return nil, err
		}
		for _, release := range state.GetReleases() {
			if release.GetSourceAssignmentId() != sourceHead || !proto.Equal(release.GetRef(), ref) {
				continue
			}
			if release.GetCompletedAt() != nil {
				if conflict {
					if release.GetState() == "released" {
						return nil, errors.New("external edit was overwritten by release")
					}
				} else if release.GetState() != "released" {
					return nil, fmt.Errorf("native release failed: %s", release)
				}
				return release, nil
			}
			if release.GetState() == "release_conflict" {
				if conflict {
					return release, nil
				}
				return nil, fmt.Errorf("native release conflict: %s", release)
			}
		}
		if err := lifecycleDelay(ctx, 250*time.Millisecond); err != nil {
			return nil, fmt.Errorf("resource release did not settle: %w; last=%s", err, state)
		}
	}
}

func resourceCreatePolicy() *resourcev1.OwnershipPolicy {
	return &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED}
}

// resourcePackaging selects the guest's native package format, architecture
// and, for RPM, the native DNF generation (EL DNF4 versus Fedora DNF5).
type resourcePackaging struct{ rpm, arm, dnf4 bool }

func newResourcePackaging(backend platform.Backend, architecture string) resourcePackaging {
	return resourcePackaging{rpm: backend.DNF(), arm: architecture == "arm64", dnf4: backend == platform.BackendDNF4}
}

// dnf4VersionlockList is the native DNF4 versionlock plugin's lock list.
const dnf4VersionlockList = "/etc/dnf/plugins/versionlock.list"

// nativeArch is the package manager's own architecture name.
func (p resourcePackaging) nativeArch() string {
	switch {
	case p.rpm && p.arm:
		return "aarch64"
	case p.rpm:
		return "x86_64"
	case p.arm:
		return "arm64"
	default:
		return "amd64"
	}
}

func resourcePackageDesired(rpm resourcePackaging, version string, present bool) *resourcev1.ResourceDesiredState {
	ecosystem, arch, key, repo := resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, rpm.nativeArch(), "deb/", "apt/"
	exact := &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Deb{Deb: version + "-1"}}
	if rpm.rpm {
		ecosystem, key, repo = resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM, "rpm/", "rpm/"
		exact = &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Rpm{Rpm: &resourcev1.RPMVersion{Version: version, Release: "1"}}}
	}
	desired := &resourcev1.NativePackageDesired{Package: &resourcev1.PackageIdentity{Ecosystem: ecosystem, NativeName: resourcePackageName, Architecture: arch}, Presence: resourcev1.Presence_PRESENCE_PRESENT, Repository: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PACKAGE_REPOSITORY, CanonicalKey: repo + resourceRepositoryID}, Removal: resourcev1.PackageRemovalPolicy_PACKAGE_REMOVAL_POLICY_PRESERVE_DATA, Version: &resourcev1.NativePackageDesired_Exact{Exact: exact}}
	if !present {
		desired.Presence = resourcev1.Presence_PRESENCE_ABSENT
		desired.Version = &resourcev1.NativePackageDesired_Any{Any: &resourcev1.AnyApprovedVersion{}}
	}
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: key + resourcePackageName + "/" + arch}, State: &resourcev1.ResourceDesiredState_NativePackage{NativePackage: desired}}
}

func resourceFileDesired(name, content string) *resourcev1.ResourceDesiredState {
	path := resourceFileRoot + "/" + name
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, CanonicalKey: path}, State: &resourcev1.ResourceDesiredState_ManagedFile{ManagedFile: &resourcev1.ManagedFileDesired{Path: path, Presence: resourcev1.Presence_PRESENCE_PRESENT, Content: []byte(content), Mode: proto.Uint32(0640), Uid: proto.Uint32(0), Gid: proto.Uint32(0)}}}
}

func resourceOracle(ctx context.Context, vm *guestVM, name, command string) (VMResourceNativeRecord, error) {
	return resourceOracleInput(ctx, vm, name, command, nil)
}

// resourceOracleInput feeds private expectations, such as a password hash to
// compare in the guest, on stdin so they never enter argv or the record.
func resourceOracleInput(ctx context.Context, vm *guestVM, name, command string, input []byte) (VMResourceNativeRecord, error) {
	var stdin io.Reader
	if input != nil {
		stdin = bytes.NewReader(input)
	}
	// Native tools (gpgv, dpkg, systemctl) report on stderr; it is part of the
	// recorded evidence, while the exit status remains the oracle verdict.
	result, err := vm.runResult(ctx, "sudo -n /bin/sh -eu -c "+nativeQuote(command)+" 2>&1", stdin, 256<<10, time.Minute)
	if err != nil {
		return VMResourceNativeRecord{}, fmt.Errorf("independent %s oracle: %w", name, err)
	}
	data := result.Stdout
	if result.ExitCode != 0 {
		// The oracle observes disposable lab state only; its tail names the
		// failed native check.
		tail := strings.TrimSpace(string(data))
		if len(tail) > 1024 {
			tail = tail[len(tail)-1024:]
		}
		return VMResourceNativeRecord{}, fmt.Errorf("independent %s oracle: guest exit %d: %q", name, result.ExitCode, tail)
	}
	if len(data) == 0 {
		return VMResourceNativeRecord{}, errors.New("native resource oracle returned no evidence")
	}
	return resourceNativeRecord(name, data), nil
}

func packageOracle(ctx context.Context, vm *guestVM, rpm resourcePackaging, version string, present bool) (VMResourceNativeRecord, error) {
	command := ""
	if rpm.rpm {
		command = "rpm -q --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}\\n' " + resourceDependencyName + "; "
		switch {
		case present && rpm.dnf4:
			command += "test \"$(rpm -q --qf '%{VERSION}' " + resourcePackageName + ")\" = " + nativeQuote(version) + "; rpm -q --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}\\n' " + resourcePackageName + "; " + dnf4PinOracle(rpm, version)
		case present:
			command += "test \"$(rpm -q --qf '%{VERSION}' " + resourcePackageName + ")\" = " + nativeQuote(version) + "; rpm -q --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}\\n' " + resourcePackageName + "; python3 -c " + nativeQuote("import tomllib; d=tomllib.load(open('/etc/dnf/versionlock.toml','rb')); p=[p for p in d['packages'] if p['name']=='"+resourcePackageName+"']; assert len(p)==1; assert any(c['key']=='evr' and c['comparator']=='=' and c['value']=='0:"+version+"-1' for c in p[0]['conditions'])") + "; cat /etc/dnf/versionlock.toml; "
		default:
			command += "if rpm -q " + resourcePackageName + "; then exit 1; fi; "
			if rpm.dnf4 {
				command += "if grep -F " + nativeQuote("# lindm:rpm/"+resourcePackageName+"/") + " " + dnf4VersionlockList + "; then exit 1; fi; cat " + dnf4VersionlockList + "; "
			}
		}
	} else {
		command = "dpkg-query -W -f='${Package} ${Version} ${Architecture} ${db:Status-Status}\\n' " + resourceDependencyName + "; test \"$(dpkg-query -W -f='${db:Status-Status}' " + resourceDependencyName + ")\" = installed; "
		if present {
			command += "test \"$(dpkg-query -W -f='${Version}' " + resourcePackageName + ")\" = " + nativeQuote(version+"-1") + "; dpkg-query -W -f='${Package} ${Version} ${Architecture} ${db:Status-Status}\\n' " + resourcePackageName + "; grep -Fx " + nativeQuote("Pin: version "+version+"-1") + " /etc/apt/preferences.d/lindm-*; cat /etc/apt/preferences.d/lindm-*; "
		} else {
			command += "if dpkg-query -W -f='${db:Status-Status}' " + resourcePackageName + " 2>/dev/null | /usr/bin/grep -qx installed; then exit 1; fi; "
		}
	}
	if present {
		command += "test \"$(/usr/bin/lindm-resource-proof)\" = " + nativeQuote(version) + "; /usr/bin/lindm-resource-proof; "
		if rpm.dnf4 {
			// RPM's SELinux plugin labels payload files and runs scriptlets
			// in rpm_script_t from the DNF4 adapter's service domain.
			command += "matchpathcon -V /usr/bin/lindm-resource-proof; ls -Z /usr/bin/lindm-resource-proof; grep -E '^scriptlet-context [a-z_]+:[a-z_]+:rpm_script_t:' " + resourceFixtureRoot + "/maintainer.log; "
		}
	}
	command += "cat " + resourceFixtureRoot + "/maintainer.log; printf 'dependency-retained\\n'"
	return resourceOracle(ctx, vm, "native-package-db-pin-readiness-maintainer", command)
}

// dnf4PinOracle proves lindm's marked exact entry exists and that the native
// DNF4 CLI, through its own versionlock plugin, refuses to resolve to the other
// version that the signed lab repository demonstrably offers. The plugin only
// filters resolving commands (list/info ignore locks), so the oracle asks for
// the upgrade or downgrade with --assumeno, with and without the plugin.
func dnf4PinOracle(rpm resourcePackaging, version string) string {
	other, op := "2.0", "upgrade"
	if version == "2.0" {
		other, op = "1.0", "downgrade"
	}
	entry := resourcePackageName + "-0:" + version + "-1." + rpm.nativeArch()
	repo := "--repofrompath=lindm-oracle,https://127.0.0.1:18449 --repo=lindm-oracle --setopt=lindm-oracle.gpgcheck=1 --setopt=lindm-oracle.repo_gpgcheck=1 --setopt=lindm-oracle.gpgkey=file://" + resourceFixtureRoot + "/repository.asc"
	// Metadata age lines are timing, not evidence; repeated oracles must match.
	resolve := "dnf --assumeno " + repo + " " + op + " " + resourcePackageName
	untimed := " 2>&1 | grep -v '^Last metadata expiration check' || true"
	return "grep -Fx " + nativeQuote("# lindm:rpm/"+resourcePackageName+"/"+rpm.nativeArch()) + " " + dnf4VersionlockList + "; grep -Fx " + nativeQuote(entry) + " " + dnf4VersionlockList + "; cat " + dnf4VersionlockList + "; " +
		"dnf -q versionlock list; dnf -q -y " + repo + " makecache >/dev/null 2>&1; " +
		"unlocked=$(" + resolve + " --disableplugin=versionlock" + untimed + "); printf 'unlocked %s: %s\\n' " + op + " \"$unlocked\"; printf '%s\\n' \"$unlocked\" | grep -F " + nativeQuote(other+"-1") + "; " +
		"locked=$(" + resolve + untimed + "); printf 'locked %s: %s\\n' " + op + " \"$locked\"; if printf '%s\\n' \"$locked\" | grep -F " + nativeQuote(other+"-1") + "; then exit 1; fi; "
}

func fileOracle(ctx context.Context, vm *guestVM, name, content string, exists bool) (VMResourceNativeRecord, error) {
	path := resourceFileRoot + "/" + name
	command := "test ! -L " + nativeQuote(path) + "; "
	if exists {
		digest := sha256.Sum256([]byte(content))
		command += "test \"$(stat -c '%a:%u:%g' " + nativeQuote(path) + ")\" = '640:0:0'; printf '%s  %s\\n' " + nativeQuote(fmt.Sprintf("%x", digest)) + " " + nativeQuote(path) + " | sha256sum --check; stat -c '%n %a %u %g %s' " + nativeQuote(path) + "; sha256sum " + nativeQuote(path) + "; getfattr -d -m- --absolute-names " + nativeQuote(path) + "; "
	} else {
		command += "test ! -e " + nativeQuote(path) + "; printf 'absent\\n'; "
	}
	command += "if test -e /sys/fs/selinux/enforce; then test \"$(getenforce)\" = Enforcing; getenforce; fi"
	return resourceOracle(ctx, vm, "native-file-content-mode-uid-gid-xattrs-selinux", command)
}

func exerciseConnectedResources(ctx context.Context, packages *nativeGuestPackages, control *vmControlPlane, result *VMDispatchResult, selected map[string]bool, firewall *firewallLane, reboot func(context.Context) error, awaitReboot func(context.Context, string, time.Duration) error) error {
	vm := packages.vm
	if result.Resources == nil {
		result.Resources = newVMResourceEvidence()
	}
	result.Resources.ExecutionPath = "connected-server-assignment-release"
	r := &resourceDispatch{vm: vm, control: control, device: result.DeviceID, profile: uuid.NewString(), resource: uuid.NewString(), reboot: reboot, awaitReboot: awaitReboot}
	rpm := newResourcePackaging(packages.backend, result.Architecture)
	kinds := result.Resources.Kinds
	if selected["packages"] {
		if err := exerciseResourcePackages(ctx, r, rpm, &kinds[0]); err != nil {
			return err
		}
	}
	if selected["files"] {
		r.fresh()
		if err := exerciseResourceFiles(ctx, r, &kinds[1]); err != nil {
			return err
		}
	}
	if selected["accounts"] {
		if err := exerciseResourceAccounts(ctx, r, &kinds[2], &kinds[3]); err != nil {
			return err
		}
	}
	if selected["sysctl"] {
		if err := exerciseResourceSysctl(ctx, r, &kinds[4]); err != nil {
			return err
		}
	}
	if selected["definitions"] {
		if err := exerciseResourceDefinitions(ctx, r, &kinds[5]); err != nil {
			return err
		}
	}
	if selected["password"] {
		if err := exerciseResourcePassword(ctx, packages, r, &kinds[8]); err != nil {
			return err
		}
	}
	if selected["os-update"] {
		r.fresh()
		if err := exerciseResourceOSUpdate(ctx, r, rpm, &kinds[10]); err != nil {
			return err
		}
	}
	if selected["secret-password"] {
		r.fresh()
		result.Resources.SecretPassword = new(VMSecretPasswordEvidence)
		if err := exerciseResourceSecretPassword(ctx, r, result.Resources.SecretPassword, &kinds[9]); err != nil {
			return err
		}
	}
	if selected["local-admin"] {
		result.Resources.LocalAdmin = &VMLocalAdminEvidence{Account: localAdminLabAccount, Unproven: []string{"managed local-admin rotation, reveal and post-reveal supersession not completed"}}
		if err := exerciseLocalAdminPassword(ctx, vm, control, result.DeviceID, result.Resources.LocalAdmin); err != nil {
			return err
		}
	}
	if selected["firewall"] {
		r.fresh()
		if err := exerciseResourceFirewall(ctx, r, firewall, &result.Resources.Fixture, &kinds[6]); err != nil {
			return err
		}
	}
	// An interrupted effect leaves its device fence held, so it runs last.
	if selected["packages"] {
		if err := exercisePackageInterruption(ctx, r, rpm, &kinds[0]); err != nil {
			return err
		}
		kinds[0].Unproven = nil
		if err := qualifyResourceEvidence(&kinds[0], []string{"exact-v1-dependency-readiness", "wrong-signing-key-refused", "unavailable-exact-version-refused", "exact-v2-upgrade", "repeat-exact-v2", "owned-absence", "presence-after-absence", "release-retains-dependency", "external-pin-drift-release-refused", "interrupted-running-no-replay"}); err != nil {
			return err
		}
	}
	if rpm.rpm {
		if _, err := serviceGuestEnforcing(ctx, vm); err != nil {
			return err
		}
	}
	return nil
}

func exerciseResourcePackages(ctx context.Context, r *resourceDispatch, rpm resourcePackaging, evidence *VMResourceKindEvidence) error {
	names := []string{"exact-v1-dependency-readiness", "exact-v2-upgrade", "repeat-exact-v2", "owned-absence", "presence-after-absence", "release-retains-dependency"}
	for index, phase := range []struct {
		version string
		present bool
	}{{"1.0", true}, {"2.0", true}, {"2.0", true}, {"2.0", false}, {"2.0", true}} {
		scenario := VMResourceScenario{Name: names[index], StartedAt: time.Now().UTC()}
		evidence.Scenarios = append(evidence.Scenarios, scenario)
		s := &evidence.Scenarios[len(evidence.Scenarios)-1]
		desired := resourcePackageDesired(rpm, phase.version, phase.present)
		if err := r.assign(ctx, desired, resourceCreatePolicy()); err != nil {
			s.Failure = err.Error()
			return err
		}
		action, err := r.action(ctx, false)
		s.Action = action
		if err != nil {
			s.Failure = err.Error()
			s.Native = append(s.Native, executorDiagnostics(ctx, r.vm))
			return err
		}
		if index == 2 && action.GetStartAuthorizedAt() != nil {
			return errors.New("repeated native package state acquired a start grant")
		}
		native, err := packageOracle(ctx, r.vm, rpm, phase.version, phase.present)
		if err != nil {
			s.Failure = err.Error()
			return err
		}
		s.Native = []VMResourceNativeRecord{native}
		s.FinishedAt = time.Now().UTC()
		s.Passed = true
		if index == 0 {
			if err := exercisePackageRefusals(ctx, r, rpm, evidence); err != nil {
				return err
			}
		}
	}
	s := VMResourceScenario{Name: names[5], StartedAt: time.Now().UTC()}
	evidence.Scenarios = append(evidence.Scenarios, s)
	release := &evidence.Scenarios[len(evidence.Scenarios)-1]
	var err error
	release.Release, err = r.release(ctx, resourcePackageDesired(rpm, "2.0", true).GetRef(), false)
	if err != nil {
		release.Failure = err.Error()
		return err
	}
	native, err := packageOracle(ctx, r.vm, rpm, "", false)
	if err != nil {
		release.Failure = err.Error()
		return err
	}
	release.Native = []VMResourceNativeRecord{native}
	release.FinishedAt = time.Now().UTC()
	release.Passed = true
	if err := exercisePackageDrift(ctx, r, rpm, evidence); err != nil {
		return err
	}
	evidence.Unproven = []string{"interrupted-running no-replay qualification has not completed"}
	return nil
}

func exerciseResourceFiles(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence) error {
	names := []string{"create", "reconcile", "repeat", "release-created-file", "approved-adoption", "restore-adopted-baseline", "external-edit-release-refused", "foreign-acl-adoption-refused", "inherited-default-acl-create-refused"}
	for index, content := range []string{"first\n", "second\n", "second\n"} {
		evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: names[index], StartedAt: time.Now().UTC()})
		s := &evidence.Scenarios[len(evidence.Scenarios)-1]
		if err := r.assign(ctx, resourceFileDesired("created", content), resourceCreatePolicy()); err != nil {
			s.Failure = err.Error()
			return err
		}
		action, err := r.action(ctx, false)
		s.Action = action
		if err != nil {
			s.Failure = err.Error()
			s.Native = append(s.Native, executorDiagnostics(ctx, r.vm))
			return err
		}
		if index == 2 && action.GetStartAuthorizedAt() != nil {
			return errors.New("repeated native file state acquired a start grant")
		}
		native, err := fileOracle(ctx, r.vm, "created", content, true)
		if err != nil {
			s.Failure = err.Error()
			return err
		}
		s.Native = []VMResourceNativeRecord{native}
		s.FinishedAt = time.Now().UTC()
		s.Passed = true
	}
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: names[3], StartedAt: time.Now().UTC()})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	var err error
	s.Release, err = r.release(ctx, resourceFileDesired("created", "second\n").GetRef(), false)
	if err != nil {
		s.Failure = err.Error()
		return err
	}
	native, err := fileOracle(ctx, r.vm, "created", "", false)
	if err != nil {
		s.Failure = err.Error()
		return err
	}
	s.Native = []VMResourceNativeRecord{native}
	s.Passed = true
	s.FinishedAt = time.Now().UTC()
	if err := exerciseResourceFileAdoption(ctx, r, evidence); err != nil {
		return err
	}
	r.profile, r.resource, r.revision = uuid.NewString(), uuid.NewString(), ""
	desired := resourceFileDesired("external", "managed\n")
	if err := r.assign(ctx, desired, resourceCreatePolicy()); err != nil {
		return err
	}
	action, err := r.action(ctx, false)
	if err != nil {
		return err
	}
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: names[6], StartedAt: time.Now().UTC(), Action: action})
	s = &evidence.Scenarios[len(evidence.Scenarios)-1]
	// Stop automatic rechecks while making the external edit and clearing the
	// assignment. Release, not reconciliation, must encounter the external bytes.
	if err := lifecycleCommand(ctx, r.vm, "pause relay before external file edit", "systemctl stop lindm-agent.service; printf 'external\\n' > "+resourceFileRoot+"/external"); err != nil {
		return err
	}
	before, err := fileOracle(ctx, r.vm, "external", "external\n", true)
	if err != nil {
		return err
	}
	// Resume only after the clear has been durably accepted by the server.
	clear, err := r.control.session.Admin.SetResourceAssignment(ctx, connect.NewRequest(&adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: r.device, ExpectedAssignmentId: proto.String(r.head), Clear: true, Reason: "external managed file edit must block ownership release"}))
	if err != nil {
		return err
	}
	sourceHead := r.head
	r.head = clear.Msg.GetAssignment().GetAssignmentId()
	if err := lifecycleCommand(ctx, r.vm, "resume release relay", "systemctl start lindm-agent.service"); err != nil {
		return err
	}
	release, err := waitResourceReleaseConflict(ctx, r.control, r.device, sourceHead, desired.GetRef())
	s.Release = release
	if err != nil {
		s.Failure = err.Error()
		return err
	}
	after, err := fileOracle(ctx, r.vm, "external", "external\n", true)
	if err != nil {
		return err
	}
	if !bytes.Equal(before.Bytes, after.Bytes) {
		return errors.New("release changed independent external file state")
	}
	s.Native = []VMResourceNativeRecord{before, after}
	s.Passed = true
	s.FinishedAt = time.Now().UTC()
	if err := exerciseResourceFileACLs(ctx, r, evidence); err != nil {
		return err
	}
	evidence.Unproven = nil
	return qualifyResourceEvidence(evidence, names)
}

func waitResourceReleaseConflict(ctx context.Context, control *vmControlPlane, device, head string, ref *resourcev1.ResourceRef) (*adminv1.ResourceRelease, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	for {
		state, err := control.dispatchState(ctx, device)
		if err != nil {
			return nil, err
		}
		for _, release := range state.GetReleases() {
			if release.GetSourceAssignmentId() == head && proto.Equal(release.GetRef(), ref) {
				if release.GetState() == "released" {
					return nil, errors.New("external file edit release unexpectedly succeeded")
				}
				if release.GetState() == "release_conflict" {
					return release, nil
				}
			}
		}
		if err := lifecycleDelay(ctx, 250*time.Millisecond); err != nil {
			return nil, fmt.Errorf("external-edit release refusal not evidenced: %w; last=%s", err, state)
		}
	}
}
