//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// Fixed disposable account, kernel and unit identities. Account IDs lie in the
// root-approved lane range; the target service is an inert oneshot fixture.
const (
	resourceLabGroup       = "rlabgroup"
	resourceLabGroupID     = 24001
	resourceLabUser        = "rlabuser"
	resourceLabUserID      = 24002
	resourceLabHomeRoot    = resourceFixtureRoot + "/homes"
	resourceLabHomeRootID  = "8f1d3a4e-6c2b-4a57-9e10-2d7b4c6a8e31"
	resourceLabSysctlKey   = "vm.swappiness"
	resourceLabTarget      = "rlab-target.service"
	resourceLabTimer       = "rlab-target.timer"
	resourceLabSysctlPrior = resourceFixtureRoot + "/sysctl-prior"
)

// provisionHostResourceRoots adds the root-local account and sysctl approvals
// and installs the inert timer target before enrollment-independent effects.
func provisionHostResourceRoots(config *agentv1.AgentConfig) {
	config.AccountProvider = &agentv1.NativeAccountProviderConfig{
		ApprovedHomeRoots: []*agentv1.NativeApprovedHomeRoot{{RootId: resourceLabHomeRootID, Path: resourceLabHomeRoot}},
		MinUid:            24000, MaxUid: 24999, MinGid: 24000, MaxGid: 24999,
	}
	config.SysctlProvider = &agentv1.NativeSysctlProviderConfig{AllowedKeys: []string{resourceLabSysctlKey}}
}

const resourceHostFixtureScript = `set -eu
install -d -o root -g root -m 0755 ` + resourceLabHomeRoot + `
cat > /etc/systemd/system/` + resourceLabTarget + ` <<'UNIT'
[Unit]
Description=Disposable lindm resource timer target

[Service]
Type=oneshot
ExecStart=/bin/true
UNIT
chmod 0644 /etc/systemd/system/` + resourceLabTarget + `
if command -v restorecon >/dev/null 2>&1; then restorecon -RF ` + resourceLabHomeRoot + ` /etc/systemd/system/` + resourceLabTarget + `; fi
systemctl daemon-reload
sysctl -n ` + resourceLabSysctlKey + ` > ` + resourceLabSysctlPrior + `
`

func setupHostResourceFixtures(ctx context.Context, vm *guestVM) error {
	return lifecycleCommand(ctx, vm, "install disposable host resource fixtures", resourceHostFixtureScript)
}

// resourceStep assigns one desired state and records the device-signed outcome
// beside an independent native oracle. Repeats must not acquire start authority.
func resourceStep(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence, name string, desired *resourcev1.ResourceDesiredState, policy *resourcev1.OwnershipPolicy, repeat bool, oracle func(context.Context) (VMResourceNativeRecord, error)) error {
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: name, StartedAt: time.Now().UTC()})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	fail := func(err error) error {
		s.Failure = err.Error()
		s.Native = append(s.Native, executorDiagnostics(ctx, r.vm))
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := r.assign(ctx, desired, policy); err != nil {
		return fail(err)
	}
	action, err := r.action(ctx, false)
	s.Action = action
	if err != nil {
		return fail(err)
	}
	if repeat && action.GetStartAuthorizedAt() != nil {
		return fail(errors.New("repeated converged state acquired a start grant"))
	}
	native, err := oracle(ctx)
	if err != nil {
		return fail(err)
	}
	s.Native = []VMResourceNativeRecord{native}
	s.FinishedAt = time.Now().UTC()
	s.Passed = true
	return nil
}

// resourceReleaseStep clears the assignment and requires an attested release
// whose native result an independent oracle then confirms.
func resourceReleaseStep(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence, name string, ref *resourcev1.ResourceRef, oracle func(context.Context) (VMResourceNativeRecord, error)) error {
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: name, StartedAt: time.Now().UTC()})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	var err error
	s.Release, err = r.release(ctx, ref, false)
	if err != nil {
		s.Failure = err.Error()
		s.Native = append(s.Native, executorDiagnostics(ctx, r.vm))
		return fmt.Errorf("%s: %w", name, err)
	}
	native, err := oracle(ctx)
	if err != nil {
		s.Failure = err.Error()
		return fmt.Errorf("%s: %w", name, err)
	}
	s.Native = []VMResourceNativeRecord{native}
	s.FinishedAt = time.Now().UTC()
	s.Passed = true
	return nil
}

// executorDiagnostics retains the installed executor's recent journal for a
// failed scenario. It is diagnostic context, never qualification evidence.
func executorDiagnostics(ctx context.Context, vm *guestVM) VMResourceNativeRecord {
	data, err := vm.run(ctx, "sudo -n journalctl --no-pager -o short-iso -n 120 -u lindm-executor.service 2>&1", nil, 256<<10, 30*time.Second)
	if err != nil {
		data = []byte(err.Error())
	}
	return resourceNativeRecord("failure-diagnostic-executor-journal", data)
}

func (r *resourceDispatch) fresh() {
	r.profile, r.resource, r.revision = uuid.NewString(), uuid.NewString(), ""
}

func resourceGroupDesired(present bool) *resourcev1.ResourceDesiredState {
	group := &resourcev1.LocalGroupDesired{Name: resourceLabGroup, Presence: resourcev1.Presence_PRESENCE_ABSENT}
	if present {
		group.Presence, group.Gid = resourcev1.Presence_PRESENCE_PRESENT, proto.Uint32(resourceLabGroupID)
	}
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, CanonicalKey: resourceLabGroup}, State: &resourcev1.ResourceDesiredState_LocalGroup{LocalGroup: group}}
}

func resourceUserDesired(shell string) *resourcev1.ResourceDesiredState {
	user := &resourcev1.LocalUserDesired{
		Name: resourceLabUser, Presence: resourcev1.Presence_PRESENCE_PRESENT, Uid: proto.Uint32(resourceLabUserID),
		PrimaryGroup: proto.String("users"), HomeDirectory: proto.String(resourceLabHomeRoot + "/" + resourceLabUser),
		Shell:    &resourcev1.LoginShell{InstalledShell: shell},
		Password: &resourcev1.PasswordState{State: &resourcev1.PasswordState_Locked{Locked: &resourcev1.LockedPassword{}}},
		Home:     &resourcev1.HomePolicy{Creation: resourcev1.HomeCreation_HOME_CREATION_CREATE_IF_ABSENT, Mode: proto.Uint32(0o700), ApprovedRootId: resourceLabHomeRootID},
	}
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, CanonicalKey: resourceLabUser}, State: &resourcev1.ResourceDesiredState_LocalUser{LocalUser: user}}
}

func groupOracle(present bool) func(context.Context, *guestVM) (VMResourceNativeRecord, error) {
	return func(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
		command := "if getent group " + resourceLabGroup + "; then exit 1; fi; if grep '^" + resourceLabGroup + ":' /etc/group /etc/gshadow; then exit 1; fi; printf 'group-absent\\n'"
		if present {
			command = fmt.Sprintf("test \"$(getent group %s)\" = '%s:x:%d:'; grep '^%s:' /etc/group; grep -c '^%s:' /etc/gshadow", resourceLabGroup, resourceLabGroup, resourceLabGroupID, resourceLabGroup, resourceLabGroup)
		}
		return resourceOracle(ctx, vm, "native-group-database", command)
	}
}

func userOracle(shell string, present bool) func(context.Context, *guestVM) (VMResourceNativeRecord, error) {
	home := resourceLabHomeRoot + "/" + resourceLabUser
	return func(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
		// Release never deletes home data; it remains as created, owned by
		// the removed numeric identity.
		command := "if getent passwd " + resourceLabUser + "; then exit 1; fi; if grep '^" + resourceLabUser + ":' /etc/passwd /etc/shadow; then exit 1; fi; test -d " + home + "; stat -c '%n %a %u %g' " + home + "; printf 'user-absent-home-preserved\\n'"
		if present {
			command = fmt.Sprintf("test \"$(getent passwd %s)\" = '%s:x:%d:100::%s:%s'; id %s; test \"$(stat -c '%%a %%u %%g' %s)\" = '700 %d 100'; stat -c '%%n %%a %%u %%g' %s; getent shadow %s | cut -d: -f1,2 | grep -E '^%s:!'; grep -Fx %s /etc/shells",
				resourceLabUser, resourceLabUser, resourceLabUserID, home, shell, resourceLabUser, home, resourceLabUserID, home, resourceLabUser, resourceLabUser, nativeQuote(shell))
		}
		return resourceOracle(ctx, vm, "native-user-database-home-shadow", command)
	}
}

func withVM(vm *guestVM, oracle func(context.Context, *guestVM) (VMResourceNativeRecord, error)) func(context.Context) (VMResourceNativeRecord, error) {
	return func(ctx context.Context) (VMResourceNativeRecord, error) { return oracle(ctx, vm) }
}

func exerciseResourceAccounts(ctx context.Context, r *resourceDispatch, groups, users *VMResourceKindEvidence) error {
	r.fresh()
	if err := resourceStep(ctx, r, groups, "create", resourceGroupDesired(true), resourceCreatePolicy(), false, withVM(r.vm, groupOracle(true))); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, groups, "repeat", resourceGroupDesired(true), resourceCreatePolicy(), true, withVM(r.vm, groupOracle(true))); err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, groups, "release-created-group", resourceGroupDesired(true).GetRef(), withVM(r.vm, groupOracle(false))); err != nil {
		return err
	}
	groups.Unproven = nil
	if err := qualifyResourceEvidence(groups, []string{"create", "repeat", "release-created-group"}); err != nil {
		return err
	}
	r.fresh()
	if err := resourceStep(ctx, r, users, "create-locked-home", resourceUserDesired("/bin/sh"), resourceCreatePolicy(), false, withVM(r.vm, userOracle("/bin/sh", true))); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, users, "reconcile-shell", resourceUserDesired("/bin/bash"), resourceCreatePolicy(), false, withVM(r.vm, userOracle("/bin/bash", true))); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, users, "repeat", resourceUserDesired("/bin/bash"), resourceCreatePolicy(), true, withVM(r.vm, userOracle("/bin/bash", true))); err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, users, "release-preserves-home", resourceUserDesired("/bin/bash").GetRef(), withVM(r.vm, userOracle("", false))); err != nil {
		return err
	}
	users.Unproven = []string{"password hash delivery and UID reuse are not exercised"}
	return qualifyResourceEvidence(users, []string{"create-locked-home", "reconcile-shell", "repeat", "release-preserves-home"})
}

func resourceSysctlDesired(value string) *resourcev1.ResourceDesiredState {
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL, CanonicalKey: resourceLabSysctlKey}, State: &resourcev1.ResourceDesiredState_Sysctl{Sysctl: &resourcev1.SysctlDesired{Key: resourceLabSysctlKey, Value: value, Persistent: true}}}
}

func sysctlOracle(value string) func(context.Context, *guestVM) (VMResourceNativeRecord, error) {
	return func(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
		// An empty value means the pre-management value and no owned file.
		command := "prior=$(cat " + resourceLabSysctlPrior + "); test \"$(sysctl -n " + resourceLabSysctlKey + ")\" = \"$prior\"; if ls /etc/sysctl.d/60-lindm-*.conf 2>/dev/null; then exit 1; fi; printf 'restored %s\\n' \"$prior\""
		if value != "" {
			command = "test \"$(sysctl -n " + resourceLabSysctlKey + ")\" = " + nativeQuote(value) + "; sysctl " + resourceLabSysctlKey + "; grep -Fx " + nativeQuote(resourceLabSysctlKey+" = "+value) + " /etc/sysctl.d/60-lindm-*.conf; stat -c '%n %a %u %g' /etc/sysctl.d/60-lindm-*.conf; systemd-sysctl --cat-config | grep -F " + nativeQuote(resourceLabSysctlKey)
		}
		return resourceOracle(ctx, vm, "native-sysctl-live-persistent", command)
	}
}

func exerciseResourceSysctl(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence) error {
	r.fresh()
	if err := resourceStep(ctx, r, evidence, "set-persistent", resourceSysctlDesired("17"), resourceCreatePolicy(), false, withVM(r.vm, sysctlOracle("17"))); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "reconcile", resourceSysctlDesired("23"), resourceCreatePolicy(), false, withVM(r.vm, sysctlOracle("23"))); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "repeat", resourceSysctlDesired("23"), resourceCreatePolicy(), true, withVM(r.vm, sysctlOracle("23"))); err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, evidence, "release-restores-prior", resourceSysctlDesired("23").GetRef(), withVM(r.vm, sysctlOracle(""))); err != nil {
		return err
	}
	evidence.Unproven = []string{"persistence across a guest reboot is not exercised"}
	return qualifyResourceEvidence(evidence, []string{"set-persistent", "reconcile", "repeat", "release-restores-prior"})
}

func resourceTimerDesired(interval uint32) *resourcev1.ResourceDesiredState {
	timer := &resourcev1.TimerDefinition{Unit: resourceLabTimer, Service: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: resourceLabTarget}, Schedule: &resourcev1.TimerSchedule{Schedule: &resourcev1.TimerSchedule_IntervalSeconds{IntervalSeconds: interval}}, Enabled: true}
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION, CanonicalKey: "timer/" + resourceLabTimer}, State: &resourcev1.ResourceDesiredState_SystemdDefinition{SystemdDefinition: &resourcev1.SystemdDefinitionDesired{Presence: resourcev1.Presence_PRESENCE_PRESENT, Definition: &resourcev1.SystemdDefinitionDesired_Timer{Timer: timer}}}}
}

func resourceDropInDesired(weight uint32) *resourcev1.ResourceDesiredState {
	dropIn := &resourcev1.ServiceDropIn{Unit: resourceLabTarget, CpuWeight: proto.Uint32(weight), TasksMax: proto.Uint32(64)}
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION, CanonicalKey: "drop-in/" + resourceLabTarget}, State: &resourcev1.ResourceDesiredState_SystemdDefinition{SystemdDefinition: &resourcev1.SystemdDefinitionDesired{Presence: resourcev1.Presence_PRESENCE_PRESENT, Definition: &resourcev1.SystemdDefinitionDesired_DropIn{DropIn: dropIn}}}}
}

func timerOracle(interval string) func(context.Context, *guestVM) (VMResourceNativeRecord, error) {
	return func(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
		command := "test \"$(systemctl show -P LoadState " + resourceLabTimer + ")\" = not-found; test ! -e /etc/systemd/system/" + resourceLabTimer + "; test ! -e /etc/systemd/system/timers.target.wants/" + resourceLabTimer + "; printf 'timer-absent\\n'"
		if interval != "" {
			command = "test \"$(systemctl show -P ActiveState " + resourceLabTimer + ")\" = active; test \"$(systemctl show -P UnitFileState " + resourceLabTimer + ")\" = enabled; test \"$(systemctl show -P Unit " + resourceLabTimer + ")\" = " + resourceLabTarget + "; shown=$(systemctl show -p TimersMonotonic -p ActiveState -p UnitFileState -p Unit " + resourceLabTimer + "); printf '%s\\n' \"$shown\"; printf '%s\\n' \"$shown\" | grep -qF " + nativeQuote("OnUnitActiveUSec="+interval) + "; systemctl cat " + resourceLabTimer + "; test \"$(systemctl show -P ActiveState " + resourceLabTarget + ")\" != failed"
		}
		return resourceOracle(ctx, vm, "native-systemd-timer", command)
	}
}

func dropInOracle(weight string) func(context.Context, *guestVM) (VMResourceNativeRecord, error) {
	return func(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
		command := "test ! -e /etc/systemd/system/" + resourceLabTarget + ".d/50-lindm.conf; test \"$(systemctl show -P CPUWeight " + resourceLabTarget + ")\" = '[not set]'; systemctl show -p CPUWeight -p TasksMax -p DropInPaths " + resourceLabTarget
		if weight != "" {
			command = "test \"$(systemctl show -P CPUWeight " + resourceLabTarget + ")\" = " + weight + "; test \"$(systemctl show -P TasksMax " + resourceLabTarget + ")\" = 64; systemctl show -p CPUWeight -p TasksMax -p DropInPaths " + resourceLabTarget + "; systemctl cat " + resourceLabTarget
		}
		return resourceOracle(ctx, vm, "native-systemd-drop-in", command)
	}
}

func exerciseResourceDefinitions(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence) error {
	r.fresh()
	if err := resourceStep(ctx, r, evidence, "timer-create-enabled", resourceTimerDesired(3600), resourceCreatePolicy(), false, withVM(r.vm, timerOracle("1h"))); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "timer-reconcile-interval", resourceTimerDesired(7200), resourceCreatePolicy(), false, withVM(r.vm, timerOracle("2h"))); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "timer-repeat", resourceTimerDesired(7200), resourceCreatePolicy(), true, withVM(r.vm, timerOracle("2h"))); err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, evidence, "timer-release", resourceTimerDesired(7200).GetRef(), withVM(r.vm, timerOracle(""))); err != nil {
		return err
	}
	r.fresh()
	if err := resourceStep(ctx, r, evidence, "drop-in-create", resourceDropInDesired(50), resourceCreatePolicy(), false, withVM(r.vm, dropInOracle("50"))); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "drop-in-reconcile", resourceDropInDesired(70), resourceCreatePolicy(), false, withVM(r.vm, dropInOracle("70"))); err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, evidence, "drop-in-release", resourceDropInDesired(70).GetRef(), withVM(r.vm, dropInOracle(""))); err != nil {
		return err
	}
	evidence.Unproven = nil
	return qualifyResourceEvidence(evidence, []string{"timer-create-enabled", "timer-reconcile-interval", "timer-repeat", "timer-release", "drop-in-create", "drop-in-reconcile", "drop-in-release"})
}

// ResourceKindSelection parses the connected lane's explicit kind groups.
func ResourceKindSelection(value string) (map[string]bool, error) {
	selected := make(map[string]bool)
	for name := range strings.SplitSeq(value, ",") {
		switch name {
		case "packages", "files", "accounts", "sysctl", "definitions", "password":
			selected[name] = true
		default:
			return nil, fmt.Errorf("unknown resource lane kind %q", name)
		}
	}
	return selected, nil
}
