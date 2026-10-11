//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// Fixed disposable account, kernel and unit identities. Account IDs lie in the
// root-approved lane range; the target service is an inert oneshot fixture.
// The foreign and adopted accounts are pre-existing, unmanaged native state.
const (
	resourceLabGroup           = "rlabgroup"
	resourceLabGroupID         = 24001
	resourceLabUser            = "rlabuser"
	resourceLabUserID          = 24002
	resourceLabForeign         = "rlabforeign"
	resourceLabForeignID       = 24003
	resourceLabReuse           = "rlabreuse"
	resourceLabReuseID         = 24004
	resourceLabReuseOtherID    = 24005
	resourceLabClash           = "rlabclash"
	resourceLabPrimary         = "rlabprimary"
	resourceLabPrimaryID       = 24010
	resourceLabAdoptGroup      = "rlabadoptg"
	resourceLabAdoptGroupID    = 24020
	resourceLabAdoptGroupNewID = 24021
	resourceLabAdoptUser       = "rlabadoptu"
	resourceLabAdoptUserID     = 24030
	resourceLabHomeRoot        = resourceFixtureRoot + "/homes"
	resourceLabHomeRootID      = "8f1d3a4e-6c2b-4a57-9e10-2d7b4c6a8e31"
	resourceLabSysctlKey       = "vm.swappiness"
	resourceLabNetKey          = "net.ipv4.ip_forward"
	resourceLabTarget          = "rlab-target.service"
	resourceLabTimer           = "rlab-target.timer"
	resourceLabSysctlPrior     = resourceFixtureRoot + "/sysctl-prior"
	resourceLabNetPrior        = resourceFixtureRoot + "/sysctl-net-prior"
)

// provisionHostResourceRoots adds the root-local account and sysctl approvals
// and installs the inert timer target before enrollment-independent effects.
func provisionHostResourceRoots(config *agentv1.AgentConfig) {
	config.AccountProvider = &agentv1.NativeAccountProviderConfig{
		ApprovedHomeRoots: []*agentv1.NativeApprovedHomeRoot{{RootId: resourceLabHomeRootID, Path: resourceLabHomeRoot}},
		MinUid:            24000, MaxUid: 24999, MinGid: 24000, MaxGid: 24999,
	}
	config.SysctlProvider = &agentv1.NativeSysctlProviderConfig{AllowedKeys: []string{resourceLabSysctlKey, resourceLabNetKey}}
}

// The adopted user's password is random and never known to the lane; only the
// SHA-256 of its shadow hash is ever recorded.
const resourceHostFixtureScript = `set -eu
install -d -o root -g root -m 0755 ` + resourceLabHomeRoot + `
groupadd -g 24010 ` + resourceLabPrimary + `
useradd -M -N -u 24003 -g ` + resourceLabPrimary + ` -d /nonexistent -s /usr/sbin/nologin ` + resourceLabForeign + `
groupadd -g 24020 ` + resourceLabAdoptGroup + `
usermod -a -G ` + resourceLabAdoptGroup + ` ` + resourceLabForeign + `
useradd -M -N -u 24030 -g ` + resourceLabPrimary + ` -d ` + resourceLabHomeRoot + `/` + resourceLabAdoptUser + ` -s /bin/sh ` + resourceLabAdoptUser + `
install -d -o 24030 -g 24010 -m 0750 ` + resourceLabHomeRoot + `/` + resourceLabAdoptUser + `
printf '` + resourceLabAdoptUser + `:%s\n' "$(openssl passwd -6 "$(openssl rand -hex 24)")" | chpasswd -e
chage -M 120 ` + resourceLabAdoptUser + `
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
sysctl -n ` + resourceLabNetKey + ` > ` + resourceLabNetPrior + `
`

func setupHostResourceFixtures(ctx context.Context, vm *guestVM) error {
	return lifecycleCommand(ctx, vm, "install disposable host resource fixtures", resourceHostFixtureScript)
}

// resourceStep assigns one desired state and records the device-signed outcome
// beside an independent native oracle. Repeats must not acquire start authority.
func resourceStep(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence, name string, desired *resourcev1.ResourceDesiredState, policy *resourcev1.OwnershipPolicy, repeat bool, oracle func(context.Context) (VMResourceNativeRecord, error)) error {
	return resourceStepRecords(ctx, r, evidence, name, desired, policy, repeat, singleOracle(oracle))
}

// resourceStepRecords is resourceStep for scenarios whose independent proof
// spans several native records, such as a shadow oracle and a real login.
func resourceStepRecords(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence, name string, desired *resourcev1.ResourceDesiredState, policy *resourcev1.OwnershipPolicy, repeat bool, oracle func(context.Context) ([]VMResourceNativeRecord, error)) error {
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: name, StartedAt: time.Now().UTC()})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	fail := func(err error) error {
		s.Failure = err.Error()
		s.Native = append(s.Native, r.failureDiagnostics(ctx)...)
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
	s.Native = native
	s.FinishedAt = time.Now().UTC()
	s.Passed = true
	return nil
}

// resourceReleaseStep clears the assignment and requires an attested release
// whose native result an independent oracle then confirms.
func resourceReleaseStep(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence, name string, ref *resourcev1.ResourceRef, oracle func(context.Context) (VMResourceNativeRecord, error)) error {
	return resourceReleaseStepRecords(ctx, r, evidence, name, ref, singleOracle(oracle))
}

func resourceReleaseStepRecords(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence, name string, ref *resourcev1.ResourceRef, oracle func(context.Context) ([]VMResourceNativeRecord, error)) error {
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: name, StartedAt: time.Now().UTC()})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	var err error
	s.Release, err = r.release(ctx, ref, false)
	if err != nil {
		s.Failure = err.Error()
		s.Native = append(s.Native, r.failureDiagnostics(ctx)...)
		return fmt.Errorf("%s: %w", name, err)
	}
	native, err := oracle(ctx)
	if err != nil {
		s.Failure = err.Error()
		s.Native = append(s.Native, r.failureDiagnostics(ctx)...)
		return fmt.Errorf("%s: %w", name, err)
	}
	s.Native = native
	s.FinishedAt = time.Now().UTC()
	s.Passed = true
	return nil
}

func singleOracle(oracle func(context.Context) (VMResourceNativeRecord, error)) func(context.Context) ([]VMResourceNativeRecord, error) {
	return func(ctx context.Context) ([]VMResourceNativeRecord, error) {
		native, err := oracle(ctx)
		if err != nil {
			return nil, err
		}
		return []VMResourceNativeRecord{native}, nil
	}
}

// resourceRefusalStep assigns a desired state that the device must refuse
// before any native effect: the device-signed outcome is a failure that never
// started, and the independent oracle bytes before the assignment, after the
// refusal and after the clear's release settles are identical.
func resourceRefusalStep(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence, name string, desired *resourcev1.ResourceDesiredState, policy *resourcev1.OwnershipPolicy, oracle func(context.Context) (VMResourceNativeRecord, error)) error {
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: name, StartedAt: time.Now().UTC()})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	fail := func(err error) error {
		s.Failure = err.Error()
		s.Native = append(s.Native, r.failureDiagnostics(ctx)...)
		return fmt.Errorf("%s: %w", name, err)
	}
	before, err := oracle(ctx)
	if err != nil {
		return fail(err)
	}
	if err := r.assign(ctx, desired, policy); err != nil {
		return fail(err)
	}
	action, err := r.action(ctx, true)
	s.Action = action
	if err != nil {
		return fail(err)
	}
	status := action.GetStatus()
	if action.GetStartAuthorizedAt() != nil || status.GetStartedAt() != nil || status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED {
		return fail(fmt.Errorf("refusal is not a failure before native effect: %s", status))
	}
	refused, err := oracle(ctx)
	if err != nil {
		return fail(err)
	}
	s.Release, err = r.settledRelease(ctx, desired.GetRef())
	if err != nil {
		return fail(err)
	}
	cleared, err := oracle(ctx)
	if err != nil {
		return fail(err)
	}
	if !bytes.Equal(before.Bytes, refused.Bytes) || !bytes.Equal(before.Bytes, cleared.Bytes) {
		return fail(errors.New("refused resource changed independent native state"))
	}
	before.Name, refused.Name, cleared.Name = "before-"+before.Name, "after-refusal-"+refused.Name, "after-clear-"+cleared.Name
	s.Native = []VMResourceNativeRecord{before, refused, cleared}
	s.FinishedAt = time.Now().UTC()
	s.Passed = true
	return nil
}

// settledRelease clears the assignment and waits until the release of ref is
// terminal, whether released or refused; refusal scenarios prove with their
// native oracle that the clear path had no effect either.
func (r *resourceDispatch) settledRelease(ctx context.Context, ref *resourcev1.ResourceRef) (*adminv1.ResourceRelease, error) {
	sourceHead := r.head
	response, err := r.control.session.Admin.SetResourceAssignment(ctx, connect.NewRequest(&adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: r.device, ExpectedAssignmentId: proto.String(r.head), Clear: true, Reason: "refused native resource clear qualification"}))
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
			if release.GetSourceAssignmentId() == sourceHead && proto.Equal(release.GetRef(), ref) && (release.GetCompletedAt() != nil || release.GetState() == "release_conflict") {
				return release, nil
			}
		}
		if err := lifecycleDelay(ctx, 250*time.Millisecond); err != nil {
			return nil, fmt.Errorf("refused resource release did not settle: %w; last=%s", err, state)
		}
	}
}

// executorDiagnostics retains the installed executor's recent journal for a
// failed scenario. It is diagnostic context, never qualification evidence.
func executorDiagnostics(ctx context.Context, vm *guestVM) VMResourceNativeRecord {
	data, err := vm.run(ctx, "sudo -n journalctl --no-pager -o short-iso -n 50000 2>&1 | grep -E 'lindm-(executor|agent|package|resource|observe)|useradd|groupadd|usermod|userdel|chage|authselect|pam-auth|scriptlet|lindm-resource-crash' | grep -v -e ' audit' -e ' sudo\\[' | tail -n 200", nil, 256<<10, 30*time.Second)
	if err != nil {
		data = []byte(err.Error())
	}
	return resourceNativeRecord("failure-diagnostic-executor-journal", data)
}

// failureDiagnostics adds a lane's own native diagnostic context, such as the
// firewall guard journal and ruleset, to the executor journal.
func (r *resourceDispatch) failureDiagnostics(ctx context.Context) []VMResourceNativeRecord {
	records := []VMResourceNativeRecord{executorDiagnostics(ctx, r.vm)}
	if r.diagnostics != nil {
		records = append(records, r.diagnostics(ctx)...)
	}
	return records
}

// resourceAdoptionPolicy adopts pre-existing native state under an approved
// assignment and restores the recorded baseline on release.
func resourceAdoptionPolicy() *resourcev1.OwnershipPolicy {
	return &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED}
}

func (r *resourceDispatch) fresh() {
	r.profile, r.resource, r.revision = uuid.NewString(), uuid.NewString(), ""
}

// nativeRecordLine returns the first record line starting with prefix.
func nativeRecordLine(record VMResourceNativeRecord, prefix string) string {
	for line := range strings.SplitSeq(string(record.Bytes), "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

// withRecordLine additionally requires the oracle's line with prefix to equal
// the baseline's, e.g. a password hash digest preserved under a lock.
func withRecordLine(oracle func(context.Context) (VMResourceNativeRecord, error), baseline VMResourceNativeRecord, prefix string) func(context.Context) (VMResourceNativeRecord, error) {
	return func(ctx context.Context) (VMResourceNativeRecord, error) {
		record, err := oracle(ctx)
		if err != nil {
			return record, err
		}
		if want := nativeRecordLine(baseline, prefix); want == "" || nativeRecordLine(record, prefix) != want {
			return record, fmt.Errorf("native %q differs from the recorded baseline", prefix)
		}
		return record, nil
	}
}

// withBaseline requires the oracle bytes to equal the recorded baseline.
func withBaseline(oracle func(context.Context) (VMResourceNativeRecord, error), baseline VMResourceNativeRecord) func(context.Context) (VMResourceNativeRecord, error) {
	return func(ctx context.Context) (VMResourceNativeRecord, error) {
		record, err := oracle(ctx)
		if err != nil {
			return record, err
		}
		if !bytes.Equal(record.Bytes, baseline.Bytes) {
			return record, fmt.Errorf("native state differs from the recorded baseline: %q", record.Bytes)
		}
		return record, nil
	}
}

func resourceGroupDesired(present bool) *resourcev1.ResourceDesiredState {
	group := &resourcev1.LocalGroupDesired{Name: resourceLabGroup, Presence: resourcev1.Presence_PRESENCE_ABSENT}
	if present {
		group.Presence, group.Gid = resourcev1.Presence_PRESENCE_PRESENT, proto.Uint32(resourceLabGroupID)
	}
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, CanonicalKey: resourceLabGroup}, State: &resourcev1.ResourceDesiredState_LocalGroup{LocalGroup: group}}
}

// labUserDesired creates a locked user with its home under the approved root.
func labUserDesired(name string, uid uint32, shell string) *resourcev1.ResourceDesiredState {
	user := &resourcev1.LocalUserDesired{
		Name: name, Presence: resourcev1.Presence_PRESENCE_PRESENT, Uid: proto.Uint32(uid),
		PrimaryGroup: proto.String(resourceLabPrimary), HomeDirectory: proto.String(resourceLabHomeRoot + "/" + name),
		Shell:    &resourcev1.LoginShell{InstalledShell: shell},
		Password: &resourcev1.PasswordState{State: &resourcev1.PasswordState_Locked{Locked: &resourcev1.LockedPassword{}}},
		Home:     &resourcev1.HomePolicy{Creation: resourcev1.HomeCreation_HOME_CREATION_CREATE_IF_ABSENT, Mode: proto.Uint32(0o700), ApprovedRootId: resourceLabHomeRootID},
	}
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, CanonicalKey: name}, State: &resourcev1.ResourceDesiredState_LocalUser{LocalUser: user}}
}

// adoptedGroupDesired manages the pre-existing group's GID and, optionally,
// additive membership; unmanaged members are preserved.
func adoptedGroupDesired(gid uint32, members ...string) *resourcev1.ResourceDesiredState {
	group := &resourcev1.LocalGroupDesired{Name: resourceLabAdoptGroup, Presence: resourcev1.Presence_PRESENCE_PRESENT, Gid: proto.Uint32(gid)}
	if len(members) != 0 {
		group.Members = &resourcev1.MemberSet{LocalUserNames: members, Mode: resourcev1.SetMode_SET_MODE_ADDITIVE}
	}
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP, CanonicalKey: resourceLabAdoptGroup}, State: &resourcev1.ResourceDesiredState_LocalGroup{LocalGroup: group}}
}

// adoptedUserDesired manages the pre-existing user's shell and password lock
// and, when maxDays is nonzero, its maximum password age.
func adoptedUserDesired(maxDays uint32) *resourcev1.ResourceDesiredState {
	user := &resourcev1.LocalUserDesired{
		Name: resourceLabAdoptUser, Presence: resourcev1.Presence_PRESENCE_PRESENT,
		Shell:    &resourcev1.LoginShell{InstalledShell: "/bin/bash"},
		Password: &resourcev1.PasswordState{State: &resourcev1.PasswordState_Locked{Locked: &resourcev1.LockedPassword{}}},
	}
	if maxDays != 0 {
		user.Aging = &resourcev1.PasswordAging{MaxDays: proto.Uint32(maxDays)}
	}
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, CanonicalKey: resourceLabAdoptUser}, State: &resourcev1.ResourceDesiredState_LocalUser{LocalUser: user}}
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

func userOracle(name string, uid uint32, shell string, present bool) func(context.Context, *guestVM) (VMResourceNativeRecord, error) {
	home := resourceLabHomeRoot + "/" + name
	return func(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
		// Release never deletes home data; it remains as created, owned by
		// the removed numeric identity.
		command := "if getent passwd " + name + "; then exit 1; fi; if grep '^" + name + ":' /etc/passwd /etc/shadow; then exit 1; fi; test -d " + home + "; stat -c '%n %a %u %g' " + home + "; printf 'user-absent-home-preserved\\n'"
		if present {
			command = fmt.Sprintf("test \"$(getent passwd %s)\" = '%s:x:%d:%d::%s:%s'; id %s; test \"$(stat -c '%%a %%u %%g' %s)\" = '700 %d %d'; stat -c '%%n %%a %%u %%g' %s; getent shadow %s | cut -d: -f1,2 | grep -E '^%s:!'; grep -Fx %s /etc/shells",
				name, name, uid, resourceLabPrimaryID, home, shell, name, home, uid, resourceLabPrimaryID, home, name, name, nativeQuote(shell))
		}
		return resourceOracle(ctx, vm, "native-user-database-home-shadow", command)
	}
}

// accountDatabaseOracle binds the complete local account databases by digest
// plus a scenario-specific native check; shadow content is never printed.
func accountDatabaseOracle(check string) func(context.Context, *guestVM) (VMResourceNativeRecord, error) {
	return func(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
		return resourceOracle(ctx, vm, "native-account-databases-unchanged", "sha256sum /etc/passwd /etc/shadow /etc/group /etc/gshadow; ls -1A "+resourceLabHomeRoot+"; "+check)
	}
}

// adoptedGroupOracle checks the pre-existing group's GID and member set and
// records its exact /etc/group line and /etc/gshadow digest.
func adoptedGroupOracle(gid uint32, members string) func(context.Context, *guestVM) (VMResourceNativeRecord, error) {
	return func(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
		g := resourceLabAdoptGroup
		command := "line=$(getent group " + g + "); printf '%s\\n' \"$line\"; test \"$(printf '%s' \"$line\" | cut -d: -f3)\" = " + strconv.FormatUint(uint64(gid), 10) +
			"; test \"$(printf '%s' \"$line\" | cut -d: -f4 | tr , '\\n' | sort | paste -sd, -)\" = " + nativeQuote(members) +
			"; grep '^" + g + ":' /etc/group; printf 'gshadow-sha256 %s\\n' \"$(grep '^" + g + ":' /etc/gshadow | sha256sum | cut -d' ' -f1)\"; grep '^" + g + ":' /etc/gshadow | cut -d: -f1,4; id -nG " + resourceLabForeign + "; id -nG " + resourceLabAdoptUser
		return resourceOracle(ctx, vm, "native-adopted-group", command)
	}
}

// adoptedUserOracle checks the pre-existing user's shell, password lock and
// maximum age. Only the SHA-256 of the shadow hash (without a lock prefix) is
// recorded, never the hash itself.
func adoptedUserOracle(shell string, locked bool, maxDays string) func(context.Context, *guestVM) (VMResourceNativeRecord, error) {
	return func(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
		u := resourceLabAdoptUser
		lock := "case \"$field\" in '!'*|'*'*) exit 1;; esac; printf 'locked no\\n'"
		if locked {
			lock = "case \"$field\" in '!'*) ;; *) exit 1;; esac; printf 'locked yes\\n'"
		}
		command := "line=$(getent passwd " + u + "); printf '%s\\n' \"$line\"; test \"$(printf '%s' \"$line\" | cut -d: -f7)\" = " + nativeQuote(shell) +
			"; field=$(getent shadow " + u + " | cut -d: -f2); " + lock +
			"; printf 'hash-sha256 %s\\n' \"$(printf '%s' \"${field#!}\" | sha256sum | cut -d' ' -f1)\"; case \"${field#!}\" in '$6$'*|'$y$'*) ;; *) exit 1;; esac" +
			"; getent shadow " + u + " | cut -d: -f1,3-; test \"$(getent shadow " + u + " | cut -d: -f5)\" = " + maxDays +
			"; id " + u + "; stat -c '%n %a %u %g' " + resourceLabHomeRoot + "/" + u
		return resourceOracle(ctx, vm, "native-adopted-user-shadow-digest", command)
	}
}

func withVM(vm *guestVM, oracle func(context.Context, *guestVM) (VMResourceNativeRecord, error)) func(context.Context) (VMResourceNativeRecord, error) {
	return func(ctx context.Context) (VMResourceNativeRecord, error) { return oracle(ctx, vm) }
}

func exerciseResourceAccounts(ctx context.Context, r *resourceDispatch, groups, users *VMResourceKindEvidence) error {
	if err := exerciseResourceGroups(ctx, r, groups); err != nil {
		return err
	}
	r.fresh()
	if err := resourceStep(ctx, r, users, "create-locked-home", labUserDesired(resourceLabUser, resourceLabUserID, "/bin/sh"), resourceCreatePolicy(), false, withVM(r.vm, userOracle(resourceLabUser, resourceLabUserID, "/bin/sh", true))); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, users, "reconcile-shell", labUserDesired(resourceLabUser, resourceLabUserID, "/bin/bash"), resourceCreatePolicy(), false, withVM(r.vm, userOracle(resourceLabUser, resourceLabUserID, "/bin/bash", true))); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, users, "repeat", labUserDesired(resourceLabUser, resourceLabUserID, "/bin/bash"), resourceCreatePolicy(), true, withVM(r.vm, userOracle(resourceLabUser, resourceLabUserID, "/bin/bash", true))); err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, users, "release-preserves-home", labUserDesired(resourceLabUser, resourceLabUserID, "/bin/bash").GetRef(), withVM(r.vm, userOracle(resourceLabUser, 0, "", false))); err != nil {
		return err
	}
	// A UID held by a different, unmanaged account is never shared.
	r.fresh()
	if err := resourceRefusalStep(ctx, r, users, "uid-collision-refused", labUserDesired(resourceLabClash, resourceLabForeignID, "/bin/sh"), resourceCreatePolicy(), withVM(r.vm, accountDatabaseOracle(fmt.Sprintf("test \"$(getent passwd %d | cut -d: -f1)\" = %s; getent passwd %d; if getent passwd %s; then exit 1; fi; test ! -e %s/%s", resourceLabForeignID, resourceLabForeign, resourceLabForeignID, resourceLabClash, resourceLabHomeRoot, resourceLabClash)))); err != nil {
		return err
	}
	// An owned account replaced outside lindm under the same name with another
	// UID is a reused native identity, not the account lindm created.
	r.fresh()
	if err := resourceStep(ctx, r, users, "reuse-create", labUserDesired(resourceLabReuse, resourceLabReuseID, "/bin/sh"), resourceCreatePolicy(), false, withVM(r.vm, userOracle(resourceLabReuse, resourceLabReuseID, "/bin/sh", true))); err != nil {
		return err
	}
	if err := lifecycleCommand(ctx, r.vm, "replace the owned account outside lindm", fmt.Sprintf("userdel %s; useradd -M -N -u %d -g %s -d %s/%s -s /bin/sh %s", resourceLabReuse, resourceLabReuseOtherID, resourceLabPrimary, resourceLabHomeRoot, resourceLabReuse, resourceLabReuse)); err != nil {
		return err
	}
	if err := resourceRefusalStep(ctx, r, users, "owned-identity-reuse-refused", labUserDesired(resourceLabReuse, resourceLabReuseID, "/bin/bash"), resourceCreatePolicy(), withVM(r.vm, accountDatabaseOracle(fmt.Sprintf("test \"$(getent passwd %s | cut -d: -f3,7)\" = '%d:/bin/sh'; getent passwd %s", resourceLabReuse, resourceLabReuseOtherID, resourceLabReuse)))); err != nil {
		return err
	}
	if err := lifecycleCommand(ctx, r.vm, "remove the externally recreated account", "userdel "+resourceLabReuse); err != nil {
		return err
	}
	if err := exerciseUserAdoption(ctx, r, users); err != nil {
		return err
	}
	// Delivered password hashes are qualified by the secret-password lane.
	return qualifyResourceEvidence(users, []string{"create-locked-home", "reconcile-shell", "repeat", "release-preserves-home", "uid-collision-refused", "reuse-create", "owned-identity-reuse-refused", "adopt-existing-user", "reconcile-adopted-aging", "repeat-adopted-user", "release-restores-user-baseline"})
}

func exerciseResourceGroups(ctx context.Context, r *resourceDispatch, groups *VMResourceKindEvidence) error {
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
	baseline, err := adoptedGroupOracle(resourceLabAdoptGroupID, resourceLabForeign)(ctx, r.vm)
	if err != nil {
		return err
	}
	r.fresh()
	if err := resourceStep(ctx, r, groups, "adopt-existing-group", adoptedGroupDesired(resourceLabAdoptGroupNewID), resourceAdoptionPolicy(), false, withVM(r.vm, adoptedGroupOracle(resourceLabAdoptGroupNewID, resourceLabForeign))); err != nil {
		return err
	}
	groups.Scenarios[len(groups.Scenarios)-1].Native = append([]VMResourceNativeRecord{baseline}, groups.Scenarios[len(groups.Scenarios)-1].Native...)
	members := resourceLabAdoptUser + "," + resourceLabForeign
	if err := resourceStep(ctx, r, groups, "reconcile-adopted-members", adoptedGroupDesired(resourceLabAdoptGroupNewID, resourceLabAdoptUser), resourceAdoptionPolicy(), false, withVM(r.vm, adoptedGroupOracle(resourceLabAdoptGroupNewID, members))); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, groups, "repeat-adopted-group", adoptedGroupDesired(resourceLabAdoptGroupNewID, resourceLabAdoptUser), resourceAdoptionPolicy(), true, withVM(r.vm, adoptedGroupOracle(resourceLabAdoptGroupNewID, members))); err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, groups, "release-restores-group-baseline", adoptedGroupDesired(resourceLabAdoptGroupNewID).GetRef(), withBaseline(withVM(r.vm, adoptedGroupOracle(resourceLabAdoptGroupID, resourceLabForeign)), baseline)); err != nil {
		return err
	}
	groups.Scenarios[len(groups.Scenarios)-1].Native = append([]VMResourceNativeRecord{baseline}, groups.Scenarios[len(groups.Scenarios)-1].Native...)
	groups.Unproven = nil
	return qualifyResourceEvidence(groups, []string{"create", "repeat", "release-created-group", "adopt-existing-group", "reconcile-adopted-members", "repeat-adopted-group", "release-restores-group-baseline"})
}

// exerciseUserAdoption adopts a pre-existing user with a real password hash,
// locks it without changing the hash, manages aging and restores the exact
// baseline (passwd line, shadow digest and aging, memberships, home) on release.
func exerciseUserAdoption(ctx context.Context, r *resourceDispatch, users *VMResourceKindEvidence) error {
	baselineOracle := withVM(r.vm, adoptedUserOracle("/bin/sh", false, "120"))
	baseline, err := baselineOracle(ctx)
	if err != nil {
		return err
	}
	r.fresh()
	if err := resourceStep(ctx, r, users, "adopt-existing-user", adoptedUserDesired(0), resourceAdoptionPolicy(), false, withRecordLine(withVM(r.vm, adoptedUserOracle("/bin/bash", true, "120")), baseline, "hash-sha256 ")); err != nil {
		return err
	}
	users.Scenarios[len(users.Scenarios)-1].Native = append([]VMResourceNativeRecord{baseline}, users.Scenarios[len(users.Scenarios)-1].Native...)
	if err := resourceStep(ctx, r, users, "reconcile-adopted-aging", adoptedUserDesired(90), resourceAdoptionPolicy(), false, withRecordLine(withVM(r.vm, adoptedUserOracle("/bin/bash", true, "90")), baseline, "hash-sha256 ")); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, users, "repeat-adopted-user", adoptedUserDesired(90), resourceAdoptionPolicy(), true, withRecordLine(withVM(r.vm, adoptedUserOracle("/bin/bash", true, "90")), baseline, "hash-sha256 ")); err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, users, "release-restores-user-baseline", adoptedUserDesired(90).GetRef(), withBaseline(baselineOracle, baseline)); err != nil {
		return err
	}
	users.Scenarios[len(users.Scenarios)-1].Native = append([]VMResourceNativeRecord{baseline}, users.Scenarios[len(users.Scenarios)-1].Native...)
	return nil
}

func resourceSysctlDesired(key, value string) *resourcev1.ResourceDesiredState {
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSCTL, CanonicalKey: key}, State: &resourcev1.ResourceDesiredState_Sysctl{Sysctl: &resourcev1.SysctlDesired{Key: key, Value: value, Persistent: true}}}
}

// sysctlStanza is the provider's owned persistence file, derived here
// independently from the documented naming rule.
func sysctlStanza(key string) string {
	return fmt.Sprintf("/etc/sysctl.d/60-lindm-%x.conf", sha256.Sum256([]byte(key)))
}

// sysctlCommand checks the live value, the owned stanza and systemd-sysctl's
// merged configuration. An empty value means the pre-management value recorded
// in prior and no owned stanza.
func sysctlCommand(key, prior, value string) string {
	stanza := sysctlStanza(key)
	if value == "" {
		return "prior=$(cat " + prior + "); test \"$(sysctl -n " + key + ")\" = \"$prior\"; test ! -e " + stanza + "; printf 'restored %s %s\\n' " + key + " \"$prior\""
	}
	return "test \"$(sysctl -n " + key + ")\" = " + nativeQuote(value) + "; sysctl " + key + "; grep -Fx " + nativeQuote(key+" = "+value) + " " + stanza + "; stat -c '%n %a %u %g' " + stanza + "; /usr/lib/systemd/systemd-sysctl --cat-config | grep -F " + nativeQuote(key)
}

func sysctlOracle(key, prior, value string) func(context.Context, *guestVM) (VMResourceNativeRecord, error) {
	return func(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
		command := sysctlCommand(key, prior, value)
		if strings.HasPrefix(key, "net.") {
			// net.* keys are per network namespace. The oracle, like the
			// executor and the helper for net.* keys, runs in the host (PID 1)
			// namespace; the value a fresh namespace starts with is recorded
			// only as context.
			command = "test \"$(readlink /proc/self/ns/net)\" = \"$(readlink /proc/1/ns/net)\"; printf 'netns %s\\n' \"$(readlink /proc/1/ns/net)\"; printf 'fresh-netns-value %s\\n' \"$(unshare --net sysctl -n " + key + ")\"; " + command
		}
		return resourceOracle(ctx, vm, "native-sysctl-live-persistent", command)
	}
}

func exerciseResourceSysctl(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence) error {
	key, prior := resourceLabSysctlKey, resourceLabSysctlPrior
	r.fresh()
	if err := resourceStep(ctx, r, evidence, "set-persistent", resourceSysctlDesired(key, "17"), resourceAdoptionPolicy(), false, withVM(r.vm, sysctlOracle(key, prior, "17"))); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "reconcile", resourceSysctlDesired(key, "23"), resourceAdoptionPolicy(), false, withVM(r.vm, sysctlOracle(key, prior, "23"))); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "repeat", resourceSysctlDesired(key, "23"), resourceAdoptionPolicy(), true, withVM(r.vm, sysctlOracle(key, prior, "23"))); err != nil {
		return err
	}
	if err := sysctlRebootStep(ctx, r, evidence, resourceSysctlDesired(key, "23")); err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, evidence, "release-after-reboot-restores-prior", resourceSysctlDesired(key, "23").GetRef(), withVM(r.vm, sysctlOracle(key, prior, ""))); err != nil {
		return err
	}
	net, netPrior := resourceLabNetKey, resourceLabNetPrior
	r.fresh()
	if err := resourceStep(ctx, r, evidence, "net-key-set-persistent", resourceSysctlDesired(net, "1"), resourceAdoptionPolicy(), false, withVM(r.vm, sysctlOracle(net, netPrior, "1"))); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "net-key-repeat", resourceSysctlDesired(net, "1"), resourceAdoptionPolicy(), true, withVM(r.vm, sysctlOracle(net, netPrior, "1"))); err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, evidence, "net-key-release-restores-prior", resourceSysctlDesired(net, "1").GetRef(), withVM(r.vm, sysctlOracle(net, netPrior, ""))); err != nil {
		return err
	}
	evidence.Unproven = nil
	return qualifyResourceEvidence(evidence, []string{"set-persistent", "reconcile", "repeat", "reboot-persists", "release-after-reboot-restores-prior", "net-key-set-persistent", "net-key-repeat", "net-key-release-restores-prior"})
}

// sysctlRebootStep reboots the guest: systemd-sysctl must apply the owned
// stanza at boot, and a fresh device observation (no start grant) must
// converge and report reboot persistence against the pre-boot ledger.
func sysctlRebootStep(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence, desired *resourcev1.ResourceDesiredState) error {
	const name = "reboot-persists"
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: name, StartedAt: time.Now().UTC()})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	fail := func(err error) error {
		s.Failure = err.Error()
		s.Native = append(s.Native, r.failureDiagnostics(ctx)...)
		return fmt.Errorf("%s: %w", name, err)
	}
	if r.reboot == nil {
		return fail(errors.New("device reboot is not wired"))
	}
	boot, err := firewallBootID(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	if err := r.reboot(ctx); err != nil {
		return fail(err)
	}
	if _, err := waitGuestExecutorReady(ctx, r.vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return fail(err)
	}
	d := desired.GetSysctl()
	booted, err := resourceOracle(ctx, r.vm, "after-boot-sysctl", "now=$(cat /proc/sys/kernel/random/boot_id); test \"$now\" != "+boot+"; printf 'boot %s -> %s\\n' "+boot+" \"$now\"; test \"$(systemctl show -P Result systemd-sysctl.service)\" = success; systemctl show -p ActiveState -p Result -p ExecMainStartTimestamp systemd-sysctl.service; "+sysctlCommand(d.GetKey(), resourceLabSysctlPrior, d.GetValue()))
	if err != nil {
		return fail(err)
	}
	if err := r.assign(ctx, desired, resourceAdoptionPolicy()); err != nil {
		return fail(err)
	}
	action, err := r.action(ctx, false)
	s.Action = action
	if err != nil {
		return fail(err)
	}
	if action.GetStartAuthorizedAt() != nil {
		return fail(errors.New("post-boot observation acquired a start grant"))
	}
	if !action.GetStatus().GetVerification().GetSysctl().GetRebootPersistenceVerified() {
		return fail(fmt.Errorf("device did not verify reboot persistence: %s", action.GetStatus().GetVerification()))
	}
	s.Native = []VMResourceNativeRecord{booted}
	s.FinishedAt = time.Now().UTC()
	s.Passed = true
	return nil
}

func resourceTimerDesired(schedule *resourcev1.TimerSchedule) *resourcev1.ResourceDesiredState {
	timer := &resourcev1.TimerDefinition{Unit: resourceLabTimer, Service: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_SERVICE, CanonicalKey: resourceLabTarget}, Schedule: schedule, Enabled: true}
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SYSTEMD_DEFINITION, CanonicalKey: "timer/" + resourceLabTimer}, State: &resourcev1.ResourceDesiredState_SystemdDefinition{SystemdDefinition: &resourcev1.SystemdDefinitionDesired{Presence: resourcev1.Presence_PRESENCE_PRESENT, Definition: &resourcev1.SystemdDefinitionDesired_Timer{Timer: timer}}}}
}

func intervalSchedule(seconds uint32) *resourcev1.TimerSchedule {
	return &resourcev1.TimerSchedule{Schedule: &resourcev1.TimerSchedule_IntervalSeconds{IntervalSeconds: seconds}}
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

// guestClock reads the guest's exact realtime clock, in seconds; timer windows
// need the unadjusted value.
func guestClock(ctx context.Context, vm *guestVM) (int64, error) {
	data, err := vm.run(ctx, "date +%s", nil, 64, 10*time.Second)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

// targetRunsCommand counts the inert target's distinct systemd invocations
// (PID 1 job messages carry INVOCATION_ID) logged in [since, until].
func targetRunsCommand(since, until int64) string {
	window := "--since @" + strconv.FormatInt(since, 10)
	if until != 0 {
		window += " --until @" + strconv.FormatInt(until, 10)
	}
	return "journalctl -b -o json " + window + " UNIT=" + resourceLabTarget + " | grep -o '\"INVOCATION_ID\":\"[0-9a-f]*\"' | sort -u | wc -l"
}

// waitTargetRuns polls, with a deadline, until the target ran at least runs
// times since the given guest time.
func waitTargetRuns(ctx context.Context, vm *guestVM, since int64, runs int, deadline time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	for {
		data, err := vm.run(ctx, "sudo -n /bin/sh -c "+nativeQuote(targetRunsCommand(since, 0)), nil, 64, 15*time.Second)
		if err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && n >= runs {
				return nil
			}
		}
		if err := lifecycleDelay(ctx, 2*time.Second); err != nil {
			return fmt.Errorf("timer target did not run %d times: %w; last=%q", runs, err, data)
		}
	}
}

// timerFiredCommand records the timer's schedule and trigger, the target's
// last result and its invocation journal since the given guest time.
func timerFiredCommand(since int64, runs int, schedule string) string {
	return "n=$(" + targetRunsCommand(since, 0) + "); printf 'target-invocations %s\\n' \"$n\"; test \"$n\" -ge " + strconv.Itoa(runs) +
		"; shown=$(systemctl show -p TimersMonotonic -p TimersCalendar -p LastTriggerUSec -p Unit " + resourceLabTimer + "); printf '%s\\n' \"$shown\"; printf '%s\\n' \"$shown\" | grep -qF " + nativeQuote(schedule) +
		"; test \"$(systemctl show -P LastTriggerUSecMonotonic " + resourceLabTimer + ")\" != 0" +
		"; test \"$(systemctl show -P Result " + resourceLabTarget + ")\" = success; systemctl show -p Result -p ExecMainStartTimestamp -p ExecMainStatus -p InvocationID " + resourceLabTarget +
		"; journalctl -b --no-pager -o short-iso --since @" + strconv.FormatInt(since, 10) + " UNIT=" + resourceLabTarget
}

// timerFiringStep assigns a timer and proves, beyond the unit file, that
// systemd actually runs the target service on its schedule.
func timerFiringStep(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence, name string, desired *resourcev1.ResourceDesiredState, fired func(ctx context.Context, before, after int64) (VMResourceNativeRecord, error)) error {
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: name, StartedAt: time.Now().UTC()})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	fail := func(err error) error {
		s.Failure = err.Error()
		s.Native = append(s.Native, r.failureDiagnostics(ctx)...)
		return fmt.Errorf("%s: %w", name, err)
	}
	before, err := guestClock(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	if err := r.assign(ctx, desired, resourceCreatePolicy()); err != nil {
		return fail(err)
	}
	action, err := r.action(ctx, false)
	s.Action = action
	if err != nil {
		return fail(err)
	}
	after, err := guestClock(ctx, r.vm)
	if err != nil {
		return fail(err)
	}
	native, err := fired(ctx, before, after)
	if err != nil {
		return fail(err)
	}
	s.Native = []VMResourceNativeRecord{native}
	s.FinishedAt = time.Now().UTC()
	s.Passed = true
	return nil
}

// exerciseTimerFiring runs a monotonic timer until it has fired twice
// (OnActiveSec, then OnUnitActiveSec), switches it to a UTC calendar time a few
// minutes ahead and waits for that firing, then releases it.
func exerciseTimerFiring(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence) error {
	r.fresh()
	const interval = 10
	if err := timerFiringStep(ctx, r, evidence, "timer-interval-fires-target", resourceTimerDesired(intervalSchedule(interval)), func(ctx context.Context, before, _ int64) (VMResourceNativeRecord, error) {
		if err := waitTargetRuns(ctx, r.vm, before, 2, 3*time.Minute); err != nil {
			return VMResourceNativeRecord{}, err
		}
		return resourceOracle(ctx, r.vm, "native-timer-fired-target", timerFiredCommand(before, 2, "OnUnitActiveUSec=10s"))
	}); err != nil {
		return err
	}
	now, err := guestClock(ctx, r.vm)
	if err != nil {
		return err
	}
	// The calendar minute leaves the switch at least two minutes to converge
	// so that the firing cannot be missed (Persistent=no never catches up).
	scheduled := (now+120)/60*60 + 60
	at := time.Unix(scheduled, 0).UTC()
	spec := fmt.Sprintf("OnCalendar=*-*-* %02d:%02d:00 UTC", at.Hour(), at.Minute())
	daily := &resourcev1.TimerSchedule{Schedule: &resourcev1.TimerSchedule_Daily{Daily: &resourcev1.DailyTimerSchedule{Hour: uint32(at.Hour()), Minute: uint32(at.Minute())}}}
	if err := timerFiringStep(ctx, r, evidence, "timer-calendar-fires-target", resourceTimerDesired(daily), func(ctx context.Context, _, after int64) (VMResourceNativeRecord, error) {
		if after >= scheduled {
			return VMResourceNativeRecord{}, errors.New("calendar timer switch converged after its scheduled minute")
		}
		wait := time.Duration(scheduled-after)*time.Second + 2*time.Minute
		if err := waitTargetRuns(ctx, r.vm, scheduled, 1, wait); err != nil {
			return VMResourceNativeRecord{}, err
		}
		// No run between the converged switch and the scheduled minute: the
		// firing is the calendar event, not the replaced interval.
		quiet := "q=$(" + targetRunsCommand(after+1, scheduled-1) + "); printf 'runs-before-scheduled %s\\n' \"$q\"; test \"$q\" = 0; printf 'scheduled %s\\n' " + at.Format(time.RFC3339) + "; "
		return resourceOracle(ctx, r.vm, "native-timer-calendar-fired-target", quiet+timerFiredCommand(scheduled, 1, spec))
	}); err != nil {
		return err
	}
	return resourceReleaseStep(ctx, r, evidence, "timer-fired-release", resourceTimerDesired(daily).GetRef(), withVM(r.vm, timerOracle("")))
}

func exerciseResourceDefinitions(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence) error {
	r.fresh()
	if err := resourceStep(ctx, r, evidence, "timer-create-enabled", resourceTimerDesired(intervalSchedule(3600)), resourceCreatePolicy(), false, withVM(r.vm, timerOracle("1h"))); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "timer-reconcile-interval", resourceTimerDesired(intervalSchedule(7200)), resourceCreatePolicy(), false, withVM(r.vm, timerOracle("2h"))); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "timer-repeat", resourceTimerDesired(intervalSchedule(7200)), resourceCreatePolicy(), true, withVM(r.vm, timerOracle("2h"))); err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, evidence, "timer-release", resourceTimerDesired(intervalSchedule(7200)).GetRef(), withVM(r.vm, timerOracle(""))); err != nil {
		return err
	}
	if err := exerciseTimerFiring(ctx, r, evidence); err != nil {
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
	return qualifyResourceEvidence(evidence, []string{"timer-create-enabled", "timer-reconcile-interval", "timer-repeat", "timer-release", "timer-interval-fires-target", "timer-calendar-fires-target", "timer-fired-release", "drop-in-create", "drop-in-reconcile", "drop-in-release"})
}

// ResourceKindSelection parses the connected lane's explicit kind groups.
func ResourceKindSelection(value string) (map[string]bool, error) {
	selected := make(map[string]bool)
	for name := range strings.SplitSeq(value, ",") {
		switch name {
		case "packages", "files", "modules", "accounts", "sysctl", "definitions", "password", "firewall", "secret-password", "local-admin", "os-update":
			selected[name] = true
		default:
			return nil, fmt.Errorf("unknown resource lane kind %q", name)
		}
	}
	return selected, nil
}
