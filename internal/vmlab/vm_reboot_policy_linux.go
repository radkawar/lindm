// SPDX-License-Identifier: Apache-2.0

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
	"lindm/internal/platform"
	"lindm/internal/resource"
)

// VMRebootPolicyResult is deliberately not an assistance qualification. Fixture
// carries image/package/runtime and bound screenshots; its Passed stays false.
// The employee click is QMP input on an actual graphical guest, not physical QA.
type VMRebootPolicyResult struct {
	Fixture              *VMAssistanceResult         `json:"desktop_fixture"`
	Policy               VMResourceKindEvidence      `json:"reboot_policy"`
	EmployeeClick        *assistanceScenarioEvidence `json:"employee_interaction"`
	Prerequisite         []VMResourceNativeRecord    `json:"reboot_prerequisite"`
	PrerequisiteBoundary string                      `json:"prerequisite_boundary"`
	BootBefore           string                      `json:"boot_before"`
	BootAfter            string                      `json:"boot_after"`
	Passed               bool                        `json:"passed"`
	Failure              string                      `json:"failure,omitempty"`
}

// Follow-on observations remain bound to the accepted signed policy that
// installed the timer. They do not fabricate another policy execution.
func (proof *VMRebootPolicyResult) scenario(ctx context.Context, r *resourceDispatch, name string) (*VMResourceScenario, func(error) error) {
	scenario, fail := firewallScenario(ctx, r, &proof.Policy, name)
	scenario.Action = proof.Policy.Scenarios[0].Action
	return scenario, fail
}

func exerciseDesktopRebootPolicy(ctx context.Context, vm *EncryptedVM, screen *assistanceScreen, control *vmControlPlane, release *platform.Release, fixture *VMAssistanceResult, proof *VMRebootPolicyResult) error {
	if err := release.Gate(platform.OSUpdate); err != nil {
		return err
	}
	rpm := newResourcePackaging(release.Native().Packages.Backend, fixture.Architecture)
	proof.Policy.Kind = resourcev1.ResourceKind_RESOURCE_KIND_OS_UPDATE_POLICY
	proof.Policy.Unproven = []string{"Physical employee interaction, suspend across the restart time, and real-clock DST transitions are not qualified by this VM lane."}
	r := &resourceDispatch{vm: vm.guest, control: control, device: fixture.DeviceID, profile: uuid.NewString(), resource: uuid.NewString()}
	r.diagnostics = func(ctx context.Context) []VMResourceNativeRecord {
		return []VMResourceNativeRecord{osUpdateDiagnostics(rpm)(ctx, vm.guest)}
	}
	if err := lifecycleCommand(ctx, vm.guest, "install signed native update prerequisites", osUpdatePrerequisiteScript(rpm)); err != nil {
		return err
	}
	if err := prepareRebootPrerequisite(ctx, vm.guest, rpm, proof); err != nil {
		return err
	}
	if err := enableOSUpdateProvider(ctx, vm.guest); err != nil {
		return err
	}
	zone, err := time.LoadLocation(osUpdateLabZone)
	if err != nil {
		return err
	}
	start := osUpdateWindowStart(time.Now())
	restartStart := start.Add(30 * time.Minute)
	desired := osUpdateDesired(zone, resourcev1.UpdateSelection_UPDATE_SELECTION_ALL, start, 0)
	update := desired.GetOsUpdate()
	update.Maintenance.DurationMinutes = 15
	local := restartStart.In(zone)
	update.RebootPolicy.MaxDelayMinutes = 120
	update.RebootPolicy.RebootWindow = &resourcev1.MaintenanceWindow{TimeZone: osUpdateLabZone, Weekdays: []resourcev1.Weekday{resourcev1.Weekday(int32(local.Weekday()+6)%7 + 1)}, LocalStartMinute: uint32(local.Hour()*60 + local.Minute()), DurationMinutes: 90}
	update.RebootPolicy.EmployeeDeferral = &resourcev1.OSUpdateRebootDeferral{MaxDeferrals: 1, DelayMinutes: 5}
	if err := resourceStep(ctx, r, &proof.Policy, "signed-independent-reboot-window", desired, resourceCreatePolicy(), false, withVM(vm.guest, osUpdateInstalledOracle(rpm, zone, start))); err != nil {
		return err
	}
	proof.Policy.Scenarios[0].Native = append(proof.Policy.Scenarios[0].Native, proof.Prerequisite...)
	scenario, fail := proof.scenario(ctx, r, "native-update-and-reboot-window")
	run, err := waitOSUpdateWindowRun(ctx, vm.guest, start, osUpdateRunDeadline)
	if err != nil {
		return fail(err)
	}
	scenario.Native = append(scenario.Native, run)
	oracle, err := nativeRebootOracle(rpm)(ctx, vm.guest)
	if err == nil {
		scenario.Native = append(scenario.Native, oracle)
	}
	if err != nil || nativeRecordLine(oracle, "reboot-required ") != "reboot-required yes" {
		return fail(errors.Join(errors.New("native reboot requirement is absent after the timer run; cannot qualify reboot policy"), err))
	}
	schedule, kind, at, err := logindScheduleOracle(ctx, vm.guest)
	if err != nil || kind != "reboot" || at.Before(restartStart) || !at.Before(restartStart.Add(90*time.Minute)) {
		return fail(errors.Join(fmt.Errorf("native schedule %s %s outside independent restart window", kind, at), err))
	}
	state, stateRecord, err := readRebootPolicyState(ctx, vm.guest)
	if err != nil {
		return fail(err)
	}
	if state.GetReboot().GetDeferralsUsed() != 0 || !state.GetReboot().GetScheduledFor().AsTime().Equal(at) {
		return fail(errors.New("initial native schedule differs from protected reboot ownership"))
	}
	proof.BootBefore = state.GetReboot().GetBootId()
	passScenario(scenario, schedule, stateRecord)
	if err := clickRebootDeferral(ctx, vm, screen, r, proof, state); err != nil {
		return err
	}
	return finishRebootPolicy(ctx, vm, r, proof)
}

func readRebootPolicyState(ctx context.Context, vm *guestVM) (*agentv1.OSUpdateRunState, VMResourceNativeRecord, error) {
	data, err := vm.run(ctx, "sudo -n cat "+resource.OSUpdateRunStatePath, nil, 8<<20, 10*time.Second)
	if err != nil {
		return nil, VMResourceNativeRecord{}, err
	}
	state := new(agentv1.OSUpdateRunState)
	if err := proto.Unmarshal(data, state); err != nil {
		return nil, VMResourceNativeRecord{}, err
	}
	return state, resourceNativeRecord("protected-reboot-state", data), nil
}

func clickRebootDeferral(ctx context.Context, vm *EncryptedVM, screen *assistanceScreen, r *resourceDispatch, proof *VMRebootPolicyResult, before *agentv1.OSUpdateRunState) error {
	scenario, fail := proof.scenario(ctx, r, "employee-deferral-and-executor-restart")
	proof.EmployeeClick = &assistanceScenarioEvidence{Name: "reboot-policy"}
	image, banner, err := screen.waitBanner(ctx, 45*time.Second)
	if err != nil {
		return fail(err)
	}
	path, err := screen.save("reboot-policy-before-deferral", image)
	if err != nil {
		return fail(err)
	}
	proof.EmployeeClick.Screenshots = append(proof.EmployeeClick.Screenshots, path)
	if err := screen.click(ctx, image.Bounds(), notificationActionPoint(banner, 1, 0), "employee-restart-deferral", proof.EmployeeClick); err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for {
		state, record, err := readRebootPolicyState(ctx, vm.guest)
		if err != nil {
			return fail(err)
		}
		if state.GetReboot().GetDeferralsUsed() == 1 {
			old, next := before.GetReboot(), state.GetReboot()
			if !proto.Equal(old.GetDeadline(), next.GetDeadline()) || !next.GetScheduledFor().AsTime().Equal(old.GetScheduledFor().AsTime().Add(5*time.Minute)) {
				return fail(errors.New("employee deferral escaped signed interval or changed deadline"))
			}
			if err := lifecycleCommand(ctx, vm.guest, "restart executor without resetting employee deferral", "systemctl restart lindm-executor.service"); err != nil {
				return fail(err)
			}
			after, afterRecord, err := readRebootPolicyState(ctx, vm.guest)
			if err != nil || !proto.Equal(after.GetReboot(), next) {
				return fail(errors.Join(errors.New("reboot authority changed across executor restart"), err))
			}
			schedule, kind, at, err := logindScheduleOracle(ctx, vm.guest)
			if err != nil || kind != "reboot" || !at.Equal(next.GetScheduledFor().AsTime()) {
				return fail(errors.Join(errors.New("logind did not accept employee deferral"), err))
			}
			updated, _, err := screen.waitBanner(ctx, 20*time.Second)
			if err != nil {
				return fail(err)
			}
			path, err := screen.save("reboot-policy-after-deferral", updated)
			if err != nil {
				return fail(err)
			}
			proof.EmployeeClick.Screenshots = append(proof.EmployeeClick.Screenshots, path)
			passScenario(scenario, record, afterRecord, schedule)
			return nil
		}
		if err := lifecycleDelay(ctx, time.Second); err != nil {
			return fail(err)
		}
	}
}

func finishRebootPolicy(ctx context.Context, vm *EncryptedVM, r *resourceDispatch, proof *VMRebootPolicyResult) (err error) {
	scenario, fail := proof.scenario(ctx, r, "deferred-native-reboot-executes")
	previous, err := uuid.Parse(proof.BootBefore)
	if err != nil || previous == uuid.Nil {
		return fail(errors.New("missing original boot identity"))
	}
	state, _, err := readRebootPolicyState(ctx, vm.guest)
	if err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Until(state.GetReboot().GetScheduledFor().AsTime())+8*time.Minute)
	defer cancel()
	console, err := vm.serial(ctx)
	if err != nil {
		return fail(err)
	}
	defer func() { err = errors.Join(err, console.Close()) }()
	unlocked := make(chan error, 1)
	go func() {
		_, err := unlockEncryptedSerial(ctx, console, vm.InitialUnlockSecret(), vm.bootConsole)
		unlocked <- err
	}()
	defer func() {
		cancel()
		_ = console.SetReadDeadline(time.Now())
		err = errors.Join(err, <-unlocked)
	}()
	err = waitGuestBootChange(ctx, previous, func(probe context.Context) (string, error) {
		if vm.guest.client != nil {
			_ = vm.guest.client.Close()
			vm.guest.client = nil
		}
		if err := vm.guest.connect(probe); err != nil {
			return "", err
		}
		boot, err := vm.guest.run(probe, "cat /proc/sys/kernel/random/boot_id", nil, 128, 10*time.Second)
		proof.BootAfter = strings.TrimSpace(string(boot))
		return proof.BootAfter, err
	})
	if err != nil {
		return fail(err)
	}
	passScenario(scenario, resourceNativeRecord("new-boot-after-policy-reboot", []byte(proof.BootAfter)))
	return qualifyResourceEvidence(&proof.Policy, []string{"signed-independent-reboot-window", "native-update-and-reboot-window", "employee-deferral-and-executor-restart", "deferred-native-reboot-executes"})
}
