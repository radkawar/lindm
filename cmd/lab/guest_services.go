//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/serviceprovider"
	"lindm/internal/vmlab"
)

const serviceProofUnit = "lab-native-service-proof.service"
const serviceProofAlias = "lab-native-service-proof-alias.service"
const serviceProofOneshot = "lab-native-service-proof-oneshot.service"
const serviceProofMissing = "lab-native-service-proof-missing.service"
const serviceProofLegacyInclude = "lab-native-service-proof-legacy-include.service"
const serviceProofDirectory = "/etc/systemd/system/"

// These literal fixtures belong only to a disposable laboratory guest. The
// production provider never receives executable paths or service definitions.
const serviceProofDefinition = `[Unit]
Description=Disposable native service provider proof
[Service]
Type=simple
ExecStart=/usr/bin/sleep infinity
[Install]
WantedBy=multi-user.target
`
const serviceProofOneshotDefinition = `[Unit]
Description=Disposable nonpersistent oneshot rejection proof
[Service]
Type=oneshot
ExecStart=/usr/bin/true
RemainAfterExit=no
[Install]
WantedBy=multi-user.target
`

func guestServices(ctx context.Context, output io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("native service probe requires root in a disposable guest")
	}
	// Refuse accidental execution on a non-VM host. The maintained entry point
	// boots and destroys its own VM; this development helper is not an agent API.
	if _, err := serviceProofCommand(ctx, "/usr/bin/systemd-detect-virt", "--vm", "--quiet"); err != nil {
		return errors.New("native service probe requires a virtual machine")
	}
	evidence, err := probeGuestServices(ctx)
	if err != nil {
		return err
	}
	// Cleanup and provider Close both precede publication of any success.
	return json.NewEncoder(output).Encode(evidence)
}

func probeGuestServices(ctx context.Context) (_ *vmlab.VMServicesEvidence, err error) {
	owned := make([]string, 0, 4)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if len(owned) == 0 {
			return
		}
		for _, unit := range owned {
			if unit == serviceProofAlias {
				continue
			}
			_, stopErr := serviceProofCommand(cleanup, "/usr/bin/systemctl", "--no-ask-password", "disable", "--now", unit)
			err = errors.Join(err, stopErr)
		}
		for i := len(owned) - 1; i >= 0; i-- {
			removeErr := os.Remove(serviceProofDirectory + owned[i])
			// Native disable removes aliases pointing to the owned unit.
			if owned[i] != serviceProofAlias || !errors.Is(removeErr, os.ErrNotExist) {
				err = errors.Join(err, removeErr)
			}
		}
		_, reloadErr := serviceProofCommand(cleanup, "/usr/bin/systemctl", "--no-ask-password", "daemon-reload")
		err = errors.Join(err, reloadErr)
	}()
	for _, unit := range []string{serviceProofUnit, serviceProofAlias, serviceProofOneshot, serviceProofMissing, serviceProofLegacyInclude} {
		native, err := serviceProofNative(ctx, unit)
		if err != nil {
			return nil, err
		}
		if native.LoadState != "not-found" {
			return nil, errors.New("service proof refuses to replace an existing unit")
		}
	}
	for _, executable := range []string{"/usr/bin/sleep", "/usr/bin/true"} {
		info, err := os.Stat(executable)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return nil, errors.New("service proof requires native sleep and true executables")
		}
	}
	for _, fixture := range []struct{ unit, content string }{
		{serviceProofUnit, serviceProofDefinition},
		{serviceProofOneshot, serviceProofOneshotDefinition},
		{serviceProofLegacyInclude, serviceProofDefinition + "\n.include /dev/null\n"},
	} {
		file, err := os.OpenFile(serviceProofDirectory+fixture.unit, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		owned = append(owned, fixture.unit)
		_, writeErr := io.WriteString(file, fixture.content)
		if err := errors.Join(writeErr, file.Close()); err != nil {
			return nil, err
		}
	}
	if enforcing, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		if strings.TrimSpace(string(enforcing)) != "1" {
			return nil, errors.New("service proof refuses permissive SELinux")
		}
		// Restore only our new fixtures to vendor policy labels. Never relabel
		// vendor executables, alter policy, or relax the guest enforcement mode.
		if _, err := serviceProofCommand(ctx, "/usr/sbin/restorecon", serviceProofDirectory+serviceProofUnit, serviceProofDirectory+serviceProofOneshot, serviceProofDirectory+serviceProofLegacyInclude); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if _, err := serviceProofCommand(ctx, "/usr/bin/systemctl", "--no-ask-password", "daemon-reload"); err != nil {
		return nil, err
	}
	provider, err := serviceprovider.Open(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, provider.Close()) }()
	evidence := &vmlab.VMServicesEvidence{Capability: serviceprovider.Capability}
	active := &agentv1.ServiceDesiredState{Unit: serviceProofUnit, Runtime: agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: agentv1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED}
	inactive := &agentv1.ServiceDesiredState{Unit: serviceProofUnit, Runtime: agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE, Enablement: agentv1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED}
	for _, phase := range []struct {
		name                string
		runtime, enablement bool
	}{
		{"converge-active", true, true},
		{"repeat-active", false, false},
	} {
		step, err := serviceProofConverge(ctx, provider, phase.name, active, phase.runtime, phase.enablement)
		if err != nil {
			return nil, err
		}
		evidence.Steps = append(evidence.Steps, *step)
	}
	stale, err := provider.Plan(ctx, inactive)
	if err != nil {
		return nil, err
	}
	if !stale.ChangeRuntime || !stale.ChangeEnablement {
		return nil, errors.New("stale-plan fixture did not initially require both effects")
	}
	// Change runtime independently after planning. Applying the stale plan must
	// not perform its still-requested disable effect.
	if _, err := serviceProofCommand(ctx, "/usr/bin/systemctl", "--no-ask-password", "stop", serviceProofUnit); err != nil {
		return nil, err
	}
	before, err := serviceProofNative(ctx, serviceProofUnit)
	if err != nil {
		return nil, err
	}
	if before.ActiveState != "inactive" || before.UnitFileState != "enabled" {
		return nil, errors.New("independent stale-plan mutation did not stop without disabling")
	}
	if _, err := provider.Apply(ctx, stale, serviceProofAuthorize); !errors.Is(err, serviceprovider.ErrConflict) {
		return nil, fmt.Errorf("stale service plan must fail with conflict: %w", err)
	}
	after, err := provider.Observe(ctx, serviceProofUnit)
	if err != nil {
		return nil, err
	}
	native, err := serviceProofNative(ctx, serviceProofUnit)
	if err != nil {
		return nil, err
	}
	if *before != *native || after.ActiveState != "inactive" || after.UnitFileState != "enabled" || bytes.Equal(stale.Before.FingerprintSha256, after.FingerprintSha256) {
		return nil, errors.New("stale plan mutated state or failed to expose native drift")
	}
	evidence.Steps = append(evidence.Steps, vmlab.VMServiceStep{Name: "stale-plan", Target: serviceProofUnit, Plan: stale, After: after, NativeBefore: before, NativeAfter: native, Rejection: "conflict"})
	step, err := serviceProofConverge(ctx, provider, "reconverge-active", active, true, false)
	if err != nil {
		return nil, err
	}
	evidence.Steps = append(evidence.Steps, *step)
	step, err = serviceProofConverge(ctx, provider, "converge-inactive", inactive, true, true)
	if err != nil {
		return nil, err
	}
	evidence.Steps = append(evidence.Steps, *step)
	plan, err := provider.Plan(ctx, active)
	if err != nil {
		return nil, err
	}
	if !plan.ChangeRuntime || !plan.ChangeEnablement {
		return nil, errors.New("cancellation fixture must require start and enable")
	}
	nativeBefore, err := serviceProofNative(ctx, serviceProofUnit)
	if err != nil {
		return nil, err
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := provider.Apply(canceled, plan, serviceProofAuthorize); !errors.Is(err, context.Canceled) {
		return nil, fmt.Errorf("pre-start canceled service apply must fail with cancellation: %w", err)
	}
	after, err = provider.Observe(ctx, serviceProofUnit)
	if err != nil {
		return nil, err
	}
	nativeAfter, err := serviceProofNative(ctx, serviceProofUnit)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(plan.Before.FingerprintSha256, after.FingerprintSha256) || *nativeBefore != *nativeAfter || nativeAfter.ActiveState != "inactive" || nativeAfter.UnitFileState != "disabled" {
		return nil, errors.New("pre-start cancellation changed native service state")
	}
	evidence.Steps = append(evidence.Steps, vmlab.VMServiceStep{Name: "canceled-before-start", Target: serviceProofUnit, Plan: plan, After: after, NativeBefore: nativeBefore, NativeAfter: nativeAfter, Rejection: "canceled"})
	// DisableUnitFiles removes aliases as well as target-wants links. Create
	// this fixture afterward so alias rejection cannot pass as "not found".
	if err := os.Symlink(serviceProofUnit, serviceProofDirectory+serviceProofAlias); err != nil {
		return nil, err
	}
	owned = append(owned, serviceProofAlias)
	if _, err := os.Stat("/sys/fs/selinux/enforce"); err == nil {
		if _, err := serviceProofCommand(ctx, "/usr/sbin/restorecon", serviceProofDirectory+serviceProofAlias); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if _, err := serviceProofCommand(ctx, "/usr/bin/systemctl", "--no-ask-password", "daemon-reload"); err != nil {
		return nil, err
	}
	for _, target := range []struct{ name, unit string }{
		{"missing-rejected", serviceProofMissing},
		{"alias-rejected", serviceProofAlias},
		{"oneshot-rejected", serviceProofOneshot},
		{"legacy-include-rejected", serviceProofLegacyInclude},
	} {
		before, err := provider.Observe(ctx, serviceProofUnit)
		if err != nil {
			return nil, err
		}
		nativeBefore, err := serviceProofNative(ctx, target.unit)
		if err != nil {
			return nil, err
		}
		if target.unit == serviceProofAlias && (nativeBefore.LoadState != "loaded" || nativeBefore.ID != serviceProofUnit) {
			return nil, errors.New("alias rejection requires a loaded alias of the canonical fixture")
		}
		if target.unit == serviceProofLegacyInclude && (nativeBefore.LoadState != "loaded" || nativeBefore.ID != serviceProofLegacyInclude || nativeBefore.ActiveState != "inactive" || nativeBefore.UnitFileState != "disabled") {
			return nil, errors.New("legacy include rejection requires an otherwise loaded, inactive and disabled service")
		}
		desired := proto.CloneOf(active)
		desired.Unit = target.unit
		if _, err := provider.Plan(ctx, desired); !errors.Is(err, serviceprovider.ErrUnsupported) {
			return nil, fmt.Errorf("%s must fail as unsupported: %w", target.name, err)
		}
		after, err := provider.Observe(ctx, serviceProofUnit)
		if err != nil {
			return nil, err
		}
		nativeAfter, err := serviceProofNative(ctx, target.unit)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(before.FingerprintSha256, after.FingerprintSha256) || *nativeBefore != *nativeAfter {
			return nil, errors.New("unsupported service input changed native state")
		}
		evidence.Steps = append(evidence.Steps, vmlab.VMServiceStep{Name: target.name, Target: target.unit, Before: before, After: after, NativeBefore: nativeBefore, NativeAfter: nativeAfter, Rejection: "unsupported"})
	}
	return evidence, nil
}

// Only the disposable-root fixture calls this library directly. Product effects
// use the executor's signed, journal-consuming admission callback instead.
func serviceProofAuthorize(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("disposable service fixture lost root authority")
	}
	return ctx.Err()
}

func serviceProofConverge(ctx context.Context, provider *serviceprovider.Provider, name string, desired *agentv1.ServiceDesiredState, changeRuntime, changeEnablement bool) (*vmlab.VMServiceStep, error) {
	plan, err := provider.Plan(ctx, desired)
	if err != nil {
		return nil, err
	}
	nativeBefore, err := serviceProofNative(ctx, desired.Unit)
	if err != nil {
		return nil, err
	}
	if plan.ChangeRuntime != changeRuntime || plan.ChangeEnablement != changeEnablement || plan.Before.ActiveState != nativeBefore.ActiveState || plan.Before.UnitFileState != nativeBefore.UnitFileState {
		return nil, fmt.Errorf("%s: provider plan disagrees with expected drift or native state", name)
	}
	applied, err := provider.Apply(ctx, plan, serviceProofAuthorize)
	if err != nil {
		return nil, fmt.Errorf("%s apply: %w", name, err)
	}
	if applied == nil || !applied.Converged || !applied.RuntimeMatches || !applied.EnablementMatches || !applied.DefinitionMatches {
		return nil, fmt.Errorf("%s: apply did not verify convergence", name)
	}
	verified, err := provider.Verify(ctx, plan)
	if err != nil {
		return nil, fmt.Errorf("%s verify: %w", name, err)
	}
	if verified == nil || !verified.Converged || !verified.RuntimeMatches || !verified.EnablementMatches || !verified.DefinitionMatches || verified.Observation == nil {
		return nil, fmt.Errorf("%s: independent provider verify did not converge", name)
	}
	nativeAfter, err := serviceProofNative(ctx, desired.Unit)
	if err != nil {
		return nil, err
	}
	wantRuntime, wantEnablement := "inactive", "disabled"
	if desired.Runtime == agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE {
		wantRuntime = "active"
	}
	if desired.Enablement == agentv1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED {
		wantEnablement = "enabled"
	}
	observation := verified.Observation
	if nativeAfter.ID != desired.Unit || nativeAfter.LoadState != "loaded" || nativeAfter.ActiveState != wantRuntime || nativeAfter.UnitFileState != wantEnablement || observation.ActiveState != nativeAfter.ActiveState || observation.SubState != nativeAfter.SubState || observation.UnitFileState != nativeAfter.UnitFileState || !bytes.Equal(plan.Before.DefinitionSha256, observation.DefinitionSha256) {
		return nil, fmt.Errorf("%s: independent systemctl oracle did not confirm desired state", name)
	}
	if name == "converge-active" && (nativeBefore.ActiveState != "inactive" || nativeBefore.UnitFileState != "disabled") {
		return nil, errors.New("initial service fixture was not disabled and inactive")
	}
	return &vmlab.VMServiceStep{Name: name, Target: desired.Unit, Plan: plan, After: observation, Verification: verified, NativeBefore: nativeBefore, NativeAfter: nativeAfter}, nil
}

func serviceProofNative(ctx context.Context, unit string) (*vmlab.VMServiceNativeState, error) {
	data, commandErr := serviceProofCommand(ctx, "/usr/bin/systemctl", "--no-pager", "--all", "show", "--property=Id,LoadState,ActiveState,SubState,UnitFileState", "--", unit)
	fields := make(map[string]string, 5)
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, errors.New("invalid native systemctl service oracle")
		}
		if _, exists := fields[key]; exists {
			return nil, errors.New("duplicate native systemctl service field")
		}
		fields[key] = value
	}
	for _, key := range []string{"Id", "LoadState", "ActiveState", "SubState", "UnitFileState"} {
		if _, exists := fields[key]; !exists || len(fields) != 5 {
			return nil, errors.New("incomplete native systemctl service oracle")
		}
	}
	if commandErr != nil {
		var exit *exec.ExitError
		if fields["LoadState"] != "not-found" || !errors.As(commandErr, &exit) || exit.ExitCode() != 1 {
			return nil, commandErr
		}
	}
	return &vmlab.VMServiceNativeState{Unit: unit, ID: fields["Id"], LoadState: fields["LoadState"], ActiveState: fields["ActiveState"], SubState: fields["SubState"], UnitFileState: fields["UnitFileState"]}, nil
}

type serviceProofOutput struct{ buffer bytes.Buffer }

func (b *serviceProofOutput) Write(data []byte) (int, error) {
	if len(data) > (16<<10)-b.buffer.Len() {
		return 0, errors.New("native service oracle output exceeds limit")
	}
	return b.buffer.Write(data)
}

func serviceProofCommand(ctx context.Context, executable string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C", "SYSTEMD_PAGER=cat"}
	command.WaitDelay = time.Second
	var stdout, stderr serviceProofOutput
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return stdout.buffer.Bytes(), fmt.Errorf("native service fixture/oracle command: %w", err)
	}
	return stdout.buffer.Bytes(), nil
}
