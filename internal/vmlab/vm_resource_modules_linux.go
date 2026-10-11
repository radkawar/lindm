//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/fileprovider"
	"lindm/internal/platform"
	"lindm/internal/resource"
)

func moduleBlocklistDesired(modules ...string) *resourcev1.ResourceDesiredState {
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_MANAGED_FILE, CanonicalKey: fileprovider.ModuleBlocklistPath}, State: &resourcev1.ResourceDesiredState_ManagedFile{ManagedFile: &resourcev1.ManagedFileDesired{Path: fileprovider.ModuleBlocklistPath, Presence: resourcev1.Presence_PRESENCE_PRESENT, KernelModuleBlocklist: &resourcev1.KernelModuleBlocklist{Modules: modules}}}}
}

// kmod prints an empty options field as trailing whitespace. Check every command's
// complete token sequence, not its presentation spacing; empty/other commands fail.
const moduleDependencyOracle = `test -n "$dependencies"; printf '%s\n' "$dependencies" | while read -r operation executable extra; do test "$operation" = install; test "$executable" = /bin/false; test -z "$extra"; done; `

func moduleOracle(ctx context.Context, vm *guestVM, tools platform.ModuleBlocklistTooling, loaded, released bool) (VMResourceNativeRecord, error) {
	path := nativeQuote(fileprovider.ModuleBlocklistPath)
	command := "uname -r; cat /proc/sys/kernel/random/boot_id; test \"$(systemctl show lindm-executor.service -p ProtectKernelModules --value)\" = yes; systemctl show lindm-executor.service -p ProtectKernelModules; "
	if released {
		command += "test ! -e " + path + "; printf 'owned-blocklist-absent\\n'; "
	} else {
		command += "test \"$(stat -c '%a:%u:%g' " + path + ")\" = '644:0:0'; cat " + path + "; sha256sum " + path + "; "
		for _, module := range []string{"usb_storage", "uas"} {
			command += "dependencies=$(modprobe --show-depends -- " + module + "); printf '%s\\n' \"$dependencies\"; " + moduleDependencyOracle
			if loaded {
				command += "grep '^" + module + " ' /proc/modules; "
			} else {
				command += "if grep '^" + module + " ' /proc/modules; then exit 1; fi; if modprobe " + module + "; then exit 1; fi; "
			}
		}
	}
	command += "sha256sum " + strings.ReplaceAll(tools.InitramfsPattern, "%s", "*")
	return resourceOracle(ctx, vm, "native-module-load-state-modprobe-and-initramfs-digests", command)
}

func moduleRejectedStep(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence, name string, desired *resourcev1.ResourceDesiredState, disposition resourcev1.VerificationDisposition, repeat bool, oracle func(context.Context) (VMResourceNativeRecord, error)) error {
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: name, StartedAt: time.Now().UTC()})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	if err := r.assign(ctx, desired, resourceCreatePolicy()); err != nil {
		s.Failure = err.Error()
		return err
	}
	action, err := r.action(ctx, true)
	s.Action = action
	if err == nil && action.GetStatus().GetVerification().GetDisposition() != disposition {
		err = fmt.Errorf("module observation disposition: want %s, got %s", disposition, action.GetStatus().GetVerification().GetDisposition())
	}
	if err == nil && (action.GetStatus().GetReadOnly() != repeat || (action.GetStartAuthorizedAt() == nil) != repeat) {
		err = errors.New("module finding changed expected read-only/start-authority boundary")
	}
	if err != nil {
		s.Failure = err.Error()
		s.Native = append(s.Native, executorDiagnostics(ctx, r.vm))
		return err
	}
	native, err := oracle(ctx)
	if err != nil {
		s.Failure = err.Error()
		return err
	}
	s.Native, s.Passed, s.FinishedAt = []VMResourceNativeRecord{native}, true, time.Now().UTC()
	return nil
}

// A successful no-op must not qualify as repair of externally introduced drift.
func moduleDriftEvidence(s *VMResourceScenario, bootOnly bool) error {
	status := s.Action.GetStatus()
	before := status.GetBefore().GetManagedFile()
	after := status.GetVerification().GetAfter().GetManagedFile()
	sameFile := bytes.Equal(before.GetFile().GetSha256(), after.GetFile().GetSha256())
	staleImage := false
	for _, image := range before.GetKernelModuleBlocklist().GetInitramfs() {
		staleImage = staleImage || !bytes.Equal(image.GetBlocklistSha256(), before.GetFile().GetSha256())
	}
	if s.Action.GetStartAuthorizedAt() == nil || status.GetReadOnly() || !before.GetExists() || !after.GetExists() || sameFile != bootOnly || (bootOnly && !staleImage) {
		s.Passed = false
		s.Failure = "module drift repair lacks an effect grant and independently observed pre-effect drift"
		return errors.New(s.Failure)
	}
	return nil
}

func moduleSetup(ctx context.Context, vm *guestVM, tools platform.ModuleBlocklistTooling) (VMResourceNativeRecord, error) {
	command := "test ! -e " + nativeQuote(fileprovider.ModuleBlocklistPath) + "; modprobe usb_storage; modprobe uas; grep -E '^(usb_storage|uas) ' /proc/modules; "
	if tools.StateDirectory != "" {
		path := nativeQuote(tools.StateDirectory)
		command += "if test -e " + path + "; then stat -c '%n:%F:%a:%u:%g' " + path + "; else printf 'native-tool-state-absent\\n'; fi"
	}
	return resourceOracle(ctx, vm, "native-module-preload-and-initial-tool-state", command)
}

func moduleBuiltinDesired(entries []byte) (*resourcev1.ResourceDesiredState, string, error) {
	for entry := range strings.SplitSeq(string(entries), "\n") {
		if !strings.HasSuffix(entry, ".ko") {
			continue
		}
		name := strings.ReplaceAll(strings.TrimSuffix(filepath.Base(entry), ".ko"), "-", "_")
		desired := moduleBlocklistDesired(name)
		if err := resource.ValidateDesired(desired); err == nil {
			return desired, entry, nil
		}
	}
	return nil, "", errors.New("native built-in module list has no supported canonical module name")
}

func exerciseResourceModules(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence) error {
	if r.reboot == nil {
		return errors.New("module qualification requires disposable guest reboot")
	}
	identity, err := r.vm.run(ctx, ". /etc/os-release; printf '%s\\n%s' \"$ID\" \"$VERSION_ID\"", nil, 4096, 15*time.Second)
	if err != nil {
		return err
	}
	id, version, _ := strings.Cut(string(identity), "\n")
	tools := platform.Identify(platform.OSRelease{ID: id, VersionID: version}).ModuleBlocklist
	if tools.Rebuild == "" {
		return errors.New("module blocklist platform has no qualified initramfs tooling")
	}
	setup, err := moduleSetup(ctx, r.vm, tools)
	if err != nil {
		return err
	}
	desired := moduleBlocklistDesired("usb_storage", "uas")
	loadedOracle := func(ctx context.Context) (VMResourceNativeRecord, error) {
		return moduleOracle(ctx, r.vm, tools, true, false)
	}
	blockedOracle := func(ctx context.Context) (VMResourceNativeRecord, error) {
		return moduleOracle(ctx, r.vm, tools, false, false)
	}
	releasedOracle := func(ctx context.Context) (VMResourceNativeRecord, error) {
		return moduleOracle(ctx, r.vm, tools, false, true)
	}
	err = moduleRejectedStep(ctx, r, evidence, "modules-loaded-pending-reboot", desired, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_PENDING_REBOOT, false, loadedOracle)
	evidence.Scenarios[len(evidence.Scenarios)-1].Native = append(evidence.Scenarios[len(evidence.Scenarios)-1].Native, setup)
	if err != nil {
		return err
	}
	if err := moduleRejectedStep(ctx, r, evidence, "modules-loaded-observed", desired, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_PENDING_REBOOT, true, loadedOracle); err != nil {
		return err
	}
	if err := r.reboot(ctx); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "modules-blocked-after-reboot", desired, resourceCreatePolicy(), true, blockedOracle); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "modules-idempotent", desired, resourceCreatePolicy(), true, blockedOracle); err != nil {
		return err
	}
	path := nativeQuote(fileprovider.ModuleBlocklistPath)
	if err := lifecycleCommand(ctx, r.vm, "introduce module file drift", "printf '# external drift\\n' >> "+path); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "modules-file-drift-repaired", desired, resourceCreatePolicy(), false, blockedOracle); err != nil {
		return err
	}
	if err := moduleDriftEvidence(&evidence.Scenarios[len(evidence.Scenarios)-1], false); err != nil {
		return err
	}
	// Deliberately rebuild without the owned file, then restore the same inode.
	// A file-equality-only provider would incorrectly skip this boot-image drift.
	rebuild := nativeQuote(tools.Rebuild)
	for _, arg := range tools.RebuildArgs {
		rebuild += " " + nativeQuote(arg)
	}
	saved := nativeQuote(fileprovider.ModuleBlocklistPath + ".lab-saved")
	if err := lifecycleCommand(ctx, r.vm, "introduce initramfs-only drift", "systemctl stop lindm-agent.service; identity=$(stat -c '%d:%i:%W' "+path+"); mv "+path+" "+saved+"; "+rebuild+"; mv "+saved+" "+path+"; test \"$identity\" = \"$(stat -c '%d:%i:%W' "+path+")\"; systemctl start lindm-agent.service"); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "modules-initramfs-drift-repaired", desired, resourceCreatePolicy(), false, blockedOracle); err != nil {
		return err
	}
	if err := moduleDriftEvidence(&evidence.Scenarios[len(evidence.Scenarios)-1], true); err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, evidence, "modules-owned-release", desired.GetRef(), releasedOracle); err != nil {
		return err
	}
	builtins, err := r.vm.run(ctx, "cat /lib/modules/$(uname -r)/modules.builtin", nil, 4<<20, 15*time.Second)
	if err != nil {
		return err
	}
	r.fresh()
	builtinDesired, builtinEntry, err := moduleBuiltinDesired(builtins)
	if err != nil {
		return err
	}
	builtinOracle := func(ctx context.Context) (VMResourceNativeRecord, error) {
		return resourceOracle(ctx, r.vm, "native-built-in-module-cannot-unload", "grep -Fx -- "+nativeQuote(builtinEntry)+" /lib/modules/$(uname -r)/modules.builtin; cat "+path+"; sha256sum "+path)
	}
	if err := moduleRejectedStep(ctx, r, evidence, "modules-built-in-not-applicable", builtinDesired, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE, false, builtinOracle); err != nil {
		return err
	}
	if err := moduleRejectedStep(ctx, r, evidence, "modules-built-in-observed", builtinDesired, resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE, true, builtinOracle); err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, evidence, "modules-built-in-release", builtinDesired.GetRef(), releasedOracle); err != nil {
		return err
	}
	evidence.Unproven = nil
	return qualifyResourceEvidence(evidence, []string{"modules-loaded-pending-reboot", "modules-loaded-observed", "modules-blocked-after-reboot", "modules-idempotent", "modules-file-drift-repaired", "modules-initramfs-drift-repaired", "modules-owned-release", "modules-built-in-not-applicable", "modules-built-in-observed", "modules-built-in-release"})
}
