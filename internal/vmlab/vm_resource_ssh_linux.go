//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

const sshBannerLabText = "Authorized use only.\nCompany-managed SSH access.\n"
const sshBannerLabBaseline = "Native operator notice retained by approved adoption.\n"

func sshBannerDesired() *resourcev1.ResourceDesiredState {
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_SSH_SERVER, CanonicalKey: "system"}, State: &resourcev1.ResourceDesiredState_SshServer{SshServer: &resourcev1.SSHServerDesired{BannerText: proto.String(sshBannerLabText)}}}
}

// sshBannerLoginOracle is independent of the executor's loopback witness: a
// fresh external connection authenticates the lab account using its existing
// key, pins the guest key and checks the actual banner received by the client.
func sshBannerLoginOracle(ctx context.Context, vm *guestVM, expected string) (record VMResourceNativeRecord, err error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", vm.address)
	if err != nil {
		return record, err
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return record, err
	}
	config := *vm.config
	var received []byte
	config.BannerCallback = func(message string) error {
		received = append(received, []byte(message)...)
		if len(received) > 32768 {
			return errors.New("unbounded SSH banner")
		}
		return nil
	}
	client, _, _, err := ssh.NewClientConn(conn, vm.address, &config)
	if err != nil {
		return record, err
	}
	if err := client.Close(); err != nil {
		return record, err
	}
	if !bytes.Equal(received, []byte(expected)) {
		return record, fmt.Errorf("SSH login banner mismatch: received %q", received)
	}
	return resourceNativeRecord("external-host-key-pinned-authenticated-ssh-banner", append([]byte("authenticated existing lab account; received banner:\n"), received...)), nil
}

func sshBannerFilesOracle(vm *guestVM, content string, managed bool) func(context.Context) (VMResourceNativeRecord, error) {
	return func(ctx context.Context) (VMResourceNativeRecord, error) {
		command := "/usr/sbin/sshd -t; "
		if content != "" {
			command += "printf %s " + nativeQuote(content) + " | cmp - /etc/issue.net; stat -c '%n %a %u %g %s' /etc/issue.net; sha256sum /etc/issue.net; "
		} else {
			command += "test ! -e /etc/issue.net; printf 'issue.net absent\\n'; "
		}
		if managed {
			command += "/usr/sbin/sshd -T | grep -x 'banner /etc/issue.net'; stat -c '%n %a %u %g' " + resource.SSHBannerDirectivePath + "; sha256sum " + resource.SSHBannerDirectivePath + "; "
		} else {
			command += "test ! -e " + resource.SSHBannerDirectivePath + "; /usr/sbin/sshd -T | grep -x 'banner none'; "
		}
		command += "if test -e /sys/fs/selinux/enforce; then test \"$(getenforce)\" = Enforcing; getenforce; if test -f /etc/issue.net; then matchpathcon -V /etc/issue.net; ls -Z /etc/issue.net; fi; if test -f " + resource.SSHBannerDirectivePath + "; then matchpathcon -V " + resource.SSHBannerDirectivePath + "; ls -Z " + resource.SSHBannerDirectivePath + "; fi; fi"
		return resourceOracle(ctx, vm, "native-sshd-banner-files-syntax-labels", command)
	}
}
func sshBannerOracles(vm *guestVM, content string, managed bool) func(context.Context) ([]VMResourceNativeRecord, error) {
	return func(ctx context.Context) ([]VMResourceNativeRecord, error) {
		files, err := sshBannerFilesOracle(vm, content, managed)(ctx)
		if err != nil {
			return nil, err
		}
		expected := ""
		if managed {
			expected = content
		}
		login, err := sshBannerLoginOracle(ctx, vm, expected)
		if err != nil {
			return []VMResourceNativeRecord{files}, err
		}
		return []VMResourceNativeRecord{files, login}, nil
	}
}

func exerciseSSHBanner(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence) error {
	// The guest is disposable. This explicit unowned notice proves collision
	// refusal and exact adoption/release, not a guessed distro default.
	setup := "test ! -e " + resource.SSHBannerDirectivePath + "; install -m 0644 /dev/null /etc/issue.net; printf %s " + nativeQuote(sshBannerLabBaseline) + " > /etc/issue.net; if command -v restorecon >/dev/null 2>&1; then restorecon -F /etc/issue.net; fi; /usr/sbin/sshd -t"
	if err := lifecycleCommand(ctx, r.vm, "prepare disposable unowned SSH banner", setup); err != nil {
		return err
	}
	desired := sshBannerDesired()
	if err := resourceRefusalStep(ctx, r, evidence, "unowned-issue-net-refused", desired, resourceCreatePolicy(), sshBannerFilesOracle(r.vm, sshBannerLabBaseline, false)); err != nil {
		return err
	}
	r.fresh()
	if err := resourceStepRecords(ctx, r, evidence, "approved-banner-adoption", desired, resourceAdoptionPolicy(), false, sshBannerOracles(r.vm, sshBannerLabText, true)); err != nil {
		return err
	}
	if err := resourceStepRecords(ctx, r, evidence, "banner-repeat-no-effect", desired, resourceAdoptionPolicy(), true, sshBannerOracles(r.vm, sshBannerLabText, true)); err != nil {
		return err
	}
	if err := sshBannerDriftRepair(ctx, r, evidence); err != nil {
		return err
	}
	if r.reboot == nil {
		return errors.New("SSH banner lane needs a real guest reboot")
	}
	if err := r.reboot(ctx); err != nil {
		return err
	}
	if err := resourceStepRecords(ctx, r, evidence, "banner-reboot-persistence", desired, resourceAdoptionPolicy(), true, sshBannerOracles(r.vm, sshBannerLabText, true)); err != nil {
		return err
	}
	if err := resourceReleaseStepRecords(ctx, r, evidence, "banner-release-restores-baseline", desired.GetRef(), sshBannerOracles(r.vm, sshBannerLabBaseline, false)); err != nil {
		return err
	}
	if err := lifecycleCommand(ctx, r.vm, "prepare disposable absent banner", "rm /etc/issue.net"); err != nil {
		return err
	}
	r.fresh()
	if err := resourceStepRecords(ctx, r, evidence, "banner-create-absent", desired, resourceCreatePolicy(), false, sshBannerOracles(r.vm, sshBannerLabText, true)); err != nil {
		return err
	}
	if err := resourceReleaseStepRecords(ctx, r, evidence, "banner-release-removes-created-file", desired.GetRef(), sshBannerOracles(r.vm, "", false)); err != nil {
		return err
	}
	// A Banner inside a different user's Match must refuse global ownership,
	// even though the probe user's sshd -T output would otherwise look safe.
	foreign := "/etc/ssh/sshd_config.d/99-lindm-lab-banner.conf"
	if err := lifecycleCommand(ctx, r.vm, "prepare foreign Match banner", "printf 'Match User someone-else\\n Banner /etc/issue.net\\n' > "+foreign+"; chmod 0644 "+foreign+"; /usr/sbin/sshd -t"); err != nil {
		return err
	}
	r.fresh()
	if err := resourceRefusalStep(ctx, r, evidence, "foreign-match-banner-refused", desired, resourceCreatePolicy(), func(ctx context.Context) (VMResourceNativeRecord, error) {
		return resourceOracle(ctx, r.vm, "foreign-match-banner-unchanged", "sha256sum "+foreign+"; test ! -e "+resource.SSHBannerDirectivePath+"; test ! -e /etc/issue.net; /usr/sbin/sshd -t")
	}); err != nil {
		return err
	}
	if err := lifecycleCommand(ctx, r.vm, "remove disposable Match fixture", "rm "+foreign); err != nil {
		return err
	}
	// The resolved bytes are protected, but the original alias crosses a
	// writable directory. A snapshot must reject that spelling, not merely
	// capture its safe destination before a possible alias swap at reload.
	untrusted := "/etc/ssh/lindm-lab-untrusted"
	protected := "/etc/ssh/lindm-lab-protected.conf"
	setupAlias := "mkdir " + untrusted + "; chmod 0777 " + untrusted + "; printf '# protected lab configuration\\n' > " + protected + "; chmod 0644 " + protected + "; ln -s " + protected + " " + untrusted + "/alias; ln -s " + untrusted + "/alias " + foreign + "; /usr/sbin/sshd -t"
	if err := lifecycleCommand(ctx, r.vm, "prepare unsafe Include alias", setupAlias); err != nil {
		return err
	}
	r.fresh()
	if err := resourceRefusalStep(ctx, r, evidence, "untrusted-include-alias-refused", desired, resourceCreatePolicy(), func(ctx context.Context) (VMResourceNativeRecord, error) {
		return resourceOracle(ctx, r.vm, "unsafe-include-alias-unchanged", "test -L "+foreign+"; readlink "+foreign+"; readlink "+untrusted+"/alias; stat -c '%n %a %u %g' "+untrusted+"; sha256sum "+protected+"; test ! -e "+resource.SSHBannerDirectivePath+"; test ! -e /etc/issue.net; /usr/sbin/sshd -t")
	}); err != nil {
		return err
	}
	// No matching file is needed to make this unsafe: an untrusted writer
	// could supply one only while sshd rereads the graph.
	pattern := untrusted + "/*.conf"
	if err := lifecycleCommand(ctx, r.vm, "prepare empty writable Include search directory", "rm "+foreign+"; printf %s "+nativeQuote("Include "+pattern+"\n")+" > "+foreign+"; chmod 0644 "+foreign+"; /usr/sbin/sshd -t"); err != nil {
		return err
	}
	r.fresh()
	if err := resourceRefusalStep(ctx, r, evidence, "empty-writable-include-glob-refused", desired, resourceCreatePolicy(), func(ctx context.Context) (VMResourceNativeRecord, error) {
		return resourceOracle(ctx, r.vm, "empty-unsafe-include-directory-unchanged", "set -- "+pattern+"; test \"$#\" -eq 1; test \"$1\" = "+nativeQuote(pattern)+"; stat -c '%n %a %u %g' "+untrusted+"; sha256sum "+foreign+"; test ! -e "+resource.SSHBannerDirectivePath+"; test ! -e /etc/issue.net; /usr/sbin/sshd -t")
	}); err != nil {
		return err
	}
	if err := lifecycleCommand(ctx, r.vm, "remove disposable Include fixtures", "rm "+foreign+" "+untrusted+"/alias "+protected+"; rmdir "+untrusted); err != nil {
		return err
	}
	evidence.Unproven = nil
	return qualifyResourceEvidence(evidence, []string{"unowned-issue-net-refused", "approved-banner-adoption", "banner-repeat-no-effect", "banner-content-drift-repaired", "banner-reboot-persistence", "banner-release-restores-baseline", "banner-create-absent", "banner-release-removes-created-file", "foreign-match-banner-refused", "untrusted-include-alias-refused", "empty-writable-include-glob-refused"})
}

func sshBannerDriftRepair(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence) error {
	previous := evidence.Scenarios[len(evidence.Scenarios)-1].Action.GetActionId()
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: "banner-content-drift-repaired", StartedAt: time.Now().UTC()})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	if err := lifecycleCommand(ctx, r.vm, "introduce in-place SSH banner content drift", "printf 'External drift\\n' > /etc/issue.net"); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	for {
		state, err := r.control.dispatchState(ctx, r.device)
		if err != nil {
			return err
		}
		if len(state.GetResources()) == 1 {
			action := state.GetResources()[0].GetLatestAction()
			if action != nil && action.GetActionId() != previous && action.GetClosedAt() != nil {
				s.Action, err = r.action(ctx, false)
				if err != nil {
					s.Failure = err.Error()
					s.Native = append(s.Native, r.failureDiagnostics(ctx)...)
					return err
				}
				if s.Action.GetStartAuthorizedAt() == nil {
					return errors.New("drift repair has no signed start authority")
				}
				s.Native, err = sshBannerOracles(r.vm, sshBannerLabText, true)(ctx)
				if err != nil {
					return err
				}
				s.Passed = true
				s.FinishedAt = time.Now().UTC()
				return nil
			}
		}
		if err := lifecycleDelay(ctx, 250*time.Millisecond); err != nil {
			return fmt.Errorf("automatic SSH banner drift repair: %w", err)
		}
	}
}
