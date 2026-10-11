//go:build linux

package vmlab

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/platform"
)

// rootRecoverySession is a real root SSH login kept open for the duration of
// the password lane. sshd's PAM stack registers it with logind; the provider's
// access guard requires that live root session before changing authentication.
type rootRecoverySession struct {
	client  *ssh.Client
	session *ssh.Session
	id      string
}

var logindSessionID = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

// rootRecoveryLoginScript authorizes the lab's own key for a disposable root
// login. Installer-built goldens (Debian) ship the lab's sshd drop-in with
// "PermitRootLogin no"; it becomes key-only "prohibit-password", the cloud
// images' default, and sshd reloads. Password authentication stays disabled.
const rootRecoveryLoginScript = `install -d -o root -g root -m 0700 /root/.ssh
install -o root -g root -m 0600 /home/` + labUser + `/.ssh/authorized_keys /root/.ssh/authorized_keys
if command -v restorecon >/dev/null 2>&1; then restorecon -RF /root/.ssh; fi
conf=/etc/ssh/sshd_config.d/00-lindm-lab.conf
if test -f "$conf" && grep -qx 'PermitRootLogin no' "$conf"; then
 sed -i 's/^PermitRootLogin no$/PermitRootLogin prohibit-password/' "$conf"
 grep -qx 'PermitRootLogin prohibit-password' "$conf"
 grep -qx 'PasswordAuthentication no' "$conf"
 systemctl reload ssh.service 2>/dev/null || systemctl reload sshd.service
fi
`

func openRootRecoverySession(ctx context.Context, vm *guestVM) (_ *rootRecoverySession, resultErr error) {
	if err := lifecycleCommand(ctx, vm, "authorize disposable root recovery login", rootRecoveryLoginScript); err != nil {
		return nil, err
	}
	config := *vm.config
	config.User = "root"
	dial, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dial, "tcp4", vm.address)
	if err != nil {
		return nil, err
	}
	sshConn, channels, requests, err := ssh.NewClientConn(conn, vm.address, &config)
	if err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	client := ssh.NewClient(sshConn, channels, requests)
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, client.Close())
		}
	}()
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := session.Start("printf '%s\\n' \"$XDG_SESSION_ID\"; exec sleep 3600"); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	id := strings.TrimSpace(line)
	if err != nil || !logindSessionID.MatchString(id) {
		return nil, errors.Join(errors.New("root login did not register a logind session"), err, session.Close())
	}
	return &rootRecoverySession{client: client, session: session, id: id}, nil
}

func (s *rootRecoverySession) Close() error {
	return errors.Join(s.session.Close(), s.client.Close())
}

// enablePasswordProvider adds the root-local opt-in with the live session.
func enablePasswordProvider(ctx context.Context, packages *nativeGuestPackages, session string) error {
	data, err := packages.vm.run(ctx, "sudo -n cat /etc/lindm/executor.json", nil, 128<<10, 15*time.Second)
	if err != nil {
		return err
	}
	config := new(agentv1.AgentConfig)
	if err := protojson.Unmarshal(data, config); err != nil {
		return err
	}
	config.PasswordProvider = &agentv1.NativePasswordProviderConfig{Enabled: true, RecoverySessionId: session}
	encoded, err := protojson.Marshal(config)
	if err != nil {
		return err
	}
	if err := packages.uploadBytes(ctx, nativeGuestDir+"/password-executor.json", encoded); err != nil {
		return err
	}
	return lifecycleCommand(ctx, packages.vm, "enable root-local password provider", "install -o root -g root -m 0600 "+nativeGuestDir+"/password-executor.json /etc/lindm/executor.json; systemctl restart lindm-executor.service")
}

func passwordGuestManager(ctx context.Context, vm *guestVM) (platform.PAMManager, error) {
	data, err := vm.run(ctx, ". /etc/os-release; printf '%s\\n%s\\n%s' \"$ID\" \"${VERSION_ID-}\" \"${VARIANT_ID-}\"", nil, 1024, 10*time.Second)
	if err != nil {
		return "", err
	}
	fields := strings.Split(string(data), "\n")
	if len(fields) != 3 {
		return "", errors.New("invalid guest platform identity")
	}
	release := platform.Identify(platform.OSRelease{ID: fields[0], VersionID: fields[1], VariantID: fields[2]})
	return release.Native().Quirks.PAMManager, nil
}

func preparePasswordFixture(ctx context.Context, r *resourceDispatch, manager platform.PAMManager) error {
	if (manager == platform.PAMManagerNative || manager == platform.PAMManagerPamConfig) && r.rollingSnapshot == nil {
		return errors.New("password prerequisites require the approved immutable guest snapshot")
	}
	command, err := passwordFixtureCommand(manager)
	if err != nil {
		return err
	}
	// Dispatch pinned every enabled vendor repository to its captured closure
	// before this lane; package managers cannot fall back to moving mirrors.
	return lifecycleCommand(ctx, r.vm, "prepare native password quality tools", command)
}

func passwordFixtureCommand(manager platform.PAMManager) (string, error) {
	var command string
	switch manager {
	case platform.PAMManagerPamAuthUpdate:
		command = "DEBIAN_FRONTEND=noninteractive apt-get install -y libpam-pwquality libpwquality-tools"
	case platform.PAMManagerAuthselect:
		command = "rpm -q libpwquality pam authselect"
	case platform.PAMManagerNative:
		command = "pacman -Syu --needed --noconfirm libpwquality pam pambase; pacman -Q libpwquality pam pambase"
	case platform.PAMManagerPamConfig:
		command = "zypper --non-interactive install --no-recommends pam_pwquality libpwquality1 libpwquality-tools pam pam-config; rpm -q pam_pwquality libpwquality1 libpwquality-tools pam pam-config"
	default:
		return "", errors.New("password fixture has no registered PAM manager")
	}
	return "set -eu\n" + command + "\ncommand -v pwscore", nil
}

// EL 9 cloud images (RHEL and AlmaLinux 9.8) ship the pam package's own stacks
// with no authselect selection. The provider refuses that unmanaged stack; the
// lane then selects the vendor sssd profile, as an installer-provisioned EL host
// has, before qualifying the managed path.
const passwordUnmanagedProbe = nativeOSRelease + `
case "$ID" in
 rhel|almalinux|rocky) if authselect current --raw >/dev/null 2>&1; then echo managed; else echo unmanaged; fi ;;
 *) echo managed ;;
esac
`

const passwordSelectAuthselectScript = `set -eu
authselect select sssd --force
authselect check
`

// unmanagedStackOracle records the unmanaged stacks byte for byte and requires
// that no authselect selection appeared.
func unmanagedStackOracle(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
	return resourceOracle(ctx, vm, "native-unmanaged-pam-stack", "if authselect current --raw; then exit 1; fi; ls -l /etc/pam.d/system-auth /etc/pam.d/password-auth; sha256sum /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/security/pwquality.conf")
}

func resourcePasswordDesired(minLength uint32) *resourcev1.ResourceDesiredState {
	policy := &resourcev1.PasswordPolicyDesired{MinLength: proto.Uint32(minLength), MinClasses: proto.Uint32(3)}
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_PASSWORD_POLICY, CanonicalKey: "system/local-auth"}, State: &resourcev1.ResourceDesiredState_PasswordPolicy{PasswordPolicy: policy}}
}

// The candidates contain no dictionary words: twelve characters in three
// classes, and a twenty-character variant of the same classes.
const (
	passwordShortCandidate = "Qz7vKx2wRt9m"
	passwordLongCandidate  = "Qz7vKx2wRt9mBn4cJh8p"
)

// passwordOracle uses libpwquality's own pwscore, which reads the effective
// native configuration, and the distribution's PAM password stack.
func passwordOracle(minLength uint32) func(context.Context, *guestVM) (VMResourceNativeRecord, error) {
	return func(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
		manager, err := passwordGuestManager(ctx, vm)
		if err != nil {
			return VMResourceNativeRecord{}, err
		}
		var path string
		switch manager {
		case platform.PAMManagerPamAuthUpdate, platform.PAMManagerPamConfig:
			path = "/etc/pam.d/common-password"
		case platform.PAMManagerAuthselect:
			path = "/etc/pam.d/system-auth"
		case platform.PAMManagerNative:
			path = "/etc/pam.d/lindm-password"
		default:
			return VMResourceNativeRecord{}, errors.New("no registered native password stack")
		}
		stack := "stack=" + nativeQuote(path) + "; "
		if minLength > 0 {
			stack += "grep -E '^password[[:space:]].*pam_pwquality[.]so' \"$stack\"; "
			if manager == platform.PAMManagerNative {
				stack += "grep -qx 'password include lindm-password' /etc/pam.d/system-auth; grep -q 'pam_unix.so.*use_authtok' /etc/pam.d/system-auth; "
			}
		} else {
			if manager == platform.PAMManagerNative {
				stack += "test ! -e /etc/pam.d/lindm-password; if grep -q 'lindm-password' /etc/pam.d/system-auth; then exit 1; fi; "
			}
		}
		command := stack + "printf '%s\\n' " + passwordLongCandidate + " | pwscore; "
		if minLength > 12 {
			command += "if printf '%s\\n' " + passwordShortCandidate + " | pwscore; then exit 1; fi; printf 'short-rejected\\n'; "
		} else {
			command += "printf '%s\\n' " + passwordShortCandidate + " | pwscore; printf 'short-accepted\\n'; "
		}
		command += "grep -rh '^[[:space:]]*\\(minlen\\|minclass\\)' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ || true"
		return resourceOracle(ctx, vm, "native-pwquality-pam-stack", command)
	}
}

func exerciseResourcePassword(ctx context.Context, packages *nativeGuestPackages, r *resourceDispatch, evidence *VMResourceKindEvidence) (resultErr error) {
	manager, err := passwordGuestManager(ctx, r.vm)
	if err != nil {
		return err
	}
	if err := preparePasswordFixture(ctx, r, manager); err != nil {
		return err
	}
	session, err := openRootRecoverySession(ctx, r.vm)
	if err != nil {
		return fmt.Errorf("open root recovery session: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, session.Close()) }()
	if err := enablePasswordProvider(ctx, packages, session.id); err != nil {
		return err
	}
	rolling := manager == platform.PAMManagerNative || manager == platform.PAMManagerPamConfig
	current := "qQ7_" + rand.Text()
	if rolling {
		if err := lifecycleCommand(ctx, r.vm, "create ordinary PAM conversation account", "useradd --create-home --shell /bin/bash lindm-pam-lab"); err != nil {
			return err
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
			defer cancel()
			resultErr = errors.Join(resultErr, lifecycleCommand(cleanup, r.vm, "remove PAM conversation account", "userdel --remove lindm-pam-lab"))
		}()
		if _, err := r.vm.run(ctx, "sudo -n chpasswd", strings.NewReader("lindm-pam-lab:"+current+"\n"), 4096, time.Minute); err != nil {
			return err
		}
	}
	qualityOracle := func(length uint32) func(context.Context) (VMResourceNativeRecord, error) {
		return func(ctx context.Context) (VMResourceNativeRecord, error) {
			if rolling {
				next := "qQ7_" + rand.Text()
				boundary, err := passwordConversationBoundary(length)
				if err != nil {
					return VMResourceNativeRecord{}, err
				}
				rejected := boundary
				if length == 0 {
					next, rejected = boundary, ""
				}
				if err := ordinaryPasswordConversation(ctx, session, current, next, rejected); err != nil {
					return VMResourceNativeRecord{}, err
				}
				current = next
			}
			return passwordOracle(length)(ctx, r.vm)
		}
	}
	names := []string{"quality-baseline-rejects-short", "quality-reconcile-length", "repeat", "release-restores-defaults"}
	probeScript, err := r.vm.nativeScript(passwordUnmanagedProbe)
	if err != nil {
		return err
	}
	probe, err := r.vm.run(ctx, "sudo -n /bin/sh -eu -c "+nativeQuote(probeScript), nil, 4096, time.Minute)
	if err != nil {
		return fmt.Errorf("probe PAM stack manager: %w", err)
	}
	if strings.TrimSpace(string(probe)) == "unmanaged" {
		r.fresh()
		if err := resourceRefusalStep(ctx, r, evidence, "unmanaged-pam-stack-refused", resourcePasswordDesired(14), resourceAdoptionPolicy(), withVM(r.vm, unmanagedStackOracle)); err != nil {
			return err
		}
		if err := lifecycleCommand(ctx, r.vm, "select vendor authselect sssd profile", passwordSelectAuthselectScript); err != nil {
			return err
		}
		names = append([]string{"unmanaged-pam-stack-refused"}, names...)
	}
	r.fresh()
	if err := resourceStep(ctx, r, evidence, "quality-baseline-rejects-short", resourcePasswordDesired(14), resourceAdoptionPolicy(), false, qualityOracle(14)); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "quality-reconcile-length", resourcePasswordDesired(16), resourceAdoptionPolicy(), false, qualityOracle(16)); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "repeat", resourcePasswordDesired(16), resourceAdoptionPolicy(), true, qualityOracle(16)); err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, evidence, "release-restores-defaults", resourcePasswordDesired(16).GetRef(), qualityOracle(0)); err != nil {
		return err
	}
	evidence.Unproven = []string{"history, aging and faillock lockout dimensions and interactive PAM password change are not exercised"}
	if rolling {
		evidence.Unproven = []string{"aging and faillock lockout dimensions are not exercised"}
	}
	if manager == platform.PAMManagerNative {
		extra, err := exerciseNativePasswordHistory(ctx, r, session, evidence, &current)
		if err != nil {
			return err
		}
		evidence.Unproven = append(evidence.Unproven, "historical-password reuse rejection is not exercised")
		names = append(names, extra...)
	} else if rolling {
		evidence.Unproven = append(evidence.Unproven, "pam-config local-only history activation is unsupported")
	}
	return qualifyResourceEvidence(evidence, names)
}

// A managed negative probe is otherwise-valid and exactly one character below
// the requested minimum. Release must accept a baseline-length password that
// the managed policy rejected, not merely another universally long password.
func passwordConversationBoundary(minLength uint32) (string, error) {
	if minLength == 0 {
		return passwordConversationBoundary(16)
	}
	if minLength <= uint32(len(passwordShortCandidate)) || minLength > uint32(len(passwordLongCandidate)) {
		return "", errors.New("password conversation boundary outside fixture range")
	}
	return passwordLongCandidate[:minLength-1], nil
}

// ordinaryPasswordConversation runs the real setuid passwd with an ordinary
// real UID over a bounded PTY, never root chpasswd or a quality-score surrogate.
// Passwords travel only on the encrypted session's stdin, not argv or evidence.
func ordinaryPasswordConversation(ctx context.Context, recovery *rootRecoverySession, current, next, rejected string) error {
	if rejected != "" {
		if err := ordinaryPasswordAttempt(ctx, recovery, current, rejected, true); err != nil {
			return err
		}
	}
	return ordinaryPasswordAttempt(ctx, recovery, current, next, false)
}

func ordinaryPasswordAttempt(ctx context.Context, recovery *rootRecoverySession, current, next string, expectRejection bool) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	session, err := recovery.client.NewSession()
	if err != nil {
		return err
	}
	defer func() { _ = session.Close() }()
	reader, writer := io.Pipe()
	defer func() { _ = reader.Close() }()
	defer func() { _ = writer.Close() }()
	session.Stdout, session.Stderr = writer, writer
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	defer func() { _ = stdin.Close() }()
	stop := context.AfterFunc(ctx, func() {
		_ = session.Close()
		_ = reader.CloseWithError(ctx.Err())
		_ = writer.CloseWithError(ctx.Err())
	})
	defer stop()
	if err := session.RequestPty("xterm", 24, 120, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		return err
	}
	if err := session.Start("exec sudo -n -u lindm-pam-lab env LC_ALL=C sh -c 'test \"$(id -u)\" -ne 0; exec passwd'"); err != nil {
		return err
	}
	finished := make(chan error, 1)
	go func() {
		err := session.Wait()
		_ = writer.Close()
		finished <- err
	}()
	prompt := func(needles ...string) (string, error) {
		var output strings.Builder
		var block [512]byte
		for output.Len() < 8192 {
			n, err := reader.Read(block[:])
			if n > 0 {
				output.Write(block[:n])
				lower := strings.ToLower(output.String())
				for _, needle := range needles {
					if strings.HasSuffix(strings.TrimSpace(lower), needle) {
						return lower, nil
					}
				}
			}
			if err != nil {
				return strings.ToLower(output.String()), err
			}
		}
		return "", errors.New("PAM conversation exceeded output limit")
	}
	answer := func(value string, needles ...string) error {
		if _, err := prompt(needles...); err != nil {
			return fmt.Errorf("ordinary-user PAM prompt: %w", err)
		}
		_, err := io.WriteString(stdin, value+"\n")
		return err
	}
	if err := answer(current, "current password:", "(current) unix password:"); err != nil {
		return err
	}
	if expectRejection {
		badPassword := false
		for attempt := 0; attempt <= 3; attempt++ {
			output, err := prompt("new password:")
			badPassword = badPassword || strings.Contains(output, "bad password")
			if errors.Is(err, io.EOF) {
				exit := <-finished
				if badPassword && exit != nil && ctx.Err() == nil {
					return nil
				}
				return errors.New("ordinary-user weak password did not fail through PAM")
			}
			if err != nil {
				return err
			}
			if strings.Contains(output, "retype") || attempt == 3 {
				return errors.New("ordinary-user PAM did not enforce weak-password rejection")
			}
			if _, err := io.WriteString(stdin, next+"\n"); err != nil {
				return err
			}
		}
	}
	if err := answer(next, "new password:"); err != nil {
		return err
	}
	if err := answer(next, "retype new password:", "retype password:"); err != nil {
		return err
	}
	n, drainErr := io.Copy(io.Discard, io.LimitReader(reader, 8193))
	if n > 8192 {
		_ = session.Close()
		return errors.New("PAM completion exceeded output limit")
	}
	return errors.Join(<-finished, drainErr)
}

func exerciseNativePasswordHistory(ctx context.Context, r *resourceDispatch, recovery *rootRecoverySession, evidence *VMResourceKindEvidence, current *string) ([]string, error) {
	desired := resourcePasswordDesired(0)
	desired.State = &resourcev1.ResourceDesiredState_PasswordPolicy{PasswordPolicy: &resourcev1.PasswordPolicyDesired{}}
	oracle := func(ctx context.Context) (VMResourceNativeRecord, error) {
		next := "qQ7_" + rand.Text()
		if err := ordinaryPasswordConversation(ctx, recovery, *current, next, ""); err != nil {
			return VMResourceNativeRecord{}, err
		}
		*current = next
		return resourceOracle(ctx, r.vm, "ordinary-user-history-pam-conversation", "id lindm-pam-lab; grep '^remember' /etc/security/pwhistory.conf; cat /etc/pam.d/lindm-password; grep 'pam_unix.so' /etc/pam.d/system-auth")
	}
	names := []string{"history-zero-ordinary-password", "history-nonzero-ordinary-password", "history-nonzero-to-zero-password", "history-release"}
	r.fresh()
	for index, count := range []uint32{0, 5, 0} {
		desired.GetPasswordPolicy().HistoryCount = proto.Uint32(count)
		if err := resourceStep(ctx, r, evidence, names[index], desired, resourceAdoptionPolicy(), false, oracle); err != nil {
			return nil, err
		}
	}
	if err := resourceReleaseStep(ctx, r, evidence, "history-release", desired.GetRef(), withVM(r.vm, passwordOracle(0))); err != nil {
		return nil, err
	}
	// A deliberate administrator-owned quality module must not be preceded by
	// newly owned history: a quality retry could replace its already-checked
	// token. Refusal is measured before effect and after release with equal bytes.
	const backup = "/var/tmp/lindm-native-lab/password-system-auth"
	if err := lifecycleCommand(ctx, r.vm, "stage unowned PAM quality fixture", "set -eu\ncp -p /etc/pam.d/system-auth "+backup+"\nsed -i '/^-password/i password requisite pam_pwquality.so retry=3' /etc/pam.d/system-auth"); err != nil {
		return nil, err
	}
	restore := func() error {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		return lifecycleCommand(cleanup, r.vm, "restore administrator PAM fixture", "cp -p "+backup+" /etc/pam.d/system-auth; rm "+backup)
	}
	r.fresh()
	desired.GetPasswordPolicy().HistoryCount = proto.Uint32(5)
	err := resourceRefusalStep(ctx, r, evidence, "mixed-unowned-quality-history-refused", desired, resourceAdoptionPolicy(), func(ctx context.Context) (VMResourceNativeRecord, error) {
		return resourceOracle(ctx, r.vm, "mixed-native-password-stack", "sha256sum /etc/pam.d/system-auth; if test -e /etc/security/pwhistory.conf; then sha256sum /etc/security/pwhistory.conf; else printf 'pwhistory-absent\\n'; fi; test ! -e /etc/pam.d/lindm-password")
	})
	if err := errors.Join(err, restore()); err != nil {
		return nil, err
	}
	return append(names, "mixed-unowned-quality-history-refused"), nil
}
