//go:build linux

package vmlab

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
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

func openRootRecoverySession(ctx context.Context, vm *guestVM) (_ *rootRecoverySession, resultErr error) {
	if err := lifecycleCommand(ctx, vm, "authorize disposable root recovery login", "install -d -o root -g root -m 0700 /root/.ssh; install -o root -g root -m 0600 /home/"+labUser+"/.ssh/authorized_keys /root/.ssh/authorized_keys; if command -v restorecon >/dev/null 2>&1; then restorecon -RF /root/.ssh; fi"); err != nil {
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

const passwordFixtureScript = `set -eu
. /etc/os-release
case "$ID" in
 ubuntu) DEBIAN_FRONTEND=noninteractive apt-get install -y libpam-pwquality libpwquality-tools ;;
 fedora) rpm -q libpwquality pam ;;
esac
command -v pwscore
`

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
		stack := ". /etc/os-release; case \"$ID\" in ubuntu) stack=/etc/pam.d/common-password ;; fedora) stack=/etc/pam.d/system-auth ;; esac; grep -E '^password[[:space:]].*pam_pwquality[.]so' \"$stack\"; "
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
	if err := lifecycleCommand(ctx, r.vm, "install native password quality tools", passwordFixtureScript); err != nil {
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
	r.fresh()
	if err := resourceStep(ctx, r, evidence, "quality-baseline-rejects-short", resourcePasswordDesired(14), resourceCreatePolicy(), false, withVM(r.vm, passwordOracle(14))); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "quality-reconcile-length", resourcePasswordDesired(16), resourceCreatePolicy(), false, withVM(r.vm, passwordOracle(16))); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "repeat", resourcePasswordDesired(16), resourceCreatePolicy(), true, withVM(r.vm, passwordOracle(16))); err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, evidence, "release-restores-defaults", resourcePasswordDesired(16).GetRef(), withVM(r.vm, passwordOracle(0))); err != nil {
		return err
	}
	evidence.Unproven = []string{"history, aging and faillock lockout dimensions and interactive PAM password change are not exercised"}
	return qualifyResourceEvidence(evidence, []string{"quality-baseline-rejects-short", "quality-reconcile-length", "repeat", "release-restores-defaults"})
}
