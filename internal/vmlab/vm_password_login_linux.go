//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Password-login proofs dial the guest's pinned loopback SSH forward as the
// named local user with password authentication only. The password exists only
// in caller memory and in x/crypto's unavoidable string copy; it never enters
// argv, environment, records or errors.

var passwordLoginUser = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// installPasswordLoginDropIn enables sshd password authentication for exactly
// one disposable account and records sshd's own effective configuration.
func installPasswordLoginDropIn(ctx context.Context, vm *guestVM, user string) (VMResourceNativeRecord, error) {
	if !passwordLoginUser.MatchString(user) {
		return VMResourceNativeRecord{}, errors.New("invalid password login account")
	}
	path := "/etc/ssh/sshd_config.d/01-lindm-lab-password-" + user + ".conf"
	script := "umask 022; printf 'Match User %s\\n  PasswordAuthentication yes\\n' " + user + " > " + path + "; chmod 0644 " + path + "; if command -v restorecon >/dev/null 2>&1; then restorecon -F " + path + "; fi; /usr/sbin/sshd -t; systemctl reload ssh.service 2>/dev/null || systemctl reload sshd.service"
	if err := lifecycleCommand(ctx, vm, "enable disposable sshd password login for "+user, script); err != nil {
		return VMResourceNativeRecord{}, err
	}
	// sshd evaluates Match blocks against the connection; -T -C prints the
	// effective per-user result, and the global default stays disabled.
	oracle := "effective=$(/usr/sbin/sshd -T -C user=" + user + ",host=localhost,addr=127.0.0.1); printf '%s\\n' \"$effective\" | grep -Ex 'passwordauthentication yes'; printf '%s\\n' \"$effective\" | grep -E '^(kbdinteractiveauthentication|usepam|permitrootlogin) '; other=$(/usr/sbin/sshd -T -C user=lindm-lab-other,host=localhost,addr=127.0.0.1); printf '%s\\n' \"$other\" | grep -Eqx 'passwordauthentication no'; printf 'other-users: passwordauthentication no\\n'; cat " + path
	return resourceOracle(ctx, vm, "native-sshd-effective-password-authentication", oracle)
}

func passwordLoginConfig(vm *guestVM, user string, password []byte) *ssh.ClientConfig {
	config := *vm.config
	config.User = user
	config.Auth = []ssh.AuthMethod{ssh.Password(string(password))}
	return &config
}

// passwordLogin proves a real PAM/logind session for user and the matching sshd
// journal entry. Only identities and session metadata are recorded.
func passwordLogin(ctx context.Context, vm *guestVM, user string, password []byte) ([]VMResourceNativeRecord, error) {
	if !passwordLoginUser.MatchString(user) {
		return nil, errors.New("invalid password login account")
	}
	since, err := guestEpoch(ctx, vm)
	if err != nil {
		return nil, err
	}
	output, err := passwordSession(ctx, vm, user, password, "id; printf 'session=%s\\n' \"$XDG_SESSION_ID\"; loginctl show-session \"$XDG_SESSION_ID\" -p Name -p Service -p Remote -p Type -p Class")
	if err != nil {
		return nil, fmt.Errorf("password login as %s: %w", user, err)
	}
	if !bytes.Contains(output, []byte("Name="+user+"\n")) || !bytes.Contains(output, []byte("Service=sshd\n")) || !bytes.Contains(output, []byte("Remote=yes\n")) {
		return nil, fmt.Errorf("password login as %s lacks its own remote sshd logind session", user)
	}
	login := resourceNativeRecord("native-ssh-password-login", output)
	// The journal entry is sshd's own authentication verdict for this method.
	journal, err := resourceOracle(ctx, vm, "native-sshd-journal-accepted-password", "journalctl --no-pager -o short-iso --since=@"+strconv.FormatInt(since, 10)+" | grep -F "+nativeQuote("Accepted password for "+user+" from "))
	if err != nil {
		return nil, err
	}
	return []VMResourceNativeRecord{login, journal}, nil
}

// passwordLoginRefused requires sshd to reject the password itself; a network
// or host-key failure is never accepted as a refusal.
func passwordLoginRefused(ctx context.Context, vm *guestVM, user string, password []byte, name string) (VMResourceNativeRecord, error) {
	if !passwordLoginUser.MatchString(user) {
		return VMResourceNativeRecord{}, errors.New("invalid password login account")
	}
	_, err := passwordSession(ctx, vm, user, password, "id")
	if err == nil {
		return VMResourceNativeRecord{}, fmt.Errorf("%s: password login as %s unexpectedly succeeded", name, user)
	}
	if !strings.Contains(err.Error(), "ssh: unable to authenticate") {
		return VMResourceNativeRecord{}, fmt.Errorf("%s: password login as %s failed without an authentication refusal: %w", name, user, err)
	}
	return resourceNativeRecord(name, []byte("user="+user+"\nrefusal="+err.Error()+"\n")), nil
}

func passwordSession(ctx context.Context, vm *guestVM, user string, password []byte, command string) ([]byte, error) {
	config := passwordLoginConfig(vm, user, password)
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", vm.address)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	sshConn, channels, requests, err := ssh.NewClientConn(conn, vm.address, config)
	if err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	client := ssh.NewClient(sshConn, channels, requests)
	defer func() { _ = client.Close() }() // The session result is already complete.
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = session.Close() }()
	stdout := &limitedOutput{limit: 16 << 10}
	session.Stdout = stdout
	if err := session.Run(command); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return stdout.data, nil
}

func guestEpoch(ctx context.Context, vm *guestVM) (int64, error) {
	data, err := vm.run(ctx, "date +%s", nil, 64, 10*time.Second)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || value <= 0 {
		return 0, errors.New("invalid guest clock")
	}
	return value - 1, nil
}
