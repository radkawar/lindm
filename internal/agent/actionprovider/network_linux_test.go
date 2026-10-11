//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"lindm/internal/agent/nativeexec"
)

// The native parser and kernel must accept the timeout set's fixed-width key;
// a fake successful nft command cannot detect an unqualified integer key type.
func TestQuarantineRulesNativeCheckInPrivateNetwork(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native nft check requires root and a private network namespace")
	}
	if _, err := os.Stat(executable[nft]); errors.Is(err, os.ErrNotExist) {
		t.Skip("native nft is unavailable")
	} else if err != nil {
		t.Fatal(err)
	}
	rules, err := quarantineRules("lindm_q_native_check", []string{"127.0.0.1", "10.0.2.2", "::1"}, []string{"10.0.2.3", "2001:db8::53"}, 60)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable[nft], "--check", "--file", "-")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LANG=C", "LC_ALL=C"}
	cmd.Stdin = bytes.NewReader(rules)
	output := nativeexec.NewBuffer(outputLimit)
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Run(); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skip("private network namespace capability unavailable")
		}
		t.Fatalf("native nft rejected quarantine rules: %v: %s", err, output.Bytes())
	}
}
