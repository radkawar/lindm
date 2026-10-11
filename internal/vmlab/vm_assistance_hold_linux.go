//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"lindm/internal/devlab"
)

// AssistanceHold is the owner's access to a held assistance demo. The
// enrollment secret and desktop password are for the owner only: callers keep
// them in private files, never in logs.
type AssistanceHold struct {
	ConsoleOrigin    string
	Username         string
	EnrollmentSecret string
	ExpiresAt        time.Time
	DeviceID         string
	Hostname         string
	// DisplaySocket is the guest's QEMU VNC server: a Unix socket inside the
	// VM's private 0700 run directory, with no TCP listener.
	DisplaySocket   string
	DesktopUser     string
	DesktopPassword string
}

// holdAssistance hands the owner a fresh console enrollment and the guest's
// display and login, then keeps lindmd and the VM running until ctx ends.
// Consent stays the guest user's own click; nothing is seeded for the device.
func holdAssistance(ctx context.Context, vm *EncryptedVM, fixture *devlab.AuthorityFixture, result *VMAssistanceResult, hold func(*AssistanceHold) error) error {
	hostname, err := vm.Run(ctx, "hostname", nil)
	if err != nil {
		return err
	}
	// GDM autologin owns the session and locking is off; the password only
	// matters if the owner locks or logs out, so it is set now and handed over.
	access := &AssistanceHold{ConsoleOrigin: fixture.ConsoleOrigin, DeviceID: result.DeviceID, Hostname: strings.TrimSpace(string(hostname)), DisplaySocket: filepath.Join(vm.dir, "display.sock"), DesktopUser: actionDesktopUser, DesktopPassword: rand.Text()}
	defer func() { access.EnrollmentSecret, access.DesktopPassword = "", "" }()
	line := []byte(actionDesktopUser + ":" + access.DesktopPassword + "\n")
	_, err = vm.Run(ctx, "sudo -n chpasswd", bytes.NewReader(line))
	clear(line)
	if err != nil {
		return fmt.Errorf("set demo desktop password: %w", err)
	}
	enrollment, err := fixture.CreateConsoleEnrollment(ctx)
	if err != nil {
		return err
	}
	access.Username, access.EnrollmentSecret, access.ExpiresAt = "console-owner", enrollment.GetSecret(), enrollment.GetExpiresAt().AsTime().UTC()
	enrollment.Secret = ""
	if err := hold(access); err != nil {
		return err
	}
	held, stop := context.WithCancelCause(ctx)
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		select {
		case <-vm.guest.done:
			stop(errors.New("demo VM exited"))
		case <-held.Done():
		}
	}()
	defer func() { stop(nil); <-watched }()
	if err := fixture.Wait(held); err != nil {
		return err
	}
	if ctx.Err() == nil {
		return context.Cause(held)
	}
	return nil
}
