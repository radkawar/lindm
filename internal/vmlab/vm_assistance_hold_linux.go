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
	ConsoleOrigin string
	// RelayPort is the loopback TURN listener (UDP and TCP); a remote console
	// forwards it over SSH and reaches the relay with TURN over TCP.
	RelayPort        uint32
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
	// Split handoff metadata identifies the two hosts without disclosing secrets.
	ControllerAddress string
	RemoteEvidenceDir string
	RespondBinary     string
	Findings          *devlab.DeviceFindingCounts
	Persistent        bool
	ExistingAccount   bool
	OwnerAccessFile   string
	TPMActionID       string
	Resumed           bool
	// TPMPassphraseFallback reports that this run's boot of a TPM-bound device
	// prompted and was unlocked with the stored owner passphrase.
	TPMPassphraseFallback bool
}

// holdAssistance hands the owner a fresh console enrollment and the guest's
// display and login, then keeps lindmd and the VM running until ctx ends.
// Consent stays the guest user's own click; nothing is seeded for the device.
func holdAssistance(ctx context.Context, vm *EncryptedVM, fixture *devlab.AuthorityFixture, screen *assistanceScreen, result *VMAssistanceResult, hold func(*AssistanceHold) error, split bool, findings *devlab.DeviceFindingCounts, existingOwner bool) error {
	hostname, err := vm.Run(ctx, "hostname", nil)
	if err != nil {
		return err
	}
	// AssistanceRespond reaches this VM's QMP display through the record.
	if _, err := screen.evidence.write("held VM directory", heldVMFile, []byte(vm.dir+"\n")); err != nil {
		return err
	}
	// A check scenario's "ended" banner must not linger: the owner's first
	// prompt is located against the clean desktop.
	if err := screen.waitNoBanner(ctx, 45*time.Second); err != nil {
		return err
	}
	// GDM autologin owns the session and locking is off; the password only
	// matters if the owner locks or logs out, so it is set now and handed over.
	access := &AssistanceHold{ConsoleOrigin: fixture.ConsoleOrigin, RelayPort: result.Relay.ListenerPort, DeviceID: result.DeviceID, Hostname: strings.TrimSpace(string(hostname)), DisplaySocket: filepath.Join(vm.dir, "display.sock"), DesktopUser: actionDesktopUser, DesktopPassword: rand.Text()}
	access.Findings = findings
	access.Persistent, access.ExistingAccount = vm.persistentLock != nil, existingOwner
	if access.Persistent {
		device, err := vm.PersistentDevice()
		if err != nil {
			return err
		}
		if device == nil {
			return errors.New("held persistent VM has no enrolled device")
		}
		if device.DesktopPassword == "" {
			device.DesktopPassword = access.DesktopPassword
			if err := vm.SavePersistentDevice(device); err != nil {
				return err
			}
		}
		access.DesktopPassword = device.DesktopPassword
	}
	defer func() { access.EnrollmentSecret, access.DesktopPassword = "", "" }()
	line := []byte(actionDesktopUser + ":" + access.DesktopPassword + "\n")
	_, err = vm.Run(ctx, "sudo -n chpasswd", bytes.NewReader(line))
	clear(line)
	if err != nil {
		return fmt.Errorf("set demo desktop password: %w", err)
	}
	if !split && !existingOwner {
		enrollment, err := fixture.CreateConsoleEnrollment(ctx)
		if err != nil {
			return err
		}
		access.Username, access.EnrollmentSecret, access.ExpiresAt = "console-owner", enrollment.GetSecret(), enrollment.GetExpiresAt().AsTime().UTC()
		enrollment.Secret = ""
	}
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
	if split {
		<-held.Done()
	} else if err := fixture.Wait(held); err != nil {
		return err
	}
	if ctx.Err() == nil {
		return context.Cause(held)
	}
	return nil
}
