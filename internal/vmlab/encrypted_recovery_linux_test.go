// SPDX-License-Identifier: Apache-2.0

package vmlab

import "testing"

func TestEncryptedRecoveryRequiresExclusiveStoppedTarget(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target EncryptedVM
	}{
		{"closed", EncryptedVM{closed: true}},
		{"running", EncryptedVM{guest: &guestVM{}}},
		{"TPM running", EncryptedVM{tpm: &encryptedProcess{}}},
		{"recovery active", EncryptedVM{recoveryActive: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.target.BootRecovery(t.Context(), nil, VMHardwareOptions{}); err == nil {
				t.Fatal("accepted target before stopped/exclusive ownership checks")
			}
		})
	}
	if err := (&EncryptedVM{}).recoveryReady(); err != nil {
		t.Fatalf("stopped available target rejected: %v", err)
	}
}

func TestEncryptedRecoveryCloseReleasesOnlyItsReservation(t *testing.T) {
	target := &EncryptedVM{recoveryActive: true}
	recovery := &EncryptedRecoveryVM{target: target}
	if err := recovery.Close(); err != nil {
		t.Fatal(err)
	}
	if target.recoveryActive || target.closed || !recovery.closed {
		t.Fatal("recovery close did not release reservation independently of target lifecycle")
	}
	if err := recovery.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Run(t.Context(), "true", nil); err == nil {
		t.Fatal("closed recovery accepted a command")
	}
}

func TestEncryptedRecoveryCloseReleasesReapedCrash(t *testing.T) {
	done := make(chan struct{})
	close(done)
	target := &EncryptedVM{recoveryActive: true}
	recovery := &EncryptedRecoveryVM{target: target, guest: &guestVM{dir: t.TempDir(), done: done}}
	if err := recovery.Close(); err != nil {
		t.Fatal(err)
	}
	if target.recoveryActive {
		t.Fatal("reaped recovery crash retained target writer reservation")
	}
}
