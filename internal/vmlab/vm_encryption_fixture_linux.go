// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// configureVMEncryptionFixture deliberately formats only the first extra disk
// identified by the harness serial, never a guessed guest device name. It refuses
// existing signatures or children and never installs missing guest dependencies.
// This is an inventory fixture, not a production encryption provider or policy.
func configureVMEncryptionFixture(ctx context.Context, vm *guestVM, mode string) error {
	if mode == "" || mode == "none" {
		return nil
	}
	if mode != "luks1" && mode != "luks2" && mode != "lvm-luks2" {
		return errors.New("encryption fixture must be none, luks1, luks2 or lvm-luks2")
	}
	if vm.hardware.ExtraDisks < 1 {
		return errors.New("encryption inventory fixture requires an extra disposable disk")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	command := `sudo sh -eu -c '
command -v cryptsetup >/dev/null
command -v wipefs >/dev/null
command -v mkfs.ext4 >/dev/null
mode=$1
if [ "$mode" = lvm-luks2 ]; then
 command -v pvcreate >/dev/null
 command -v vgcreate >/dev/null
 command -v lvcreate >/dev/null
fi
disk=$(lsblk -dnro NAME,SERIAL | while read -r name serial; do if [ "$serial" = lindm-lab-1 ]; then printf "/dev/%s\n" "$name"; fi; done)
[ -n "$disk" ]
[ "$(printf "%s\n" "$disk" | wc -l)" = 1 ]
[ -b "$disk" ]
[ "$(lsblk -nr -o NAME "$disk" | wc -l)" = 1 ]
[ -z "$(wipefs --no-act --noheadings "$disk")" ]
[ ! -e /dev/mapper/lindm-lab-fixture ]
IFS= read -r secret
type=$mode
if [ "$mode" = lvm-luks2 ]; then type=luks2; fi
printf "%s" "$secret" | cryptsetup luksFormat --batch-mode --type "$type" --pbkdf pbkdf2 --iter-time 50 --key-file - "$disk"
printf "%s" "$secret" | cryptsetup open --key-file - "$disk" lindm-lab-fixture
unset secret
target=/dev/mapper/lindm-lab-fixture
if [ "$mode" = lvm-luks2 ]; then
 pvcreate "$target" >/dev/null
 vgcreate lindm_lab_fixture "$target" >/dev/null
 lvcreate -l 100%FREE -n data lindm_lab_fixture >/dev/null
 target=/dev/lindm_lab_fixture/data
fi
mkfs.ext4 -q "$target"
' -- ` + nativeQuote(mode)
	result, err := vm.runResult(ctx, command, strings.NewReader(hex.EncodeToString(secret)+"\n"), 4096, 2*time.Minute)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return errors.New("guest encryption fixture failed: require cryptsetup, wipefs, mkfs.ext4 (and LVM for lvm-luks2), plus empty harness-owned extra disk")
	}
	return nil
}
