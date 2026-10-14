// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// demoSerialLimit bounds the retained console transcript of one unattended boot.
const demoSerialLimit = 1 << 20

// boundedConsole keeps the first demoSerialLimit bytes of a boot console. An
// unattended boot types no secret, so the transcript holds none.
type boundedConsole struct{ bytes.Buffer }

func (c *boundedConsole) Write(p []byte) (int, error) {
	if room := demoSerialLimit - c.Len(); room > 0 {
		c.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// demoTPMBootProbe gathers read-only boot evidence for a TPM-bound root: this
// boot's TPM/cryptsetup journal and kernel lines, TPM devices and modules,
// crypttab, initramfs TPM content, PCR 0-7 and the LUKS token metadata
// (sealed policy and PCR mask; the sealed blob is not a secret).
const demoTPMBootProbe = `exec 2>&1
echo "== boot $(cat /proc/sys/kernel/random/boot_id) uptime $(cut -d' ' -f1 /proc/uptime)"
echo "== journal (tpm|crypt)"; journalctl -b 0 --no-pager -o short-monotonic | grep -iE 'tpm|crypt' | head -n 400 || true
echo "== /dev/tpm*"; ls -l /dev/tpm* || true
echo "== modules"; lsmod | grep -i tpm || true
echo "== crypttab"; cat /etc/crypttab || true
echo "== initramfs tpm content"; for f in /boot/initrd.img /boot/initramfs-$(uname -r).img; do if test -e "$f"; then (lsinitrd "$f" 2>/dev/null || lsinitramfs "$f" 2>/dev/null) | grep -iE 'tpm|tss2' | head -n 60; fi; done || true
echo "== pcrs"; tpm2_pcrread sha256:0,1,2,3,4,5,6,7 || true
echo "== luks tokens"; uuid=$(awk '$1 !~ /^#/ && $2 ~ /^UUID=/ {sub(/^UUID=/, "", $2); print $2; exit}' /etc/crypttab); cryptsetup luksDump "/dev/disk/by-uuid/$uuid" | sed -n '/^Tokens:/,/^Digests:/p' || true
`

// demoUnattendedBoot boots a TPM-bound device without a secret. If the TPM does
// not unseal and the initramfs prompts, it types the stored owner passphrase
// exactly as a user at the prompt would, reports that plainly and keeps the
// binding: it never rebinds. Both outcomes retain evidence for diagnosis.
func demoUnattendedBoot(ctx context.Context, vm *EncryptedVM, evidenceDir, label, hostname string, progress io.Writer) (UnlockOutcome, bool, error) {
	console := new(boundedConsole)
	vm.bootConsole = console
	boot, err := vm.ColdBoot(ctx, "")
	vm.bootConsole = nil
	if err == nil {
		return boot, false, writeDemoTPMEvidence(ctx, vm, evidenceDir, label+"-unattended", nil)
	}
	if !boot.PromptSeen || boot.Accepted || ctx.Err() != nil {
		return boot, false, err
	}
	if _, werr := fmt.Fprintf(progress, "%s: TPM unattended unlock fell back to passphrase on this boot (known intermittent race, reported)\n", hostname); werr != nil {
		return boot, false, werr
	}
	boot, err = vm.coldBoot(ctx, vm.InitialUnlockSecret(), false, nil)
	if err != nil {
		return boot, true, err
	}
	return boot, true, writeDemoTPMEvidence(ctx, vm, evidenceDir, label+"-fallback", console.Bytes())
}

// writeDemoTPMEvidence stores the failed boot's console and the current boot's
// TPM evidence in the private device evidence directory.
func writeDemoTPMEvidence(ctx context.Context, vm *EncryptedVM, evidenceDir, name string, failedConsole []byte) error {
	if evidenceDir == "" {
		return errors.New("TPM boot evidence requires the device evidence directory")
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	if failedConsole != nil {
		if err := os.WriteFile(filepath.Join(evidenceDir, "tpm-boot-"+stamp+"-"+name+"-prompted-console.log"), failedConsole, 0o600); err != nil {
			return err
		}
	}
	result, err := vm.guest.runResult(ctx, "sudo -n sh", strings.NewReader(demoTPMBootProbe), 1<<20, 2*time.Minute)
	if err != nil {
		return fmt.Errorf("collect TPM boot evidence: %w", err)
	}
	return os.WriteFile(filepath.Join(evidenceDir, "tpm-boot-"+stamp+"-"+name+".txt"), result.Stdout, 0o600)
}
