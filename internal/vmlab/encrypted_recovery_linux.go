// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
)

// EncryptedRecoveryVM boots an independently verified cloud root. Its journal is
// off-target and survives target-disk erasure, but is removed by Close. This lab
// fixture makes no production recovery-media or durable-handoff claim. Calls are
// sequential, like EncryptedVM calls, and the target stays exclusively reserved.
type EncryptedRecoveryVM struct {
	guest  *guestVM
	target *EncryptedVM
	closed bool
}

// BootRecovery attaches only this stopped machine's owned disk to a separately
// booted recovery guest. No caller-selected host disk path is accepted. A nonnil
// recovery returned with an error means cleanup failed; retain it and retry Close
// before operating on or destroying the reserved target.
func (v *EncryptedVM) BootRecovery(ctx context.Context, manifest *labv1.ImageManifest, hardware VMHardwareOptions) (_ *EncryptedRecoveryVM, err error) {
	if err := v.recoveryReady(); err != nil {
		return nil, err
	}
	if err := encryptedPrivateDir(v.dir); err != nil {
		return nil, err
	}
	disk, err := openRegular(filepath.Join(v.dir, "disk.qcow2"))
	if err != nil {
		return nil, fmt.Errorf("open owned recovery target: %w", err)
	}
	defer func() { err = errors.Join(err, disk.Close()) }()
	info, err := disk.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return nil, errors.New("recovery target must be an exclusively owned regular file")
	}
	if err := encryptedQCOWChain(disk, filepath.Join(v.dir, "disk.qcow2"), 0); err != nil {
		return nil, err
	}
	v.recoveryActive = true
	recovery := &EncryptedRecoveryVM{target: v}
	hardware.recoveryTarget = true
	guest, _, err := newVerifiedGuestWithHardware(ctx, manifest, v.cacheDir, filepath.Dir(v.dir), true, &hardware)
	if err != nil {
		v.recoveryActive = false
		return nil, err
	}
	recovery.guest = guest
	// Cleanup is owned by this handle, not the target. Failed teardown must not
	// release the target while a recovery process might still write its disk.
	fail := func(cause error) (*EncryptedRecoveryVM, error) {
		if closeErr := recovery.Close(); closeErr != nil {
			return recovery, errors.Join(cause, closeErr)
		}
		return nil, cause
	}
	if err := guest.connect(ctx); err != nil {
		return fail(fmt.Errorf("recovery SSH readiness: %w", err))
	}
	if _, err := guest.run(ctx, "sudo -n cloud-init status --wait --format=json", nil, 64<<10, 5*time.Minute); err != nil {
		return fail(fmt.Errorf("recovery cloud-init readiness: %w", err))
	}
	// QEMU opens the supervising process's pinned descriptor rather than
	// re-resolving a potentially replaced target pathname. Backings are checked
	// regular qcow2 files and QEMU opens those automatically read-only.
	path := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), disk.Fd())
	if err := recovery.attachTarget(ctx, path); err != nil {
		return fail(err)
	}
	if err := recovery.waitTarget(ctx); err != nil {
		return fail(err)
	}
	return recovery, nil
}

func (v *EncryptedVM) recoveryReady() error {
	if v.closed {
		return errors.New("encrypted VM is closed")
	}
	if v.guest != nil || v.tpm != nil {
		return errors.New("recovery requires a powered-off target")
	}
	if v.recoveryActive {
		return errors.New("encrypted VM already has an active recovery guest")
	}
	return nil
}

// Run executes only on the independent recovery root. Secret input/output stays
// in memory, with the same bounded SSH command contract as EncryptedVM.Run.
func (v *EncryptedRecoveryVM) Run(ctx context.Context, command string, input io.Reader) ([]byte, error) {
	if v.closed || v.guest == nil {
		return nil, errors.New("recovery VM is closed")
	}
	return v.guest.run(ctx, command, input, 1<<20, 2*time.Minute)
}

// Close stops/reaps recovery QEMU before releasing the target reservation. Only
// the recovery root's private directory is removed; the encrypted target remains.
func (v *EncryptedRecoveryVM) Close() error {
	if v.closed {
		return nil
	}
	if v.guest != nil {
		if v.guest.client != nil {
			_ = v.guest.client.Close()
		}
		if v.guest.done != nil {
			process := &encryptedProcess{cmd: v.guest.cmd, done: v.guest.done}
			if err := process.stop(); err != nil {
				return fmt.Errorf("stop recovery guest; target remains reserved: %w", err)
			}
		}
		if err := v.guest.tpm.stop(); err != nil {
			return fmt.Errorf("stop recovery TPM; target remains reserved: %w", err)
		}
		if v.guest.base != nil {
			closeErr := v.guest.base.Close()
			v.guest.base = nil
			if closeErr != nil {
				return fmt.Errorf("close recovery base: %w", closeErr)
			}
		}
		if err := os.RemoveAll(v.guest.dir); err != nil {
			return fmt.Errorf("remove recovery state: %w", err)
		}
	}
	v.guest = nil
	v.closed = true
	v.target.recoveryActive = false
	return nil
}

func (v *EncryptedRecoveryVM) attachTarget(ctx context.Context, path string) (err error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(v.guest.dir, "qmp.sock"))
	if err != nil {
		return fmt.Errorf("connect recovery QMP: %w", err)
	}
	defer func() { err = errors.Join(err, conn.Close()) }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	decoder := json.NewDecoder(io.LimitReader(conn, 64<<10))
	var greeting map[string]json.RawMessage
	if err := decoder.Decode(&greeting); err != nil {
		return fmt.Errorf("read recovery QMP greeting: %w", err)
	}
	if _, ok := greeting["QMP"]; !ok {
		return errors.New("missing recovery QMP greeting")
	}
	encoder := json.NewEncoder(conn)
	// QMP does not offer a transaction combining blockdev-add and device_add.
	// The exclusive target is exposed only after every command succeeds; on any
	// failure BootRecovery stops the entire recovery guest before returning.
	for _, command := range []map[string]any{
		{"execute": "qmp_capabilities", "id": "capabilities"},
		{"execute": "blockdev-add", "id": "target-file", "arguments": map[string]any{"driver": "file", "node-name": "recovery-target-file", "filename": path, "read-only": false}},
		{"execute": "blockdev-add", "id": "target-disk", "arguments": map[string]any{"driver": "qcow2", "node-name": "recovery-target-disk", "file": "recovery-target-file", "read-only": false}},
		{"execute": "device_add", "id": "target-device", "arguments": map[string]any{"driver": "scsi-hd", "id": "recovery-target", "bus": "recovery-scsi.0", "drive": "recovery-target-disk", "serial": "lindm-recovery-target", "wwn": uint64(0x5000c5000000abcd)}},
	} {
		if err := encoder.Encode(command); err != nil {
			return fmt.Errorf("write recovery QMP command: %w", err)
		}
		for {
			var response struct {
				ID     string          `json:"id"`
				Event  string          `json:"event"`
				Error  json.RawMessage `json:"error"`
				Return json.RawMessage `json:"return"`
			}
			if err := decoder.Decode(&response); err != nil {
				return fmt.Errorf("read recovery QMP response: %w", err)
			}
			if response.Event != "" {
				continue
			}
			if response.ID != command["id"] || len(response.Error) != 0 || len(response.Return) == 0 {
				return errors.New("QMP rejected recovery disk attachment")
			}
			break
		}
	}
	return nil
}

func (v *EncryptedRecoveryVM) waitTarget(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := v.guest.run(ctx, "lsblk --json --bytes --nodeps --output NAME,SERIAL,WWN,SIZE", nil, 64<<10, 10*time.Second)
		if err != nil {
			return fmt.Errorf("observe recovery target: %w", err)
		}
		var devices struct {
			BlockDevices []struct {
				Name   string      `json:"name"`
				Serial string      `json:"serial"`
				WWN    string      `json:"wwn"`
				Size   json.Number `json:"size"`
			} `json:"blockdevices"`
		}
		if err := json.Unmarshal(data, &devices); err != nil {
			return errors.New("invalid recovery block-device observation")
		}
		for _, device := range devices.BlockDevices {
			if device.Serial != "lindm-recovery-target" {
				continue
			}
			size, err := device.Size.Int64()
			if err != nil || size <= 0 || device.Name == "" || strings.ToLower(device.WWN) != "0x5000c5000000abcd" {
				return errors.New("recovery target identity differs from attached disk")
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("recovery target readiness: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
