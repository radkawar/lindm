// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"time"
)

// activateAssistanceHead uses QEMU 8.2's RFB SetDesktopSize path, which calls
// dpy_set_ui_info for the VNC endpoint's bound scanout. max_outputs=2 alone
// leaves enabled_output_bitmask=1 (hw/display/virtio-gpu-base.c, v8.2.2).
// No TCP listener, virtual compositor output or duplicate browser surface is
// involved. The caller must separately observe two active guest monitors.
// Source contracts:
// https://github.com/qemu/qemu/blob/v8.2.2/ui/vnc.c
// https://github.com/qemu/qemu/blob/v8.2.2/hw/display/virtio-gpu-base.c
func activateAssistanceHead(ctx context.Context, vm *guestVM) (_ net.Conn, err error) {
	if vm.hardware.DisplayHeads != 2 {
		return nil, errors.New("monitor assistance requires two configured virtio-gpu heads")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(vm.dir, "display-head1.sock"))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, conn.Close())
		}
	}()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := resizeAssistanceHead(conn); err != nil {
		return nil, fmt.Errorf("activate second virtio-gpu scanout over private RFB: %w", err)
	}
	return conn, nil
}

func resizeAssistanceHead(rw io.ReadWriter) error {
	var version [12]byte
	if _, err := io.ReadFull(rw, version[:]); err != nil {
		return err
	}
	if string(version[:]) != "RFB 003.008\n" {
		return errors.New("second-head endpoint requires RFB 3.8")
	}
	if _, err := rw.Write(version[:]); err != nil {
		return err
	}
	var count [1]byte
	if _, err := io.ReadFull(rw, count[:]); err != nil {
		return err
	}
	security := make([]byte, int(count[0]))
	if _, err := io.ReadFull(rw, security); err != nil {
		return err
	}
	none := false
	for _, kind := range security {
		none = none || kind == 1
	}
	if !none {
		return errors.New("private second-head endpoint did not offer local no-auth security")
	}
	if _, err := rw.Write([]byte{1}); err != nil {
		return err
	}
	var result [4]byte
	if _, err := io.ReadFull(rw, result[:]); err != nil {
		return err
	}
	if binary.BigEndian.Uint32(result[:]) != 0 {
		return errors.New("private second-head RFB security failed")
	}
	if _, err := rw.Write([]byte{1}); err != nil { // shared ClientInit
		return err
	}
	var init [24]byte
	if _, err := io.ReadFull(rw, init[:]); err != nil {
		return err
	}
	nameLength := binary.BigEndian.Uint32(init[20:])
	if nameLength > 4096 {
		return errors.New("unbounded RFB server name")
	}
	if _, err := io.CopyN(io.Discard, rw, int64(nameLength)); err != nil {
		return err
	}
	// SetEncodings: ExtendedDesktopSize (-308). SetDesktopSize: one screen,
	// ID 0, origin (0,0), 1024x768. This endpoint is bound to GPU head 1.
	packet := []byte{2, 0, 0, 1, 0xff, 0xff, 0xfe, 0xcc,
		251, 0, 4, 0, 3, 0, 1, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 3, 0, 0, 0, 0, 0}
	n, err := rw.Write(packet)
	if err == nil && n != len(packet) {
		err = io.ErrShortWrite
	}
	return err
}
