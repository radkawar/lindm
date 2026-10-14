// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"lindm/internal/labhost"
	"lindm/internal/vmlab"
)

func bindOrganizationDeviceRoot(root, parent string, create bool) error {
	if _, err := labhost.DemoDirectory(filepath.Dir(filepath.Dir(root)), parent); err != nil {
		return err
	}
	path := filepath.Join(root, ".organization-demo")
	data, err := readDemoPrivate(path)
	if err == nil {
		if string(data) != parent+"\n" {
			return errors.New("device root belongs to a different organization demo")
		}
		return nil
	}
	if !create || !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, leaf := range []string{"desktop", "authority", "control-plane", "owner-access"} {
		if _, err := os.Lstat(filepath.Join(root, leaf)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("refusing to adopt existing non-organization device state")
		}
	}
	return publishDemoFile(path, []byte(parent+"\n"), 0600)
}

func destroyOrganizationDevice(ctx context.Context, repository, root, parent, redhatToken string, stdout io.Writer) (err error) {
	lock, err := lockAssistanceDemo(root)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := bindOrganizationDeviceRoot(root, parent, false); err != nil {
		return err
	}
	// The held root lock proves the device is stopped; remove its recorded
	// RHSM consumer by exact UUID before the VM and receipt are deleted.
	if err := vmlab.UnregisterDemoRedHat(ctx, root, redhatToken, stdout); err != nil {
		return err
	}
	return destroyLockedAssistanceDemo(ctx, repository, root, stdout)
}
