// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"lindm/internal/agent/capabilitypolicy"
	"lindm/internal/agent/firewallprovider"
	"lindm/internal/agent/statefs"
)

func serveFirewallRestore(ctx context.Context, args []string) (resultErr error) {
	if os.Geteuid() != 0 || len(args) != 0 {
		return errors.New("firewall restoration requires root and no arguments")
	}
	effective, err := capabilitypolicy.LoadEffectiveExecutorConfig(ctx)
	if err != nil {
		return err
	}
	firewall := effective.Config.GetFirewallProvider()
	if firewall == nil {
		// Packages install boot ordering before root provisioning opts into policy.
		// Missing configuration is harmless only when no owned policy exists.
		fd, err := statefs.OpenDirectory(firewallprovider.StateDirectory)
		if err != nil {
			return err
		}
		directory := os.NewFile(uintptr(fd), "firewall-state")
		defer func() { resultErr = errors.Join(resultErr, directory.Close()) }()
		entries, err := directory.ReadDir(1)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if len(entries) != 0 {
			return errors.New("owned firewall state requires its approved root configuration")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return firewallprovider.ReplayNative(ctx, firewall)
}
