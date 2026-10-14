// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"errors"
	"os"

	"lindm/internal/agent/capabilitypolicy"
	"lindm/internal/agent/connectivityguard"
)

// serveConnectivityGuard is dispatched only by the fixed connectivity-guard
// command. It accepts no caller path, native text, URL or alternate state root.
func serveConnectivityGuard(ctx context.Context, args []string) error {
	if len(args) != 0 || os.Geteuid() != 0 {
		return errors.New("connectivity-guard requires root and accepts no arguments")
	}
	effective, err := capabilitypolicy.LoadEffectiveExecutorConfig(ctx)
	if err != nil {
		return err
	}
	return connectivityguard.Supervise(ctx, connectivityguard.StateDirectory, effective.Config.GetFirewallProvider())
}
