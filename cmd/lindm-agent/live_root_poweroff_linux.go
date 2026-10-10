//go:build linux

package main

import (
	"context"

	"lindm/internal/agent/actionprovider"
)

func liveRootPoweroff(_ context.Context, args []string) error {
	if len(args) != 0 {
		return actionprovider.ErrUnsupported
	}
	return actionprovider.RunLiveRootPoweroffHelper()
}
