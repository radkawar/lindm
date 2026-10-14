// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"strings"

	"lindm/internal/deploylab"
)

// completeDeployOwner is shared by the full lifecycle and the explicitly scoped
// first-run slice. The browser must verify actual password and UV passkey setup.
func completeDeployOwner(ctx context.Context, guest *guestVM, request *deploylab.BrowserRequest, browser func() error) error {
	code, err := serverGuestCommand(ctx, guest, "read protected setup code", "test \"$(stat -c %a /root/lindm-deploy-input/setup-code)\" = 600; cat /root/lindm-deploy-input/setup-code", nil)
	if err != nil {
		return err
	}
	request.SetupCode = strings.TrimSpace(string(code))
	clear(code)
	defer func() { request.SetupCode = "" }()
	if err := browser(); err != nil {
		return err
	}
	_, err = serverGuestCommand(ctx, guest, "remove spent setup code", "rm -- /root/lindm-deploy-input/setup-code", nil)
	return err
}
