// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capabilitypolicy

import (
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// A derivative must receive its base pockets without implicitly trusting its
// own vendor archives, even when those archives ship in the OS's APT config.
func TestDeriveDerivativesApproveOnlyPinnedUbuntuSource(t *testing.T) {
	local := &agentv1.AgentConfig{}
	record := testRecord(true, capPackages, capFiles, capAccounts)
	base := derive(t, local, record, testHost(t, "ubuntu-24.04"))
	for _, key := range []string{"linuxmint-22.3", "pop-24.04"} {
		t.Run(key, func(t *testing.T) {
			effective := derive(t, local, record, testHost(t, key))
			for _, capability := range []agentv1.ManagementCapability{capPackages, capFiles, capAccounts} {
				wantStatus(t, effective, capability, statusEnabled, "")
			}
			if !proto.Equal(effective.Config.GetPackageProvider(), base.Config.GetPackageProvider()) {
				t.Fatalf("%s approves sources other than the pinned Ubuntu base: %v", key, effective.Config.GetPackageProvider())
			}
			if !proto.Equal(effective.Config.GetFileProvider(), base.Config.GetFileProvider()) || !proto.Equal(effective.Config.GetAccountProvider(), base.Config.GetAccountProvider()) {
				t.Fatalf("%s lost base file/account defaults", key)
			}
		})
	}
}
