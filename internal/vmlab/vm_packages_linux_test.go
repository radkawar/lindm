// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"strings"
	"testing"
)

// The fixture apt-get update must not run the system's Update hooks: Pop!_OS
// 24.04's command-not-found hook raced the vendor updater and failed the step
// (pop2404-assistance-09). The isolation file is passed with -c, which apt-get
// reads after apt.conf.d, and clears every Update hook list.
func TestFixtureAPTClearsSystemUpdateHooks(t *testing.T) {
	for _, hook := range []string{"APT::Update::Pre-Invoke", "APT::Update::Post-Invoke", "APT::Update::Post-Invoke-Success"} {
		if !strings.Contains(aptIsolationConfig, "#clear "+hook+";\n") {
			t.Errorf("isolation config does not clear %s", hook)
		}
	}
	command := (&nativeGuestPackages{}).aptCommand("update")
	if !strings.HasPrefix(command, "apt-get -q -y -c "+nativeGuestDir+"/apt.conf ") {
		t.Fatalf("fixture apt-get does not read the isolation config: %s", command)
	}
}
