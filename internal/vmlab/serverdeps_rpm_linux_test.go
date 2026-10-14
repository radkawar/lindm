// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import "testing"

// A failed native solver must expose its fixed stage without disclosing any
// unexpected credential, traceback, repository config or transport output.
func TestRPMDependencyGuestFailureClosedDiagnosticSet(t *testing.T) {
	const unknown = "native operation failed; unrecognized diagnostics suppressed"
	for _, test := range []struct {
		input, want string
	}{
		{"lab: serverdeps: native /usr/bin/python3.9 operation failed (native diagnostics suppressed): exit status 1\n", "native /usr/bin/python3.9 operation failed; diagnostics suppressed"},
		{"lab: serverdeps: native /usr/bin/rpmkeys operation failed (native diagnostics suppressed): exit status 1\n", "native /usr/bin/rpmkeys operation failed; diagnostics suppressed"},
		{"lab: serverdeps: RPM capture failed at native-repository-configuration (native diagnostics suppressed)\n", "native RPM capture stage native-repository-configuration failed; diagnostics suppressed"},
		{"lab: serverdeps: RPM capture failed at native-keyring-diagnostic-initialization (native diagnostics suppressed)\n", "native RPM capture stage native-keyring-diagnostic-initialization failed; diagnostics suppressed"},
		{"lab: serverdeps: RPM capture failed at native-keyring-database-init-permission-denied (native diagnostics suppressed)\n", "native RPM capture stage native-keyring-database-init-permission-denied failed; diagnostics suppressed"},
		{"lab: serverdeps: RPM capture failed at native-keyring-database-init-read-only (native diagnostics suppressed)\n", "native RPM capture stage native-keyring-database-init-read-only failed; diagnostics suppressed"},
		{"lab: serverdeps: RPM capture failed at native-keyring-database-init-locked (native diagnostics suppressed)\n", "native RPM capture stage native-keyring-database-init-locked failed; diagnostics suppressed"},
		{"lab: serverdeps: RPM capture failed at native-keyring-database-init-backend (native diagnostics suppressed)\n", "native RPM capture stage native-keyring-database-init-backend failed; diagnostics suppressed"},
		{"lab: serverdeps: RPM capture failed at native-keyring-database-init-timeout (native diagnostics suppressed)\n", "native RPM capture stage native-keyring-database-init-timeout failed; diagnostics suppressed"},
		{"lab: serverdeps: RPM capture failed at native-keyring-database-init-private-token-example (native diagnostics suppressed)\n", unknown},
		{"lab: serverdeps: RPM capture failed at native-keyring-database-init-permission-denied (native diagnostics suppressed)\nprivate-token-example\n", unknown},
		{"lab: serverdeps: RPM capture failed at private-token-example (native diagnostics suppressed)\n", unknown},
		{"lab: serverdeps: RPM capture failed at native-repository-configuration (native diagnostics suppressed)\nprivate-token-example\n", unknown},
		{"lab: private-token-example\n", unknown},
		{"lab: serverdeps: native /usr/bin/python3.9 operation failed (native diagnostics suppressed): exit status 1\nprivate-token-example\n", unknown},
		{"lab: serverdeps: native /customer/private/program operation failed (native diagnostics suppressed): exit status 1\n", unknown},
		{"", unknown},
	} {
		if got := rpmDependencyGuestFailure([]byte(test.input)); got != test.want {
			t.Fatalf("closed native diagnostic got %q, want %q", got, test.want)
		}
	}
}
