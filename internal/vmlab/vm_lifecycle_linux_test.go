package vmlab

import (
	"strings"
	"testing"
)

// Remote hosts cannot reach the shared development console, so manual
// trust/service lifecycle variants must be admissible against a private
// local-authority server while the exclusive combinations stay rejected.
func TestLifecycleControlPlaneSelection(t *testing.T) {
	const lindmd = "/run/lab/bin/lindmd"
	for _, tc := range []struct {
		name    string
		options VMLifecycleOptions
		want    string
	}{
		{"shared console", VMLifecycleOptions{ServiceExecution: true}, lifecycleSharedControlPlane},
		{"service execution with local authority", VMLifecycleOptions{ServiceExecution: true, LocalAuthority: true, LindmdBinary: lindmd}, lifecycleIsolatedLocalAuthority},
		{"execution trust with local authority", VMLifecycleOptions{ExecutionTrust: true, LocalAuthority: true, LindmdBinary: lindmd}, lifecycleIsolatedLocalAuthority},
		{"control-plane trust with keycloak", VMLifecycleOptions{ControlPlaneTrust: true, LindmdBinary: lindmd}, lifecycleIsolatedKeycloak},
		{"control-plane trust with local authority", VMLifecycleOptions{ControlPlaneTrust: true, LocalAuthority: true, LindmdBinary: lindmd}, lifecycleIsolatedLocalAuthority},
		{"control-plane trust without server", VMLifecycleOptions{ControlPlaneTrust: true}, ""},
		{"local authority without server", VMLifecycleOptions{ServiceExecution: true, LocalAuthority: true}, ""},
		{"server without private authority", VMLifecycleOptions{ServiceExecution: true, LindmdBinary: lindmd}, ""},
		{"control-plane trust with service execution", VMLifecycleOptions{ControlPlaneTrust: true, ServiceExecution: true, LocalAuthority: true, LindmdBinary: lindmd}, ""},
		{"control-plane trust with execution trust", VMLifecycleOptions{ControlPlaneTrust: true, ExecutionTrust: true, LindmdBinary: lindmd}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := lifecycleControlPlane(tc.options)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("lifecycleControlPlane() = %q, want rejection", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("lifecycleControlPlane() = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// The Omarchy executor resources lane failed preparation with only the
// executor's reason code; the native manager's diagnostic lives in the
// transient package helper unit's journal, which diagnostics must include.
func TestLifecycleFailureCollectsPackageHelperJournal(t *testing.T) {
	if !strings.Contains(lifecycleFailureCommand, "journalctl --no-pager -n 120 -u 'lindm-package-*'") {
		t.Fatalf("lifecycle diagnostics omit package helper units: %s", lifecycleFailureCommand)
	}
}
