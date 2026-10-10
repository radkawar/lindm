//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// saveInspectComparisonFailure retains the independent counterexample only with
// explicit diagnostics consent. Numeric CPU topology sources explain util-linux
// logical IDs versus kernel physical IDs without inventing a passing comparison.
func saveInspectComparisonFailure(ctx context.Context, vm *guestVM, directory string, before, after, actual *inventoryv1.NativeDetails, failure error) error {
	if directory == "" {
		return failure
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	data := make(map[string]json.RawMessage)
	for name, details := range map[string]*inventoryv1.NativeDetails{"native_before": before, "native_after": after, "agent": actual} {
		encoded, err := protojson.Marshal(details)
		if err != nil {
			return errors.Join(failure, err)
		}
		data[name] = encoded
	}
	result, probeErr := vm.runResult(ctx, `printf '== lscpu logical IDs ==\n'; lscpu --parse=CPU,SOCKET,CORE --all; printf '== lscpu physical IDs ==\n'; lscpu --physical --parse=CPU,SOCKET,CORE --all; printf '== kernel topology ==\n'; for cpu in /sys/devices/system/cpu/cpu[0-9]*; do printf '%s\n' "$cpu"; for field in physical_package_id die_id cluster_id core_id core_cpus_list thread_siblings_list; do if test -r "$cpu/topology/$field"; then printf '%s=' "$field"; cat "$cpu/topology/$field"; fi; done; done`, nil, 64<<10, 15*time.Second)
	probe, err := json.Marshal(map[string]any{"stdout": string(result.Stdout), "stderr": string(result.Stderr), "exit_code": result.ExitCode})
	if err != nil {
		return errors.Join(failure, err)
	}
	data["cpu_topology"] = probe
	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return errors.Join(failure, err)
	}
	path, saveErr := saveGuestDiagnostics(directory, encoded)
	return errors.Join(failure, probeErr, saveErr, fmt.Errorf("private native comparison diagnostics saved to %q", path))
}
