package labhost

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
)

// Status is a bounded, observational snapshot; only Acquire reserves capacity.
// Guests includes pre-scheduler QEMU processes, which are visible but unleased.
type Status struct {
	Name         string `json:"name"`
	Reachable    bool   `json:"reachable"`
	Architecture string `json:"architecture"`
	KVM          bool   `json:"kvm"`
	ActiveLeases uint32 `json:"active_leases"`
	Guests       uint32 `json:"guests"`
	Free         uint32 `json:"free"`
	Error        string `json:"error,omitempty"`
}

func InspectHost(ctx context.Context, host *labv1.LabHost) Status {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	status := Status{Name: host.Name}
	if host.Transport == "local" {
		slots, err := OpenSlots(host)
		if err != nil {
			status.Error = err.Error()
			return status
		}
		status.ActiveLeases, err = slots.Count()
		if err != nil {
			status.Error = err.Error()
			return status
		}
		status.Reachable = true
		cmd := exec.CommandContext(ctx, "uname", "-m")
		data, e := cmd.Output()
		if e == nil {
			status.Architecture = strings.TrimSpace(string(data))
		}
		kvm, e := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
		if e == nil {
			status.KVM = kvm.Close() == nil
		}
		entries, _ := filepath.Glob("/proc/[0-9]*/comm")
		for _, p := range entries {
			data, e := os.ReadFile(p)
			if e == nil && strings.HasPrefix(string(data), "qemu-system-") {
				status.Guests++
			}
		}
	} else {
		work := remoteShellPath(host.WorkDirectory)
		script := `set -eu
work=` + work + `
active=0
for slot in "$work"/.leases/` + QuoteShell(host.Name) + `/slot-*.lock; do
 if test -e "$slot"; then
   test -f "$slot" && test ! -L "$slot" || exit 1
   if ! flock -n "$slot" true; then active=$((active+1)); fi
 fi
done
kvm=0
if (exec 9<>/dev/kvm) 2>/dev/null; then kvm=1; fi
guests=0
for path in /proc/[0-9]*/comm; do
 if read -r command 2>/dev/null < "$path"; then
  case "$command" in qemu-system-*) guests=$((guests+1));; esac
 fi
done
printf '%s %s %s %s\n' "$(uname -m)" "$kvm" "$active" "$guests"`
		output, err := runOutput(ctx, host.SshAlias, script)
		if err != nil {
			status.Error = err.Error()
			return status
		}
		var kvm int
		if _, err := fmt.Sscanf(output, "%s %d %d %d", &status.Architecture, &kvm, &status.ActiveLeases, &status.Guests); err != nil {
			status.Error = err.Error()
			return status
		}
		status.Reachable = true
		status.KVM = kvm == 1
	}
	if status.ActiveLeases < host.MaxGuests {
		status.Free = host.MaxGuests - status.ActiveLeases
	}
	return status
}
