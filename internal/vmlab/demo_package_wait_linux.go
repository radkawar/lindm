//go:build linux

package vmlab

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// demoPackageHolderBudget bounds waiting for a vendor package run already in
// progress on a persistent organization device. A golden booted long after it
// was built runs its missed persistent apt-daily-upgrade timer at once: a
// first-boot unattended security upgrade. The organization's own OS-update
// policy manages those units, so the demo waits for that run instead of
// stopping or masking it. Disposable lanes keep their own bounded wait.
const demoPackageHolderBudget = 30 * time.Minute

// demoPackageHolderPoll is the interval between holder observations.
const demoPackageHolderPoll = 15 * time.Second

// demoPackageHolderProbe prints one line naming the current package-manager
// holder: a running (oneshot "activating") vendor periodic apt unit, else a
// process holding a dpkg lock, else "none". It reads systemd and /proc/locks
// only and changes nothing.
const demoPackageHolderProbe = `for unit in apt-daily-upgrade.service apt-daily.service; do
state=$(systemctl show -p ActiveState --value "$unit" 2>/dev/null || true)
pid=$(systemctl show -p MainPID --value "$unit" 2>/dev/null || true)
if [ "$state" = activating ] && [ -n "$pid" ] && [ "$pid" != 0 ]; then
echo "unit $unit $pid $(cat /proc/$pid/comm 2>/dev/null || echo unknown)"; exit 0
fi
done
for lock in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock; do
pid=$(lslocks -n -r -o PID,PATH 2>/dev/null | awk -v p="$lock" '$2 == p {print $1; exit}')
if [ -n "$pid" ]; then
echo "lock $lock $pid $(cat /proc/$pid/comm 2>/dev/null || echo unknown)"; exit 0
fi
done
echo none
`

// demoPackageHolder is a parsed probe line; an empty Kind means no holder.
type demoPackageHolder struct {
	Kind, Name, Comm string
	PID              int
}

func (h demoPackageHolder) String() string {
	return fmt.Sprintf("%s %s (pid %d %s)", h.Kind, h.Name, h.PID, h.Comm)
}

func parseDemoPackageHolder(line string) (demoPackageHolder, error) {
	fields := strings.Fields(line)
	if len(fields) == 1 && fields[0] == "none" {
		return demoPackageHolder{}, nil
	}
	if len(fields) != 4 || (fields[0] != "unit" && fields[0] != "lock") {
		return demoPackageHolder{}, fmt.Errorf("unexpected package holder probe output %q", line)
	}
	pid, err := strconv.Atoi(fields[2])
	if err != nil || pid <= 0 {
		return demoPackageHolder{}, fmt.Errorf("unexpected package holder pid %q", fields[2])
	}
	return demoPackageHolder{Kind: fields[0], Name: fields[1], PID: pid, Comm: fields[3]}, nil
}

// waitDemoPackageHolder returns once no vendor run holds the package manager.
// It reports each changed holder and its elapsed wait on progress, and fails
// naming the holder when the budget expires; the native install that follows
// still waits on dpkg's own lock with DPkg::Lock::Timeout.
func waitDemoPackageHolder(ctx context.Context, vm *guestVM, hostname string, progress io.Writer) error {
	started := time.Now()
	deadline := started.Add(demoPackageHolderBudget)
	var last demoPackageHolder
	for {
		output, err := vm.run(ctx, "sudo -n sh -eu", strings.NewReader(demoPackageHolderProbe), 4<<10, time.Minute)
		if err != nil {
			return fmt.Errorf("observe package manager holder: %w", err)
		}
		holder, err := parseDemoPackageHolder(strings.TrimSpace(string(output)))
		if err != nil {
			return err
		}
		if holder.Kind == "" {
			if last.Kind != "" {
				_, err = fmt.Fprintf(progress, "demo device %s: package manager free after %s\n", hostname, time.Since(started).Round(time.Second))
			}
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("vendor package run %s still holds the package manager after %s", holder, demoPackageHolderBudget)
		}
		if holder != last {
			if _, err := fmt.Fprintf(progress, "demo device %s: waiting for vendor package run %s (%s elapsed, budget %s)\n", hostname, holder, time.Since(started).Round(time.Second), demoPackageHolderBudget); err != nil {
				return err
			}
			last = holder
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(demoPackageHolderPoll):
		}
	}
}
