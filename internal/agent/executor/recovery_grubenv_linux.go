//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"lindm/internal/agent/recoveryboot"
)

// grubEnvironment runs the registry's grub-editenv in a short-lived PID 1
// transient unit. The executor keeps PrivateDevices and never gains a block
// device: only this unit may open the filesystem device backing /boot, read-only
// unless GRUB keeps its environment in the btrfs bootloader area, and may
// write only the GRUB configuration directory.
func (s *Service) grubEnvironment(bootDirectory, configDirectory string) recoveryboot.GrubEnvRunner {
	return func(ctx context.Context, editenv string, args ...string) ([]byte, error) {
		if editenv != "/usr/bin/grub2-editenv" && editenv != "/usr/bin/grub-editenv" {
			return nil, errors.New("recovery grub-editenv path is not a registry tool")
		}
		if len(args) < 2 || args[0] != "-" || !slices.Contains([]string{"list", "set", "unset"}, args[1]) {
			return nil, errors.New("recovery grub-editenv operation is not allowed")
		}
		device, writable, err := recoveryboot.BootBlockDevice(bootDirectory)
		if err != nil {
			return nil, err
		}
		id, err := newID()
		if err != nil {
			return nil, err
		}
		open := s.rootInventorySystemd
		if open == nil {
			open = openSystemdPrivateUnit
		}
		call, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		units, err := open(call, "lindm-grubenv-"+id+".service")
		if err != nil {
			return nil, err
		}
		defer func() { _ = units.close() }()
		output, runErr := units.run(call, grubEnvironmentProperties(editenv, args, device, writable, bootDirectory+"/"+configDirectory))
		if runErr != nil {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), rootInventoryCleanupTimeout)
			stopErr := units.stop(cleanup)
			stop()
			return nil, fmt.Errorf("recovery grub-editenv %s: %w", args[1], errors.Join(runErr, stopErr))
		}
		return output, nil
	}
}

func grubEnvironmentProperties(editenv string, args []string, device string, writable bool, configDirectory string) []systemdProperty {
	property := newSystemdProperty
	access := "r"
	if writable {
		access = "rw"
	}
	return []systemdProperty{
		property("Description", "Lindm recovery GRUB environment"),
		property("Type", "exec"), property("User", "root"), property("Group", "root"),
		property("ExecStart", []systemdExec{{Path: editenv, Arguments: append([]string{editenv}, args...)}}),
		property("PrivateDevices", false), property("DevicePolicy", "closed"),
		property("DeviceAllow", []struct{ Path, Access string }{{device, access}}),
		property("CapabilityBoundingSet", uint64(0)), property("AmbientCapabilities", uint64(0)),
		property("NoNewPrivileges", true), property("ProtectSystem", "strict"), property("ProtectHome", "yes"),
		property("ReadWritePaths", []string{configDirectory}),
		property("PrivateTmp", true), property("PrivateNetwork", true),
		property("RestrictAddressFamilies", systemdList{AllowList: true, Values: []string{"AF_UNIX"}}),
		property("ProtectKernelTunables", true), property("ProtectKernelModules", true), property("ProtectKernelLogs", true),
		property("ProtectClock", true), property("ProtectHostname", true), property("ProtectControlGroups", true),
		property("RestrictNamespaces", uint64(0)), property("RestrictRealtime", true), property("RestrictSUIDSGID", true),
		property("LockPersonality", true), property("MemoryDenyWriteExecute", true),
		property("SystemCallArchitectures", []string{"native"}),
		property("SystemCallFilter", systemdList{AllowList: true, Values: []string{"@system-service"}}),
		property("InaccessiblePaths", []string{"-/etc/lindm", "-/var/lib/lindm", "-/run/lindm"}),
		property("UMask", uint32(0o077)), property("WorkingDirectory", "/"),
		property("RuntimeMaxUSec", uint64(20*time.Second/time.Microsecond)),
		property("TimeoutStartUSec", uint64(20*time.Second/time.Microsecond)),
		property("TimeoutStopUSec", uint64(500*time.Millisecond/time.Microsecond)),
		property("KillMode", "control-group"), property("SendSIGKILL", true),
		property("TasksMax", uint64(16)), property("MemoryMax", uint64(128<<20)),
		property("LimitCORE", uint64(0)), property("LimitCORESoft", uint64(0)),
		property("Environment", []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}),
		property("Restart", "no"), property("CollectMode", "inactive-or-failed"),
		property("StandardInput", "null"),
	}
}
