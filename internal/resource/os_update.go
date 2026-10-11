package resource

import resourcev1 "lindm/gen/lindm/resource/v1"

// Fixed native identities of the os.update.v1 resource. Profiles never select
// paths; the agent provider, claims and the runner share these constants.
const (
	OSUpdateTimerUnit     = "lindm-os-update.timer"
	OSUpdateServiceUnit   = "lindm-os-update.service"
	OSUpdateNowUnit       = "lindm-os-update-now.service"
	OSUpdateStatusUnit    = "lindm-os-update-status.service"
	OSUpdatePolicyPath    = "/etc/lindm/os-update/policy.binpb"
	OSUpdateTimerPath     = "/etc/systemd/system/" + OSUpdateTimerUnit
	OSUpdateWantsPath     = "/etc/systemd/system/timers.target.d/lindm-os-update.conf"
	OSUpdateAPTPeriodPath = "/etc/apt/apt.conf.d/99lindm-os-update"
	// OSUpdateDNF5AutomaticPath is the last file `dnf5 automatic` reads (it
	// accepts no configuration path argument); owned on DNF5 only.
	OSUpdateDNF5AutomaticPath = "/etc/dnf/automatic.conf"
	// Executor-written, runner-consumed patch-now request (0700 root dir, 0600 file).
	OSUpdatePatchNowDir         = "/run/lindm/os-update"
	OSUpdatePatchNowRequestPath = OSUpdatePatchNowDir + "/patch-now.binpb"
	// Runner-owned state (0700 root dir from the package's tmpfiles entry).
	OSUpdateStateDir     = "/var/lib/lindm/os-update"
	OSUpdateRunStatePath = OSUpdateStateDir + "/run.binpb"
	OSUpdateStatusPath   = OSUpdateStateDir + "/status.binpb"
	// flock serializing the run, patch-now and status units with the
	// os.update.v1 provider's native effects (the executor takes it without
	// waiting and refuses as busy). It shares the root-only 0700 runtime
	// directory with the patch-now request (never the world-writable
	// /run/lock).
	OSUpdateLockPath = OSUpdatePatchNowDir + "/run.lock"
)

// OSUpdateNativeFiles lists every owned object kind in canonical order.
func OSUpdateNativeFiles() []resourcev1.OSUpdateNativeFile {
	return []resourcev1.OSUpdateNativeFile{
		resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_POLICY,
		resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_TIMER,
		resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_TIMER_WANTS,
		resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_APT_PERIODIC,
		resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_DNF5_AUTOMATIC,
	}
}

// OSUpdateNativePath returns the fixed path of an owned object, or "".
func OSUpdateNativePath(kind resourcev1.OSUpdateNativeFile) string {
	switch kind {
	case resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_POLICY:
		return OSUpdatePolicyPath
	case resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_TIMER:
		return OSUpdateTimerPath
	case resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_TIMER_WANTS:
		return OSUpdateWantsPath
	case resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_APT_PERIODIC:
		return OSUpdateAPTPeriodPath
	case resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_DNF5_AUTOMATIC:
		return OSUpdateDNF5AutomaticPath
	default:
		return ""
	}
}
