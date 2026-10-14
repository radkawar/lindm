// SPDX-License-Identifier: Apache-2.0

//go:build linux

package osupdateprovider

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

const managedHeader = "Managed by lindm os.update.v1. Changes are drift."

// zoneinfoRoot is the host tzdata systemd resolves OnCalendar zones from.
const zoneinfoRoot = "/usr/share/zoneinfo"

// zoneInstalled requires the IANA zone as a regular tzdata file (or a link
// resolving inside the tzdata tree, as Debian ships aliases). The signed
// pattern already excludes '.', so no component can escape the root.
func zoneInstalled(root, zone string) error {
	if zone == "" || zone == "Local" || strings.ContainsAny(zone, ".\x00") || filepath.Clean(zone) != zone || filepath.IsAbs(zone) {
		return fmt.Errorf("%w: invalid time zone", ErrUnsupported)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("%w: host tzdata unavailable: %w", ErrUnsupported, err)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(root, zone))
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: time zone %s is not in the host tzdata", ErrUnsupported, zone)
	}
	if err != nil {
		return err
	}
	if !strings.HasPrefix(resolved, resolvedRoot+"/") {
		return fmt.Errorf("%w: time zone %s resolves outside the host tzdata", ErrUnsupported, zone)
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: time zone %s is not a tzdata file", ErrUnsupported, zone)
	}
	return nil
}

// weekdayNames are systemd's calendar weekday spellings, indexed by the
// Weekday enum number; TimersCalendar reports exactly these.
var weekdayNames = [...]string{"", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}

// calendarSpecs renders one OnCalendar specification per listed weekday in
// canonical weekday order, in the form systemd reports back. root is the host
// tzdata. A start time that does not exist locally (inside a DST gap) does not
// elapse that day: systemd skips it rather than moving it.
func calendarSpecs(root string, window *resourcev1.MaintenanceWindow) ([]string, error) {
	if window == nil || window.GetLocalStartMinute() > 1439 || len(window.GetWeekdays()) == 0 {
		return nil, ErrUnsupported
	}
	// An OnCalendar zone systemd cannot resolve never triggers; refuse it
	// before any effect.
	if err := zoneInstalled(root, window.GetTimeZone()); err != nil {
		return nil, err
	}
	days := make([]int, 0, len(window.GetWeekdays()))
	for _, day := range window.GetWeekdays() {
		if day <= 0 || int(day) >= len(weekdayNames) || slices.Contains(days, int(day)) {
			return nil, ErrUnsupported
		}
		days = append(days, int(day))
	}
	slices.Sort(days)
	hour, minute := window.GetLocalStartMinute()/60, window.GetLocalStartMinute()%60
	specs := make([]string, 0, len(days))
	for _, day := range days {
		specs = append(specs, fmt.Sprintf("%s *-*-* %02d:%02d:00 %s", weekdayNames[day], hour, minute, window.GetTimeZone()))
	}
	return specs, nil
}

func joinCalendar(specs []string) string { return strings.Join(specs, "; ") }

// sameCalendar compares calendar sets; systemd's property order is not part of
// the schedule.
func sameCalendar(a, b string) bool {
	left, right := strings.Split(a, "; "), strings.Split(b, "; ")
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}

// renderPolicy is the deterministic runner policy encoding.
func renderPolicy(desired *resourcev1.OSUpdateDesired) ([]byte, error) {
	policy := &agentv1.OSUpdateRunPolicy{FormatVersion: 1, Desired: proto.CloneOf(desired)}
	if err := validateMessage(policy); err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(policy)
}

// decodePolicy returns the effective desired policy of an owned policy file, or
// nil when the bytes are not exactly a valid deterministic runner policy.
func decodePolicy(content []byte) *resourcev1.OSUpdateDesired {
	policy := new(agentv1.OSUpdateRunPolicy)
	if err := proto.Unmarshal(content, policy); err != nil || validateMessage(policy) != nil {
		return nil
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(policy)
	if err != nil || !bytes.Equal(canonical, content) {
		return nil
	}
	return policy.GetDesired()
}

func renderTimer(specs []string) []byte {
	var b strings.Builder
	b.WriteString("# " + managedHeader + "\n[Unit]\nDescription=lindm OS update maintenance window\n[Timer]\n")
	for _, spec := range specs {
		b.WriteString("OnCalendar=" + spec + "\n")
	}
	b.WriteString("Persistent=true\nAccuracySec=1min\nUnit=" + resource.OSUpdateServiceUnit + "\n")
	return []byte(b.String())
}

func renderWants() []byte {
	return []byte("# " + managedHeader + "\n[Unit]\nWants=" + resource.OSUpdateTimerUnit + "\n")
}

func renderAPTPeriodic() []byte {
	return []byte("// " + managedHeader + "\nAPT::Periodic::Unattended-Upgrade \"0\";\n")
}

// renderDNF5Automatic is the complete /etc/dnf/automatic.conf, which
// `dnf5 automatic` always reads last. The lindm runner alone starts it inside
// the window; reboots are scheduled by the runner, never by dnf5.
func renderDNF5Automatic(selection resourcev1.UpdateSelection) ([]byte, error) {
	upgrade := ""
	switch selection {
	case resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY:
		upgrade = "security"
	case resourcev1.UpdateSelection_UPDATE_SELECTION_ALL:
		upgrade = "default"
	default:
		return nil, ErrUnsupported
	}
	return []byte("# " + managedHeader + "\n[commands]\nupgrade_type = " + upgrade + "\nrandom_sleep = 0\nnetwork_online_timeout = 60\ndownload_updates = yes\napply_updates = yes\nreboot = never\n\n[emitters]\nemit_via = stdio\n"), nil
}

// fileMode is the fixed native mode of each owned object: the runner policy is
// root-only, systemd, APT and DNF configuration are world-readable.
func fileMode(kind resourcev1.OSUpdateNativeFile) uint32 {
	if kind == resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_POLICY {
		return 0600
	}
	return 0644
}

// renderFiles returns the target bytes of every owned object for a backend.
func renderFiles(zoneinfo string, desired *resourcev1.OSUpdateDesired, backend resourcev1.OSUpdateBackend) (map[resourcev1.OSUpdateNativeFile][]byte, []string, error) {
	specs, err := calendarSpecs(zoneinfo, desired.GetMaintenance())
	if err != nil {
		return nil, nil, err
	}
	if window := desired.GetRebootPolicy().GetRebootWindow(); window != nil {
		if _, err := calendarSpecs(zoneinfo, window); err != nil {
			return nil, nil, err
		}
	}
	policy, err := renderPolicy(desired)
	if err != nil {
		return nil, nil, err
	}
	files := map[resourcev1.OSUpdateNativeFile][]byte{
		resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_POLICY:      policy,
		resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_TIMER:       renderTimer(specs),
		resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_TIMER_WANTS: renderWants(),
	}
	switch backend {
	case resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES:
		files[resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_APT_PERIODIC] = renderAPTPeriodic()
	case resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF5_AUTOMATIC:
		automatic, err := renderDNF5Automatic(desired.GetSelection())
		if err != nil {
			return nil, nil, err
		}
		files[resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_DNF5_AUTOMATIC] = automatic
	}
	return files, specs, nil
}

// ownedKinds lists the closed object set of a backend in canonical order:
// the shared policy and schedule plus the backend's native configuration.
func ownedKinds(backend resourcev1.OSUpdateBackend) []resourcev1.OSUpdateNativeFile {
	native := resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_UNSPECIFIED
	switch backend {
	case resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES:
		native = resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_APT_PERIODIC
	case resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF5_AUTOMATIC:
		native = resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_DNF5_AUTOMATIC
	}
	return slices.DeleteFunc(resource.OSUpdateNativeFiles(), func(kind resourcev1.OSUpdateNativeFile) bool {
		return (kind == resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_APT_PERIODIC || kind == resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_DNF5_AUTOMATIC) && kind != native
	})
}

// nativeConfigurationKind is the backend's native-configuration object, or
// UNSPECIFIED when the backend has none (DNF4 receives its configuration from
// the runner's per-run file).
func nativeConfigurationKind(backend resourcev1.OSUpdateBackend) resourcev1.OSUpdateNativeFile {
	kinds := ownedKinds(backend)
	if len(kinds) == 4 {
		return kinds[3]
	}
	return resourcev1.OSUpdateNativeFile_OS_UPDATE_NATIVE_FILE_UNSPECIFIED
}
