// SPDX-License-Identifier: Apache-2.0

//go:build linux

package osupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/platform"
	"lindm/internal/resource"
)

const (
	pacmanPath    = "/usr/bin/pacman"
	zypperPath    = "/usr/bin/zypper"
	rollingConfig = runtimeDir + "/pacman.conf"
	rollingRepos  = runtimeDir + "/repos"
	rollingCache  = resource.OSUpdateStateDir + "/zypp-cache"
	rollingReboot = runtimeDir + "/reboot-required"
)

// ValidateRollingPolicy rejects selection narrowing before configuration or any
// native refresh. Snapshot dates are calendar dates, not arbitrary path segments.
func ValidateRollingPolicy(kind resourcev1.OSUpdateBackend, desired *resourcev1.OSUpdateDesired) error {
	rolling := kind == resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN || kind == resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_ZYPPER
	pin := desired.GetRollingSnapshot()
	if !rolling {
		if pin != nil {
			return errors.New("rolling_snapshot_on_nonrolling_backend")
		}
		return nil
	}
	if pin == nil || desired.GetSelection() != resourcev1.UpdateSelection_UPDATE_SELECTION_ALL || desired.GetDeferralDays() != 0 {
		return errors.New("rolling_update_requires_pinned_whole_system_selection")
	}
	if _, err := time.Parse("2006-01-02", pin.GetDate()); err != nil {
		return errors.New("rolling_snapshot_date_invalid")
	}
	if kind == resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN {
		if pin.GetRepositoryUrl() != "" || len(pin.GetMetadataSha256()) != 0 {
			return errors.New("arch_requires_arch_linux_archive")
		}
	} else if pin.GetRepositoryUrl() == "" || len(pin.GetMetadataSha256()) != sha256.Size {
		return errors.New("tumbleweed_requires_signed_metadata_pin")
	}
	return nil
}

type rollingBackend struct {
	release *platform.Release
	pin     *resourcev1.RollingUpdateSnapshot
}

func (b *rollingBackend) kind() resourcev1.OSUpdateBackend {
	if b.release.Packages.Backend == platform.BackendPacman {
		return resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN
	}
	return resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_ZYPPER
}
func (b *rollingBackend) tool() agentv1.PatchRunTool {
	if b.kind() == resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN {
		return agentv1.PatchRunTool_PATCH_RUN_TOOL_PACMAN
	}
	return agentv1.PatchRunTool_PATCH_RUN_TOOL_ZYPPER
}
func (b *rollingBackend) missingTool(_ bool) (agentv1.PatchRunTool, string) {
	path, pkg := pacmanPath, "pacman"
	if b.kind() == resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_ZYPPER {
		path, pkg = zypperPath, "zypper"
	}
	if !executable(path) {
		return b.tool(), pkg
	}
	if b.kind() == resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN && !executable("/usr/bin/pacman-conf") {
		return b.tool(), pkg
	}
	return 0, ""
}
func (b *rollingBackend) configure(desired *resourcev1.OSUpdateDesired) error {
	if err := ValidateRollingPolicy(b.kind(), desired); err != nil {
		return err
	}
	b.pin = desired.GetRollingSnapshot()
	if err := prepareRuntimeDir(); err != nil {
		return err
	}
	if b.kind() == resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN {
		date, err := time.Parse("2006-01-02", b.pin.GetDate())
		if err != nil {
			return err
		}
		var config strings.Builder
		config.WriteString("[options]\nArchitecture = auto\nSigLevel = Required DatabaseOptional TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n")
		for _, repo := range b.release.RollingUpdate.Repositories {
			fmt.Fprintf(&config, "[%s]\nServer = %s%s/$repo/os/$arch\n", repo, b.release.RollingUpdate.ArchiveURL, date.Format("2006/01/02"))
		}
		return writeAtomic(rollingConfig, []byte(config.String()))
	}
	if err := checkPrivateDir(resource.OSUpdateStateDir); err != nil {
		return err
	}
	for _, dir := range []string{rollingRepos, rollingCache} {
		if err := unix.Mkdir(dir, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
			return err
		}
		if err := checkPrivateDir(dir); err != nil {
			return err
		}
	}
	// An isolated repository directory excludes live mirrors and third-party
	// repositories. Native trust is retained; keys are never auto-imported.
	config := "[lindm-snapshot]\nname=lindm pinned snapshot\nenabled=1\nautorefresh=0\ngpgcheck=1\nrepo_gpgcheck=1\npkg_gpgcheck=1\nbaseurl=" + b.pin.GetRepositoryUrl() + "\n"
	return writeAtomic(rollingRepos+"/snapshot.repo", []byte(config))
}
func (b *rollingBackend) command(ctx context.Context, s step, phase agentv1.PatchRunPhase, args ...string) (commandResult, error) {
	path := pacmanPath
	prefix := []string{"--config", rollingConfig, "--noconfirm"}
	if b.kind() == resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_ZYPPER {
		path = zypperPath
		prefix = []string{"--non-interactive", "--reposd-dir", rollingRepos, "--servicesd-dir", rollingRepos, "--cache-dir", rollingCache, "--no-refresh"}
	}
	result, err := runCommand(ctx, s, path, append(prefix, args...)...)
	if err != nil {
		return result, failure("rolling_native_step_failed", b.tool(), phase, result)
	}
	return result, nil
}
func (b *rollingBackend) refresh(ctx context.Context) error {
	if b.pin == nil {
		return errors.New("rolling_snapshot_missing")
	}
	if err := b.checkNativeHolds(ctx); err != nil {
		return err
	}
	args := []string{"-Syy"}
	if b.kind() == resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_ZYPPER {
		args = []string{"refresh", "--force"}
	}
	if _, err := b.command(ctx, step{timeout: refreshTimeout}, agentv1.PatchRunPhase_PATCH_RUN_PHASE_REFRESH, args...); err != nil {
		return err
	}
	return b.verifyMetadata()
}
func (b *rollingBackend) verifyMetadata() error {
	if b.pin == nil {
		return errors.New("rolling_snapshot_missing")
	}
	if b.kind() != resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_ZYPPER {
		return nil
	}
	data, err := readProtected(rollingCache+"/raw/lindm-snapshot/repodata/repomd.xml", 4<<20)
	if err != nil {
		return err
	}
	return verifyRollingMetadata(data, b.pin, b.release.RollingUpdate.SnapshotCPEPrefix)
}

func verifyRollingMetadata(data []byte, pin *resourcev1.RollingUpdateSnapshot, cpePrefix string) error {
	digest := sha256.Sum256(data)
	if !bytes.Equal(digest[:], pin.GetMetadataSha256()) {
		return errors.New("rolling_repository_metadata_changed")
	}
	var metadata struct {
		Distros []struct {
			CPE string `xml:"cpeid,attr"`
		} `xml:"tags>distro"`
	}
	if err := xml.Unmarshal(data, &metadata); err != nil {
		return err
	}
	date := strings.ReplaceAll(pin.GetDate(), "-", "")
	if len(metadata.Distros) != 1 || metadata.Distros[0].CPE != cpePrefix+date {
		return errors.New("rolling_repository_snapshot_mismatch")
	}
	return nil
}
func (b *rollingBackend) pending(ctx context.Context) ([]pendingPackage, error) {
	if err := b.verifyMetadata(); err != nil {
		return nil, err
	}
	args := []string{"-Suup", "--print-format", "%n\t%a\t%v"}
	if b.kind() == resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_ZYPPER {
		args = []string{"--xmlout", "dist-upgrade", "--dry-run", "--no-allow-vendor-change"}
	}
	result, err := b.command(ctx, step{timeout: listTimeout, stdoutLimit: listOutputLimit}, agentv1.PatchRunPhase_PATCH_RUN_PHASE_LIST, args...)
	if err != nil {
		return nil, err
	}
	return parseRollingPending(result.stdout, b.kind() == resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN)
}
func parseRollingPending(data []byte, pacman bool) ([]pendingPackage, error) {
	var pending []pendingPackage
	if pacman {
		err := scanLines(data, func(line string) error {
			if line == "" {
				return nil
			}
			parts := strings.Split(line, "\t")
			if len(parts) != 3 || parts[2] == "" {
				return errNativeOutput
			}
			key := packageKey{name: parts[0], arch: parts[1]}
			if !validPackageKey(key) {
				return errNativeOutput
			}
			pending = append(pending, pendingPackage{key: key})
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		var stream struct {
			XMLName xml.Name `xml:"stream"`
			Summary *struct {
				Count  *uint32 `xml:"packages-to-change,attr"`
				Groups []struct {
					XMLName xml.Name
					Items   []struct {
						Type string `xml:"type,attr"`
						Name string `xml:"name,attr"`
						Arch string `xml:"arch,attr"`
					} `xml:"solvable"`
				} `xml:",any"`
			} `xml:"install-summary"`
		}
		if err := xml.Unmarshal(data, &stream); err != nil || stream.Summary == nil || stream.Summary.Count == nil {
			return nil, errNativeOutput
		}
		for _, group := range stream.Summary.Groups {
			if !strings.HasPrefix(group.XMLName.Local, "to-") {
				continue
			}
			for _, item := range group.Items {
				if item.Type != "package" {
					continue
				}
				key := packageKey{name: item.Name, arch: item.Arch}
				if !validPackageKey(key) {
					return nil, errNativeOutput
				}
				pending = append(pending, pendingPackage{key: key})
			}
		}
		// Architecture/vendor change groups may repeat an upgraded package.
		pending = dedupePending(pending)
		if uint32(len(pending)) != *stream.Summary.Count {
			return nil, errNativeOutput
		}
	}
	if len(pending) > maxInstalledPackages {
		return nil, errNativeOutput
	}
	return dedupePending(pending), nil
}
func (b *rollingBackend) installed(ctx context.Context) (map[packageKey]string, error) {
	path, args := "/usr/bin/rpm", []string{"-qa", "--qf", "%{NAME}\t%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n"}
	if b.kind() == resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN {
		path, args = pacmanPath, []string{"-Q"}
	}
	result, err := runCommand(ctx, step{timeout: snapshotTimeout, stdoutLimit: snapshotOutput}, path, args...)
	if err != nil {
		return nil, failure(reasonListFailed, b.tool(), agentv1.PatchRunPhase_PATCH_RUN_PHASE_LIST, result)
	}
	if b.kind() != resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN {
		return parseInstalled(result.stdout, false)
	}
	installed := make(map[packageKey]string)
	err = scanLines(result.stdout, func(line string) error {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(installed) >= maxInstalledPackages {
			return errNativeOutput
		}
		key := packageKey{name: fields[0], arch: "native"}
		if !validPackageKey(key) || installed[key] != "" {
			return errNativeOutput
		}
		installed[key] = fields[1]
		return nil
	})
	if len(installed) == 0 {
		return nil, errNativeOutput
	}
	return installed, err
}
func (b *rollingBackend) install(ctx context.Context, request installRequest) error {
	if request.selection != resourcev1.UpdateSelection_UPDATE_SELECTION_ALL || len(request.deferred) != 0 {
		return errors.New("rolling_partial_upgrade_refused")
	}
	if err := b.verifyMetadata(); err != nil {
		return err
	}
	if err := b.checkNativeHolds(ctx); err != nil {
		return err
	}
	args := []string{"-Syyuu"}
	if b.kind() == resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_ZYPPER {
		args = []string{"dist-upgrade", "--no-allow-vendor-change"}
	}
	_, err := b.command(ctx, step{timeout: installTimeout, mutating: true}, agentv1.PatchRunPhase_PATCH_RUN_PHASE_INSTALL, args...)
	return err
}
func (b *rollingBackend) rebootRequired(_ context.Context) (bool, error) {
	_, err := readProtected(rollingReboot, 128)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}
func (b *rollingBackend) metadataPatterns() []string {
	if b.kind() == resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN {
		return []string{"/var/lib/pacman/sync/*.db"}
	}
	return []string{rollingCache + "/raw/lindm-snapshot/repodata/repomd.xml"}
}

// rollingSnapshot only advertises a pre-snapshot after querying actual Btrfs
// root and snapper's root configuration. It never invents a rollback operation.
func rollingSnapshot(ctx context.Context, summary *agentv1.PatchRunSummary) error {
	summary.RollbackStatus = "unavailable"
	var stat unix.Statfs_t
	if err := unix.Statfs("/", &stat); err != nil {
		return err
	}
	if stat.Type != unix.BTRFS_SUPER_MAGIC || !executable("/usr/bin/snapper") {
		return nil
	}
	config, err := readProtected("/etc/snapper/configs/root", 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	values := parseOSRelease(config)
	if values["SUBVOLUME"] != "/" || values["FSTYPE"] != "btrfs" {
		return nil
	}
	// A root snapshot must retain the replay hold. If /etc is a separate
	// mount/subvolume, snapshot creation alone cannot establish that boundary.
	var root, marker unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, "/", unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &root); err != nil {
		return err
	}
	if err := unix.Statx(unix.AT_FDCWD, rollingRootHoldPath, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &marker); err != nil {
		return err
	}
	if root.Mask&unix.STATX_MNT_ID == 0 || marker.Mask&unix.STATX_MNT_ID == 0 || root.Mnt_id != marker.Mnt_id {
		return nil
	}
	// A query establishes that this is a usable native configuration, rather
	// than merely a file with plausible values.
	result, err := runCommand(ctx, step{timeout: oracleTimeout, stdoutLimit: oracleOutputMax}, "/usr/bin/snapper", "--config", "root", "list")
	if err != nil {
		return failure("snapper_configuration_unusable", agentv1.PatchRunTool_PATCH_RUN_TOOL_SNAPPER, agentv1.PatchRunPhase_PATCH_RUN_PHASE_VALIDATION, result)
	}
	result, err = runCommand(ctx, step{timeout: snapshotTimeout, stdoutLimit: oracleOutputMax, mutating: true}, "/usr/bin/snapper", "--config", "root", "create", "--type", "pre", "--print-number", "--description", "lindm whole-system update")
	if err != nil {
		return failure("snapper_snapshot_failed", agentv1.PatchRunTool_PATCH_RUN_TOOL_SNAPPER, agentv1.PatchRunPhase_PATCH_RUN_PHASE_INSTALL, result)
	}
	number, err := strconv.ParseUint(strings.TrimSpace(string(result.stdout)), 10, 64)
	if err != nil || number == 0 {
		return errNativeOutput
	}
	// Btrfs snapshots are nonrecursive. Equal mount IDs do not exclude a
	// nested subvolume, so establish the actual replay guard postcondition.
	saved := fmt.Sprintf("/.snapshots/%d/snapshot%s", number, rollingRootHoldPath)
	if err := verifySnapshotReplayMarker(rollingRootHoldPath, saved, 0); err != nil {
		return err
	}
	summary.RollbackStatus, summary.RollbackSnapshot = "snapper_pre_snapshot", number
	return nil
}
