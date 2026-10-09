package vmlab

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"lindm/internal/agent/statefs"
)

// InstallProjectionEvidence describes an isolated fixture, not host service
// management, executor authorization, crash recovery or platform certification.
// Native output is diagnostic only; symlink observations establish the results.
type InstallProjectionEvidence struct {
	NativeVersion                string                  `json:"native_version"`
	FixtureUID                   int                     `json:"fixture_uid"`
	FilesystemType               string                  `json:"filesystem_type"`
	Before                       []InstallProjectionLink `json:"before"`
	AfterEnable                  []InstallProjectionLink `json:"after_enable"`
	AfterDisable                 []InstallProjectionLink `json:"after_disable"`
	AfterReenable                []InstallProjectionLink `json:"after_reenable"`
	DisableRemovedBaselineAlias  bool                    `json:"disable_removed_baseline_alias"`
	DisableRemovedEmptyParent    bool                    `json:"disable_removed_empty_parent"`
	CustodySurvivedDisable       bool                    `json:"custody_survived_disable"`
	FreshProcessVerifiedAnchor   bool                    `json:"fresh_process_verified_anchor"`
	CapturedReplacementRestored  bool                    `json:"captured_replacement_restored"`
	ConflictingReplacementsKept  bool                    `json:"conflicting_replacements_kept"`
	CapturedRegularFilePreserved bool                    `json:"captured_regular_file_preserved"`
}

type InstallProjectionLink struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

const (
	projectionPrimary       = "projection-primary.service"
	projectionAlias         = "projection-preexisting.service"
	projectionExternalAlias = "projection-external.service"
	projectionCustody       = ".lindm-ownership"
	projectionInstall       = "multi-user.target.wants/" + projectionPrimary
)

// CheckInstallProjection uses fixed native arguments and fixture-only paths.
// It deliberately does not use --dry-run: native enable may ignore that flag.
func CheckInstallProjection(ctx context.Context, workDir string) (_ *InstallProjectionEvidence, resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if workDir == "" {
		workDir = os.TempDir()
	}
	parent, err := filepath.Abs(workDir)
	if err != nil {
		return nil, err
	}
	// Validate before creating anything: cleanup through rejected ancestry
	// could otherwise remove a directory swapped into the fixture's name.
	parentFD, err := statefs.OpenTemporaryParent(parent)
	if err != nil {
		return nil, fmt.Errorf("native projection work-parent boundary: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(parentFD)) }()
	root, err := os.MkdirTemp(parent, "lindm-install-projection-")
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(root)) }()
	// Native --root still resolves ordinary paths. Pin a private fixture whose
	// ancestry cannot be renamed by another unprivileged UID before invoking it.
	directoryFD, err := statefs.OpenDirectory(root)
	if err != nil {
		return nil, fmt.Errorf("native projection fixture boundary: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(directoryFD)) }()
	binary, err := exec.LookPath("systemctl")
	if err != nil {
		return nil, err
	}
	inspector, err := exec.LookPath("stat")
	if err != nil {
		return nil, err
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(directoryFD, &filesystem); err != nil {
		return nil, err
	}
	version, err := projectionCommand(ctx, binary, "--version")
	if err != nil {
		return nil, err
	}
	evidence := &InstallProjectionEvidence{NativeVersion: strings.TrimSpace(string(version)), FixtureUID: os.Geteuid(), FilesystemType: strconv.FormatInt(int64(filesystem.Type), 16)}
	units := filepath.Join(root, "etc/systemd/system")
	if err := seedInstallProjection(root); err != nil {
		return nil, err
	}
	evidence.Before, err = observeProjectionLinks(units)
	if err != nil {
		return nil, err
	}
	if _, err := projectionCommand(ctx, binary, "--system", "--root="+root, "--no-reload", "--no-ask-password", "--no-pager", "enable", "--", projectionPrimary); err != nil {
		return nil, err
	}
	evidence.AfterEnable, err = observeProjectionLinks(units)
	if err != nil {
		return nil, err
	}
	expected := []InstallProjectionLink{
		{Path: projectionInstall, Target: "/usr/lib/systemd/system/" + projectionPrimary},
		{Path: "multi-user.target.wants/projection-related@worker.service", Target: "/usr/lib/systemd/system/projection-related@.service"},
		{Path: "projection-created.service", Target: "/usr/lib/systemd/system/" + projectionPrimary},
		{Path: projectionExternalAlias, Target: "/usr/lib/systemd/system/" + projectionPrimary},
		{Path: "projection-extra.target.wants/" + projectionPrimary, Target: "/usr/lib/systemd/system/" + projectionPrimary},
		{Path: projectionAlias, Target: "/usr/lib/systemd/system/" + projectionPrimary},
	}
	if !slices.Equal(evidence.AfterEnable, expected) {
		return nil, fmt.Errorf("native enable did not materialize the fixture's aliases, Also instance and install drop-in: %v", evidence.AfterEnable)
	}
	custody := filepath.Join(units, projectionCustody)
	if err := os.Mkdir(custody, 0700); err != nil {
		return nil, err
	}
	anchor := filepath.Join(custody, "anchor-identity")
	if err := os.Link(filepath.Join(units, projectionInstall), anchor); err != nil {
		return nil, err
	}
	before, err := projectionIdentity(anchor)
	if err != nil {
		return nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFLNK {
		return nil, errors.New("custody anchor is not a hardlink to the symlink itself")
	}
	if err := syncProjectionDirectory(custody); err != nil {
		return nil, err
	}
	if _, err := projectionCommand(ctx, binary, "--system", "--root="+root, "--no-reload", "--no-ask-password", "--no-pager", "disable", "--", projectionPrimary); err != nil {
		return nil, err
	}
	evidence.AfterDisable, err = observeProjectionLinks(units)
	if err != nil {
		return nil, err
	}
	for _, link := range evidence.AfterDisable {
		if (link.Path != projectionAlias && link.Path != projectionExternalAlias) || link.Target != "/usr/lib/systemd/system/"+projectionPrimary {
			return nil, fmt.Errorf("native disable retained an unexpected fixture install link: %s", link.Path)
		}
	}
	evidence.DisableRemovedBaselineAlias = !slices.Contains(evidence.AfterDisable, InstallProjectionLink{Path: projectionAlias, Target: "/usr/lib/systemd/system/" + projectionPrimary})
	_, err = os.Lstat(filepath.Dir(filepath.Join(units, projectionInstall)))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	evidence.DisableRemovedEmptyParent = errors.Is(err, os.ErrNotExist)
	after, err := projectionIdentity(anchor)
	if err != nil {
		return nil, err
	}
	if !sameProjectionIdentity(before, after) {
		return nil, errors.New("native disable replaced or removed private non-unit custody")
	}
	evidence.CustodySurvivedDisable = true
	// A new process receives no anchor descriptor. GNU stat's explicit numeric
	// format verifies path-based custody without parsing human-readable logs.
	observed, err := projectionCommand(ctx, inspector, "--format=%d:%i", "--", anchor)
	if err != nil {
		return nil, err
	}
	if string(observed) != fmt.Sprintf("%d:%d\n", before.Dev, before.Ino) {
		return nil, errors.New("fresh native process did not observe the retained anchor inode")
	}
	evidence.FreshProcessVerifiedAnchor = true
	// Compare a counterfactual disable/enable cycle with direct enable. It must
	// recover the already-present declared alias and Also link, but not adopt
	// an unrelated pre-existing alias as part of the declared install footprint.
	declared := slices.DeleteFunc(expected, func(link InstallProjectionLink) bool { return link.Path == projectionExternalAlias })
	if _, err := projectionCommand(ctx, binary, "--system", "--root="+root, "--no-reload", "--no-ask-password", "--no-pager", "enable", "--", projectionPrimary); err != nil {
		return nil, err
	}
	evidence.AfterReenable, err = observeProjectionLinks(units)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(evidence.AfterReenable, declared) {
		return nil, fmt.Errorf("counterfactual enable did not distinguish declared and external install links: %v", evidence.AfterReenable)
	}
	if _, err := projectionCommand(ctx, binary, "--system", "--root="+root, "--no-reload", "--no-ask-password", "--no-pager", "disable", "--", projectionPrimary); err != nil {
		return nil, err
	}
	if err := checkProjectionCaptureRaces(units, anchor, before); err != nil {
		return nil, err
	}
	evidence.CapturedReplacementRestored = true
	evidence.ConflictingReplacementsKept = true
	evidence.CapturedRegularFilePreserved = true
	return evidence, nil
}

func seedInstallProjection(root string) error {
	vendor := filepath.Join(root, "usr/lib/systemd/system")
	units := filepath.Join(root, "etc/systemd/system")
	for _, path := range []string{vendor, units, filepath.Join(vendor, projectionPrimary+".d")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			return err
		}
	}
	files := map[string]string{
		projectionPrimary:                        "[Unit]\nDescription=Isolated native install projection\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\nAlias=" + projectionAlias + " projection-created.service\nAlso=projection-related@worker.service\n",
		"projection-related@.service":            "[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n",
		"multi-user.target":                      "[Unit]\nDescription=Isolated fixture target\n",
		"projection-extra.target":                "[Unit]\nDescription=Isolated drop-in target\n",
		projectionPrimary + ".d/10-install.conf": "[Install]\nWantedBy=projection-extra.target\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(vendor, name), []byte(content), 0600); err != nil {
			return err
		}
	}
	for _, link := range []InstallProjectionLink{
		{Path: projectionAlias, Target: "/usr/lib/systemd/system/" + projectionPrimary},
		{Path: projectionExternalAlias, Target: "/usr/lib/systemd/system/" + projectionPrimary},
		{Path: "multi-user.target.wants/projection-related@worker.service", Target: "/usr/lib/systemd/system/projection-related@.service"},
	} {
		path := filepath.Join(units, link.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		if err := os.Symlink(link.Target, path); err != nil {
			return err
		}
	}
	return nil
}

func observeProjectionLinks(units string) ([]InstallProjectionLink, error) {
	links := make([]InstallProjectionLink, 0)
	err := filepath.WalkDir(units, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && entry.Name() == projectionCustody {
			return filepath.SkipDir
		}
		if entry.Type()&os.ModeSymlink == 0 {
			return nil
		}
		relative, err := filepath.Rel(units, path)
		if err != nil {
			return err
		}
		target, err := os.Readlink(path)
		if err != nil {
			return err
		}
		links = append(links, InstallProjectionLink{Path: relative, Target: target})
		return nil
	})
	slices.SortFunc(links, func(a, b InstallProjectionLink) int { return strings.Compare(a.Path, b.Path) })
	return links, err
}

func projectionCommand(ctx context.Context, binary string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output := &limitedOutput{limit: 64 << 10}
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = []string{"LC_ALL=C", "SYSTEMCTL_SKIP_SYSV=1", "SYSTEMD_LOG_TARGET=console", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
	command.Stdout, command.Stderr = output, output
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("native projection fixture command %s: %w: %s", filepath.Base(binary), err, output.data)
	}
	return output.data, nil
}

func projectionIdentity(path string) (unix.Stat_t, error) {
	var identity unix.Stat_t
	err := unix.Lstat(path, &identity)
	return identity, err
}

func sameProjectionIdentity(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode&unix.S_IFMT == b.Mode&unix.S_IFMT
}

func syncProjectionDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
