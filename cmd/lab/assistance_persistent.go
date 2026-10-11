package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
	"lindm/internal/labhost"
	"lindm/internal/vmlab"
)

const assistanceDemoMarker = "lindm named assistance demo v1\n"

type assistanceDemoLockKey struct{}

func assistanceFlag(args []string, key string) bool {
	value := false
	for _, arg := range args {
		name, text, explicit := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if strings.HasPrefix(arg, "-") && name == key {
			parsed, err := strconv.ParseBool(text)
			value = !explicit || err == nil && parsed
		}
	}
	return value
}

func controllerDemoDirectory(name string) (string, error) {
	cfg, err := labhost.Load()
	if err != nil {
		return "", err
	}
	for _, host := range cfg.Hosts {
		if host.Transport == "local" {
			work, err := labhost.ResolveWorkDirectory(host)
			if err != nil {
				return "", err
			}
			return labhost.DemoDirectory(work, name)
		}
	}
	return "", errors.New("named assistance requires a configured local controller work directory")
}

func openAssistanceDemoRoot(root string) error {
	info, err := os.Lstat(root)
	if err == nil {
		if !info.IsDir() || info.Mode().Perm() != 0700 {
			return errors.New("demo root must be a private 0700 directory")
		}
		marker, err := os.ReadFile(filepath.Join(root, ".lindm-demo"))
		if err != nil {
			return err
		}
		if string(marker) != assistanceDemoMarker {
			return errors.New("refusing unowned demo directory")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(root), 0700); err != nil {
		return err
	}
	if err := os.Mkdir(root, 0700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, ".lindm-demo"), []byte(assistanceDemoMarker), 0600)
}

// namedAssistanceHost pins auto-selection to the first host. A busy host queues
// on resume; it never silently creates another machine under the same name.
func namedAssistanceHost(args []string, requested string) (string, error) {
	name := labhost.FlagValue(args, "name")
	if len(args) < 2 || args[1] != "assistance" || name == "" {
		return requested, nil
	}
	if !vmHolds(args) {
		return "", errors.New("vm assistance -name requires -hold")
	}
	if assistanceFlag(args, "colocated") {
		return "", errors.New("named demos use the controller-hosted topology; -colocated is for isolated lanes")
	}
	root, err := controllerDemoDirectory(name)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(filepath.Join(root, "host"))
	if errors.Is(err, os.ErrNotExist) {
		return requested, nil
	}
	if err != nil {
		return "", err
	}
	host := strings.TrimSpace(string(data))
	if host == "" || requested != "" && requested != host {
		return "", errors.New("named demo is bound to a different lab host")
	}
	return host, nil
}

func bindAssistanceHost(args []string, host *labv1.LabHost) error {
	name := labhost.FlagValue(args, "name")
	if len(args) < 2 || args[1] != "assistance" || name == "" {
		return nil
	}
	root, err := controllerDemoDirectory(name)
	if err != nil {
		return err
	}
	if err := openAssistanceDemoRoot(root); err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(root, "host"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		_, err = namedAssistanceHost(args, host.Name)
		return err
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(file, host.Name)
	return errors.Join(err, file.Close())
}

func persistentOwnerExists(root string) (bool, error) {
	return vmlab.AssistanceOwnerAccessExists(filepath.Join(root, "owner-access"))
}

func destroyAssistanceDemo(ctx context.Context, repo, root string, stdout io.Writer) (err error) {
	lock, err := lockAssistanceDemo(root)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	return destroyLockedAssistanceDemo(ctx, repo, root, stdout)
}

func destroyLockedAssistanceDemo(ctx context.Context, repo, root string, stdout io.Writer) error {
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := openAssistanceDemoRoot(root); err != nil {
		return err
	}
	if err := vmlab.DestroyPersistentVM(filepath.Join(root, "desktop")); err != nil {
		return err
	}
	if err := devlab.DestroyPersistentFixture(ctx, repo, filepath.Join(root, "control-plane")); err != nil {
		return err
	}
	if err := devlab.DestroyPersistentAuthorityFixture(filepath.Join(root, "authority")); err != nil {
		return err
	}
	if err := os.RemoveAll(root); err != nil {
		return err
	}
	_, err := fmt.Fprintln(stdout, "Destroyed named assistance state:", root)
	return err
}

func runDestroyNamedAssistance(ctx context.Context, args []string, requested string, stdout, stderr io.Writer) (err error) {
	if !vmHolds(args) || labhost.FlagValue(args, "name") == "" {
		return errors.New("-destroy requires -hold -name NAME")
	}
	root, err := controllerDemoDirectory(labhost.FlagValue(args, "name"))
	if err != nil {
		return err
	}
	lock, err := lockAssistanceDemo(root)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	hostName, err := namedAssistanceHost(args, requested)
	if err != nil {
		return err
	}
	if hostName == "" {
		if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("named demo has no recorded lab host")
	}
	cfg, err := labhost.Load()
	if err != nil {
		return err
	}
	repo := labhost.FlagValue(args, "repo")
	if repo == "" {
		repo = "."
	}
	for _, host := range cfg.Hosts {
		if host.Name != hostName {
			continue
		}
		if host.Transport == "ssh" {
			build := labhost.FlagValue(args, "build-repo")
			if build == "" {
				build = repo
			}
			if err := (labhost.RemoteRun{Host: host, Repository: build, Args: args, Stdout: stdout, Stderr: stderr}).Run(ctx); err != nil {
				return err
			}
		}
		return destroyLockedAssistanceDemo(ctx, repo, root, stdout)
	}
	return errors.New("recorded demo host is no longer configured")
}

// The stable sibling inode serializes both halves through leaf deletion.
func lockAssistanceDemo(root string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(root), 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(root+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, errors.Join(errors.New("named demo is already running or being destroyed"), err, lock.Close())
	}
	return lock, nil
}
