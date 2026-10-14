// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
)

const loadPostgresDiskBytes int64 = 128 << 30

var loadNVMeDevicePattern = regexp.MustCompile(`^nvme[0-9]+n[0-9]+$`)
var loadLoopDevicePattern = regexp.MustCompile(`^/dev/loop[0-9]+$`)

type loadMount struct {
	Target     string `json:"target"`
	Source     string `json:"source"`
	Filesystem string `json:"fstype"`
}

type loadPostgresStorage struct {
	directory           string
	file                string
	mountPath           string
	loop                string
	mounted             bool
	backing             loadMount
	devices             []string
	fileInfo            os.FileInfo
	attachmentAttempted bool
	mountAttempted      bool
}

func loadStorageCommand(ctx context.Context, privileged bool, program string, args ...string) ([]byte, error) {
	name := program
	if privileged && os.Geteuid() != 0 {
		args = append([]string{"-n", "--", program}, args...)
		name = "sudo"
	}
	output := nativeexec.NewBuffer(1 << 20)
	if err := labexec.Run(ctx, labexec.Command{Path: name, Args: args, Stdout: output}); err != nil {
		return nil, fmt.Errorf("dedicated loop/XFS storage requires working %s%s", map[bool]string{true: "noninteractive root access to ", false: ""}[privileged], program)
	}
	if output.Truncated() {
		return nil, fmt.Errorf("dedicated loop/XFS storage %s output exceeds 1 MiB", program)
	}
	return output.Bytes(), nil
}

func loadFindMount(ctx context.Context, selector, path string) (loadMount, error) {
	output, err := loadStorageCommand(ctx, false, "findmnt", "--json", "--output", "TARGET,SOURCE,FSTYPE", selector, path)
	if err != nil {
		return loadMount{}, err
	}
	var mounts struct {
		Filesystems []loadMount `json:"filesystems"`
	}
	if err := json.Unmarshal(output, &mounts); err != nil || len(mounts.Filesystems) != 1 {
		return loadMount{}, errors.New("dedicated PostgreSQL requires an unambiguous backing mount")
	}
	return mounts.Filesystems[0], nil
}

type loadBlockDevice struct {
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Children []loadBlockDevice `json:"children"`
}

func loadNVMeDevices(devices []loadBlockDevice) ([]string, error) {
	var result []string
	var visit func(loadBlockDevice) error
	visit = func(device loadBlockDevice) error {
		if device.Type == "disk" {
			if !loadNVMeDevicePattern.MatchString(filepath.Base(device.Name)) {
				return errors.New("dedicated NVMe storage backing includes a non-NVMe disk")
			}
			result = append(result, device.Name)
		}
		if len(device.Children) == 0 && device.Type != "disk" {
			return errors.New("dedicated NVMe storage has an unresolved physical backing device")
		}
		for _, child := range device.Children {
			if err := visit(child); err != nil {
				return err
			}
		}
		return nil
	}
	for _, device := range devices {
		if err := visit(device); err != nil {
			return nil, err
		}
	}
	if len(result) == 0 {
		return nil, errors.New("dedicated NVMe storage requires verified NVMe physical backing")
	}
	return result, nil
}

func openLoadPostgresStorage(ctx context.Context, repository string) (_ *loadPostgresStorage, resultErr error) {
	// This file lives on the repository's durable filesystem, never /tmp/tmpfs.
	parent := filepath.Join(repository, ".cache")
	if err := os.MkdirAll(parent, 0700); err != nil {
		return nil, err
	}
	parent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp(parent, "load-postgres-nvme-")
	if err != nil {
		return nil, err
	}
	storage := &loadPostgresStorage{directory: directory, file: filepath.Join(directory, "postgres.xfs"), mountPath: filepath.Join(directory, "data")}
	defer func() {
		if resultErr != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			if err := storage.close(cleanup); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("owned loop %s and storage %s retained: %w", storage.loop, storage.directory, err))
			}
		}
	}()
	storage.backing, err = loadFindMount(ctx, "--target", directory)
	if err != nil {
		return nil, err
	}
	switch storage.backing.Filesystem {
	case "xfs", "ext4", "btrfs":
	default:
		return nil, errors.New("dedicated NVMe storage requires local durable xfs, ext4 or btrfs backing")
	}
	source := strings.SplitN(storage.backing.Source, "[", 2)[0]
	if !strings.HasPrefix(source, "/dev/") {
		return nil, errors.New("dedicated NVMe storage backing is not a local block filesystem")
	}
	output, err := loadStorageCommand(ctx, false, "lsblk", "--json", "--inverse", "--paths", "--output", "NAME,TYPE", source)
	if err != nil {
		return nil, err
	}
	var blocks struct {
		Devices []loadBlockDevice `json:"blockdevices"`
	}
	if err := json.Unmarshal(output, &blocks); err != nil {
		return nil, errors.New("cannot inspect dedicated NVMe physical backing")
	}
	storage.devices, err = loadNVMeDevices(blocks.Devices)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(storage.file, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	err = file.Truncate(loadPostgresDiskBytes)
	if err == nil {
		storage.fileInfo, err = file.Stat()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(storage.mountPath, 0700); err != nil {
		return nil, err
	}
	storage.attachmentAttempted = true
	output, err = loadStorageCommand(ctx, true, "losetup", "--find", "--show", "--nooverlap", storage.file)
	if err != nil {
		return nil, err
	}
	storage.loop = strings.TrimSpace(string(output))
	if err := storage.verifyLoop(ctx); err != nil {
		return nil, err
	}
	// No -f: even this freshly allocated, verified loop must be unformatted.
	if _, err := loadStorageCommand(ctx, true, "mkfs.xfs", storage.loop); err != nil {
		return nil, err
	}
	if err := storage.verifyLoop(ctx); err != nil {
		return nil, err
	}
	storage.mountAttempted = true
	if _, err := loadStorageCommand(ctx, true, "mount", "-t", "xfs", "-o", "nodev,nosuid,noexec", storage.loop, storage.mountPath); err != nil {
		return nil, err
	}
	storage.mounted = true
	if err := storage.verifyMount(ctx); err != nil {
		return nil, err
	}
	return storage, nil
}

func (s *loadPostgresStorage) verifyLoop(ctx context.Context) error {
	if !loadLoopDevicePattern.MatchString(s.loop) {
		return errors.New("refusing operation on unrecognized dedicated loop device")
	}
	info, err := os.Lstat(s.file)
	if err != nil || s.fileInfo == nil || !os.SameFile(s.fileInfo, info) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != loadPostgresDiskBytes {
		return errors.New("dedicated loop backing file identity changed")
	}
	output, err := loadStorageCommand(ctx, true, "losetup", "--json", "--output", "NAME,BACK-FILE", s.loop)
	if err != nil {
		return err
	}
	var loops struct {
		Devices []struct {
			Name string `json:"name"`
			File string `json:"back-file"`
		} `json:"loopdevices"`
	}
	if err := json.Unmarshal(output, &loops); err != nil || len(loops.Devices) != 1 || loops.Devices[0].Name != s.loop || loops.Devices[0].File != s.file {
		return errors.New("refusing operation: loop device is not bound to the exact owned file")
	}
	return nil
}

func (s *loadPostgresStorage) verifyMount(ctx context.Context) error {
	if err := s.verifyLoop(ctx); err != nil {
		return err
	}
	mount, err := loadFindMount(ctx, "--mountpoint", s.mountPath)
	if err != nil {
		return err
	}
	if mount.Target != s.mountPath || mount.Source != s.loop || mount.Filesystem != "xfs" {
		return errors.New("refusing operation: dedicated XFS mount identity changed")
	}
	return nil
}

func (s *loadPostgresStorage) describe(environment *LoadExperimentEnvironment) {
	environment.Storage = "storage: NVMe-backed dedicated loop/XFS (durable fsync)"
	environment.MountPath, environment.Filesystem = s.mountPath, "xfs"
	environment.BackingFile, environment.LoopDevice = s.file, s.loop
	environment.BackingMount, environment.BackingSource = s.backing.Target, s.backing.Source
	environment.BackingFilesystem, environment.BackingDevices = s.backing.Filesystem, append([]string(nil), s.devices...)
	environment.StorageLimitBytes = loadPostgresDiskBytes
}

func (s *loadPostgresStorage) close(ctx context.Context) error {
	// Interrupted attach/mount commands may have completed in the kernel.
	// Recover only by the exact owned file; never delete through an unknown mount.
	if s.attachmentAttempted && s.loop == "" {
		output, err := loadStorageCommand(ctx, true, "losetup", "--json", "--output", "NAME,BACK-FILE", "--associated", s.file)
		if err != nil {
			return err
		}
		var loops struct {
			Devices []struct {
				Name string `json:"name"`
				File string `json:"back-file"`
			} `json:"loopdevices"`
		}
		if err := json.Unmarshal(output, &loops); err != nil || len(loops.Devices) > 1 {
			return errors.New("cannot recover exact owned loop device during cleanup")
		}
		if len(loops.Devices) == 1 {
			if loops.Devices[0].File != s.file {
				return errors.New("loop recovery did not identify the exact owned file")
			}
			s.loop = loops.Devices[0].Name
		}
	}
	if s.mountAttempted && !s.mounted {
		mount, err := loadFindMount(ctx, "--target", s.mountPath)
		if err != nil {
			return err
		}
		s.mounted = mount.Target == s.mountPath
	}
	if s.mounted {
		if err := s.verifyMount(ctx); err != nil {
			return err
		}
		if _, err := loadStorageCommand(ctx, true, "umount", s.mountPath); err != nil {
			return err
		}
		s.mounted = false
		s.mountAttempted = false
	}
	if s.loop != "" {
		if err := s.verifyLoop(ctx); err != nil {
			return err
		}
		if _, err := loadStorageCommand(ctx, true, "losetup", "--detach", s.loop); err != nil {
			return err
		}
		s.loop = ""
		s.attachmentAttempted = false
	}
	if s.directory != "" {
		if err := os.RemoveAll(s.directory); err != nil {
			return err
		}
		s.directory = ""
	}
	return nil
}
