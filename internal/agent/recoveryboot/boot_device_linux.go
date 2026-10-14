// SPDX-License-Identifier: Apache-2.0

package recoveryboot

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// BootBlockDevice returns the /dev source of the filesystem containing
// bootDirectory, from the longest matching mountinfo mount point, and whether
// grub-editenv must write it (btrfs keeps GRUB's environment in the bootloader
// area rather than a file). It names a path only; it never opens the device.
func BootBlockDevice(bootDirectory string) (device string, writable bool, err error) {
	if !filepath.IsAbs(bootDirectory) || filepath.Clean(bootDirectory) != bootDirectory {
		return "", false, errors.New("recoveryboot: absolute_clean_path_required")
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(bootDirectory, &filesystem); err != nil {
		return "", false, err
	}
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", false, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	device, err = mountSourceFor(file, bootDirectory)
	return device, filesystem.Type == unix.BTRFS_SUPER_MAGIC, err
}

// mountSourceFor picks the source of the longest mount point that contains
// directory. Later duplicate mounts of the same point win, as in the kernel.
func mountSourceFor(mountinfo io.Reader, directory string) (string, error) {
	scanner := bufio.NewScanner(io.LimitReader(mountinfo, 4<<20))
	scanner.Buffer(make([]byte, 0, 4096), 1<<16)
	best, source := "", ""
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if len(fields) < 5 || separator < 0 || len(fields) < separator+3 {
			continue
		}
		point := fields[4]
		if point != "/" && point != directory && !strings.HasPrefix(directory, point+"/") {
			continue
		}
		if len(point) >= len(best) {
			best, source = point, fields[separator+2]
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if !strings.HasPrefix(source, "/dev/") || filepath.Clean(source) != source || strings.ContainsAny(source, "\\ \t") {
		return "", errors.New("recoveryboot: boot_filesystem_has_no_device_source")
	}
	return source, nil
}
