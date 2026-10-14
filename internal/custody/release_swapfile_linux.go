// SPDX-License-Identifier: Apache-2.0
//go:build linux

package custody

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Btrfs exposes anonymous st_dev numbers. Resolve a swapfile's mount and every
// member device; trusting only the mount's first device would miss mixed stacks.
func swapFileDevices(path string, device uint64, sys, mountinfo string) (_ []uint64, err error) {
	if unix.Major(device) != 0 {
		return []uint64{device}, nil
	}
	file, err := os.Open(mountinfo)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	best, filesystem, source := "", "", ""
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := -1
		for i, value := range fields {
			if value == "-" {
				separator = i
				break
			}
		}
		if len(fields) < 7 || separator < 6 || len(fields) <= separator+2 {
			return nil, errors.New("invalid filesystem mount inventory")
		}
		mount := unescapeProcPath(fields[4])
		if (path == mount || strings.HasPrefix(path, strings.TrimRight(mount, "/")+"/")) && len(mount) > len(best) {
			best, filesystem, source = mount, fields[separator+1], unescapeProcPath(fields[separator+2])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if filesystem != "btrfs" || !filepath.IsAbs(source) {
		return nil, errors.New("active swapfile backing filesystem cannot establish encrypted block custody")
	}
	var stat unix.Stat_t
	if err := unix.Stat(source, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFBLK {
		return nil, errors.New("swapfile mount source is not a block device")
	}
	return btrfsDevices(sys, uint64(stat.Rdev))
}

func unescapeProcPath(path string) string {
	return strings.NewReplacer("\\040", " ", "\\011", "\t", "\\012", "\n", "\\134", "\\").Replace(path)
}

func btrfsDevices(sys string, source uint64) ([]uint64, error) {
	filesystems, err := os.ReadDir(filepath.Join(sys, "fs", "btrfs"))
	if err != nil {
		return nil, err
	}
	for _, filesystem := range filesystems {
		if !filesystem.IsDir() {
			continue
		}
		devices, err := os.ReadDir(filepath.Join(sys, "fs", "btrfs", filesystem.Name(), "devices"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var members []uint64
		found := false
		for _, device := range devices {
			data, err := os.ReadFile(filepath.Join(sys, "fs", "btrfs", filesystem.Name(), "devices", device.Name(), "dev"))
			if err != nil {
				return nil, err
			}
			pair := strings.Split(strings.TrimSpace(string(data)), ":")
			if len(pair) != 2 {
				return nil, errors.New("invalid btrfs member device")
			}
			major, err := strconv.ParseUint(pair[0], 10, 32)
			if err != nil {
				return nil, err
			}
			minor, err := strconv.ParseUint(pair[1], 10, 32)
			if err != nil {
				return nil, err
			}
			number := unix.Mkdev(uint32(major), uint32(minor))
			found = found || number == source
			members = append(members, number)
		}
		if found {
			return members, nil
		}
	}
	return nil, fmt.Errorf("swapfile btrfs source %d:%d has no authenticated kernel member inventory", unix.Major(source), unix.Minor(source))
}
