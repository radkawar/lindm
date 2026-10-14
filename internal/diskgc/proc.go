// SPDX-License-Identifier: Apache-2.0

//go:build linux

package diskgc

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// uses is one snapshot of what every readable process on this host uses.
type uses struct {
	procs []process
}

type process struct {
	pid, comm string
	paths     []string // cwd, root, exe and open files, symlinks resolved by the kernel
	args      []string // absolute command-line paths, including KEY=/path values
}

// scanProcesses reads /proc once. Processes of other users are unreadable and
// skipped: gc removes only what this user owns.
func scanProcesses() (*uses, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	self := strconv.Itoa(os.Getpid())
	snapshot := &uses{}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil || entry.Name() == self {
			continue
		}
		base := filepath.Join("/proc", entry.Name())
		p := process{pid: entry.Name()}
		links := []string{filepath.Join(base, "cwd"), filepath.Join(base, "root"), filepath.Join(base, "exe")}
		if fds, err := os.ReadDir(filepath.Join(base, "fd")); err == nil {
			for _, fd := range fds {
				links = append(links, filepath.Join(base, "fd", fd.Name()))
			}
		}
		for _, link := range links {
			if target, err := os.Readlink(link); err == nil && strings.HasPrefix(target, "/") {
				p.paths = append(p.paths, strings.TrimSuffix(target, " (deleted)"))
			}
		}
		if cmdline, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil {
			for arg := range bytes.SplitSeq(cmdline, []byte{0}) {
				value := string(arg)
				if _, after, ok := strings.Cut(value, "="); ok {
					value = after
				}
				if strings.HasPrefix(value, "/") {
					p.args = append(p.args, canonical(value))
				}
			}
		}
		if len(p.paths) == 0 && len(p.args) == 0 {
			continue
		}
		comm, _ := os.ReadFile(filepath.Join(base, "comm"))
		p.comm = strings.TrimSpace(string(comm))
		snapshot.procs = append(snapshot.procs, p)
	}
	return snapshot, nil
}

// user names a process using path, or returns "" when none does.
func (u *uses) user(path string) string {
	root := canonical(path)
	for _, p := range u.procs {
		for _, used := range p.paths {
			if within(used, root) {
				return fmt.Sprintf("in use by pid %s (%s)", p.pid, p.comm)
			}
		}
		for _, arg := range p.args {
			if within(arg, root) {
				return fmt.Sprintf("named by pid %s (%s)", p.pid, p.comm)
			}
		}
	}
	return ""
}

func within(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

// canonical resolves symlinks where the path exists, so recorded and /proc
// paths compare equal.
func canonical(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		return resolved
	}
	return absolute
}
