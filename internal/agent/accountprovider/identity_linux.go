// SPDX-License-Identifier: Apache-2.0

//go:build linux

package accountprovider

import (
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

// getent initgroups asks getgrouplist with no base group, so it reports only
// groups that list the user as a member; the primary group is checked by NSS.
func (p *Provider) verifyGroups(ctx context.Context, db *localDB, u *resourcev1.LocalUserObservation) ([]byte, error) {
	var expected []uint32
	var evidence []byte
	primaryFound := false
	for name, row := range db.groups {
		gid, err := number(row[2])
		if err != nil {
			return nil, err
		}
		if gid != u.GetGid() && !slices.Contains(u.GetGroups(), name) {
			continue
		}
		if gid == u.GetGid() {
			primaryFound = true
		}
		result, err := p.nss(ctx, "group", name, row)
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, result...)
		if slices.Contains(u.GetGroups(), name) && !slices.Contains(expected, gid) {
			expected = append(expected, gid)
		}
	}
	if !primaryFound {
		return nil, ErrUnsafe
	}
	out, err := p.run(ctx, nil, "/usr/bin/getent", "initgroups", u.GetName())
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(out))
	if len(fields) < 1 || fields[0] != u.GetName() {
		return nil, ErrUnsafe
	}
	actual := make([]uint32, 0, len(fields)-1)
	for _, field := range fields[1:] {
		gid, e := number(field)
		if e != nil {
			return nil, e
		}
		actual = append(actual, gid)
	}
	slices.Sort(actual)
	actual = slices.Compact(actual)
	slices.Sort(expected)
	if !slices.Equal(actual, expected) {
		return nil, errors.New("accountprovider: supplementary NSS identity differs from local groups")
	}
	return append(evidence, out...), nil
}
func processesForUID(uid uint32) (found bool, err error) {
	directory, err := os.Open("/proc")
	if err != nil {
		return false, err
	}
	defer func() { err = errors.Join(err, directory.Close()) }()
	count := 0
	for {
		names, e := directory.Readdirnames(256)
		if e != nil && !errors.Is(e, io.EOF) {
			return false, e
		}
		count += len(names)
		if count > 65536 {
			return false, ErrUnsafe
		}
		for _, name := range names {
			if _, e := strconv.ParseUint(name, 10, 32); e != nil {
				continue
			}
			path := "/proc/" + name + "/status"
			f, e := os.Open(path)
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil {
				return false, e
			}
			data, e := io.ReadAll(io.LimitReader(f, 65537))
			e = errors.Join(e, f.Close())
			if e != nil {
				return false, e
			}
			if len(data) > 65536 {
				return false, ErrUnsafe
			}
			seen := false
			for line := range strings.SplitSeq(string(data), "\n") {
				if !strings.HasPrefix(line, "Uid:") {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) != 5 {
					return false, ErrUnsafe
				}
				seen = true
				for _, field := range fields[1:] {
					id, e := number(field)
					if e != nil {
						return false, e
					}
					if id == uid {
						found = true
					}
				}
			}
			if !seen {
				return false, ErrUnsafe
			}
		}
		if errors.Is(e, io.EOF) {
			return found, nil
		}
	}
}
