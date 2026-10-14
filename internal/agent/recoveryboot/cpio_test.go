// SPDX-License-Identifier: Apache-2.0

package recoveryboot

import (
	"strconv"
	"testing"
)

type cpioFile struct {
	mode, uid, gid       int
	rdevMajor, rdevMinor int
	data                 []byte
}

func decodeCPIO(t *testing.T, archive []byte) map[string]cpioFile {
	t.Helper()
	entries := map[string]cpioFile{}
	for {
		if len(archive) < 110 || string(archive[:6]) != "070701" {
			t.Fatal("invalid newc header")
		}
		field := func(offset int) int {
			value, err := strconv.ParseUint(string(archive[offset:offset+8]), 16, 32)
			if err != nil {
				t.Fatal(err)
			}
			return int(value)
		}
		size, namesize := field(54), field(94)
		if namesize < 1 || namesize > len(archive)-110 {
			t.Fatal("invalid newc name length")
		}
		if archive[110+namesize-1] != 0 {
			t.Fatal("unterminated newc name")
		}
		name := string(archive[110 : 110+namesize-1])
		start := (110 + namesize + 3) &^ 3
		end := start + size
		next := (end + 3) &^ 3
		if start > len(archive) || end > len(archive) || next > len(archive) {
			t.Fatal("newc payload exceeds archive")
		}
		if name == "TRAILER!!!" {
			return entries
		}
		if name == "." && (field(14) != 0040755 || field(22) != 0 || field(30) != 0) {
			t.Fatal("initramfs root must establish protected mode0755 uid0 gid0 ancestry")
		}
		if _, exists := entries[name]; exists {
			t.Fatal("duplicate newc path")
		}
		entries[name] = cpioFile{mode: field(14), uid: field(22), gid: field(30), rdevMajor: field(78), rdevMinor: field(86), data: archive[start:end]}
		archive = archive[next:]
	}
}
