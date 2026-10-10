package recoveryboot

import (
	"strconv"
	"testing"
)

func decodeCPIO(t *testing.T, archive []byte) map[string][]byte {
	t.Helper()
	entries := map[string][]byte{}
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
		if _, exists := entries[name]; exists {
			t.Fatal("duplicate newc path")
		}
		entries[name] = archive[start:end]
		archive = archive[next:]
	}
}
