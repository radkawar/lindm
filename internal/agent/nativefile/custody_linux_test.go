//go:build linux

package nativefile

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/google/uuid"
)

// Ubuntu 24.04 ships no /etc/motd.d. Observed live: a managed file under that
// approved but absent root failed as an internal executor error, retried every
// 20 seconds without a report, and blocked every later resource on the device.
// An absent protected ancestor is a classified precondition conflict.
func TestAbsentProtectedAncestorIsPreconditionConflict(t *testing.T) {
	absent := "/lindm-absent-" + uuid.NewString()
	if _, err := os.Lstat(absent); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("fixture path exists: %v", err)
	}
	for _, readOnly := range []bool{true, false} {
		c, err := openCustody(absent+"/motd.d/50-company", readOnly)
		if err == nil {
			t.Fatal(errors.Join(errors.New("custody opened under an absent ancestor"), c.close()))
		}
		if !errors.Is(err, ErrConflict) || !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("absent ancestor (readOnly=%t) not a classified conflict: %v", readOnly, err)
		}
	}
}
