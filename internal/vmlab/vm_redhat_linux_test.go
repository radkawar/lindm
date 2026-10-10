//go:build linux

package vmlab

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestVMRedHatCleanupAlwaysDeletesAfterUnregister(t *testing.T) {
	guestFailure := errors.New("guest unreachable")
	keyFailure := errors.New("key deletion failed")
	for _, test := range []struct {
		name     string
		guestErr error
		keyErr   error
	}{
		{name: "success"},
		{name: "guest failure", guestErr: guestFailure},
		{name: "key failure", keyErr: keyFailure},
		{name: "both failures", guestErr: guestFailure, keyErr: keyFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			var guestContext context.Context
			calls := 0
			err := cleanupVMRedHat(func(ctx context.Context) error {
				calls++
				guestContext = ctx
				deadline, ok := ctx.Deadline()
				if calls != 1 || ctx.Err() != nil || !ok || time.Until(deadline) > 3*time.Minute {
					t.Fatal("unregister must run first with a live bounded context")
				}
				return test.guestErr
			}, func(ctx context.Context) error {
				calls++
				deadline, ok := ctx.Deadline()
				if calls != 2 || guestContext.Err() == nil || ctx.Err() != nil || !ok || time.Until(deadline) > 2*time.Minute {
					t.Fatal("key deletion must follow unregister with an independent bounded context")
				}
				return test.keyErr
			})
			if calls != 2 || (err == nil) != (test.guestErr == nil && test.keyErr == nil) {
				t.Fatalf("cleanup calls %d, error %v", calls, err)
			}
			for _, expected := range []error{test.guestErr, test.keyErr} {
				if expected != nil && !errors.Is(err, expected) {
					t.Fatal("cleanup lost an operation failure")
				}
			}
		})
	}
}

func TestVMRedHatTokenScope(t *testing.T) {
	for _, distribution := range []string{"ubuntu", "fedora", "rhel"} {
		if err := validateVMRedHatToken(distribution, ""); err != nil {
			t.Fatal("offline native package lanes must not require registration")
		}
		err := validateVMRedHatToken(distribution, "/protected/token-file")
		if (err == nil) != (distribution == "rhel") {
			t.Fatalf("registration token accepted outside RHEL: %s", distribution)
		}
	}
}
