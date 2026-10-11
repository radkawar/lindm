//go:build linux

package vmlab

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
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
	for _, release := range []*platform.Release{platform.ForManifest("ubuntu", "24.04"), platform.ForManifest("fedora", "44"), platform.ForManifest("rhel", "9.6")} {
		if err := validateVMRedHatToken(release, ""); err != nil {
			t.Fatal("offline native package lanes must not require registration")
		}
		err := validateVMRedHatToken(release, "/protected/token-file")
		if (err == nil) != (release.ID == "rhel") {
			t.Fatalf("registration token accepted outside RHEL: %s", release.Name)
		}
	}
}

func TestVMRedHatPublicRunNames(t *testing.T) {
	first, err := newVMRedHatRunName()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newVMRedHatRunName()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !vmRedHatRunNamePattern.MatchString(first) || !vmRedHatRunNamePattern.MatchString(second) {
		t.Fatal("public registration names must be independently random and canonical")
	}
}

func TestVMRedHatReceiptRejectsUnexpectedIdentity(t *testing.T) {
	const name = "lindm-lab-fedcba9876543210fedcba9876543210"
	const consumer = "01234567-89ab-cdef-0123-456789abcdef"
	valid := `{"run_name":"` + name + `","consumer_uuid":"` + consumer + `"}`
	identity, err := decodeVMRedHatIdentity([]byte(valid), name)
	if err != nil || identity.GetConsumerUuid() != consumer || identity.GetRunName() != name {
		t.Fatal("valid public consumer identity rejected")
	}
	for _, data := range []string{
		"", strings.Repeat("sensitive-material", 100),
		strings.Replace(valid, consumer, "sensitive-material", 1),
		strings.Replace(valid, consumer, strings.ToUpper(consumer), 1),
		strings.Replace(valid, consumer, "00000000-0000-0000-0000-000000000000", 1),
		strings.Replace(valid, name, "lindm-lab-0123456789abcdef0123456789abcdef", 1),
		strings.TrimSuffix(valid, "}") + `,"activation_key":"sensitive-material"}`,
		valid + "\nsensitive-material",
	} {
		identity, err := decodeVMRedHatIdentity([]byte(data), name)
		if err == nil || identity != nil || strings.Contains(err.Error(), "sensitive-material") {
			t.Fatal("unexpected guest identity accepted or leaked")
		}
	}
}

func TestVMRedHatPrivateReceiptSurvivesDisposableState(t *testing.T) {
	directory := t.TempDir()
	vmDir := filepath.Join(directory, "disposable-vm")
	if err := os.Mkdir(vmDir, 0700); err != nil {
		t.Fatal(err)
	}
	const name = "lindm-lab-fedcba9876543210fedcba9876543210"
	receipt, err := createVMRedHatReceipt(filepath.Dir(vmDir), name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receipt.Close() })
	info, err := receipt.Stat()
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("registration receipt must remain private")
	}
	data, err := os.ReadFile(receipt.Name())
	if err != nil {
		t.Fatal(err)
	}
	pending := new(labv1.RedHatRegistrationIdentity)
	if err := protojson.Unmarshal(data, pending); err != nil || pending.GetRunName() != name || pending.GetConsumerUuid() != "" {
		t.Fatal("pre-mutation receipt must retain only the independent public name")
	}
	if duplicate, err := createVMRedHatReceipt(directory, name); err == nil {
		_ = duplicate.Close()
		t.Fatal("existing registration receipt overwritten")
	}
	identity := &labv1.RedHatRegistrationIdentity{RunName: name, ConsumerUuid: "01234567-89ab-cdef-0123-456789abcdef"}
	if err := appendVMRedHatReceipt(receipt, identity); err != nil {
		t.Fatal(err)
	}
	if err := receipt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(vmDir); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(receipt.Name())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatal("receipt must retain intent followed by the exact consumer identity")
	}
	observed, err := decodeVMRedHatIdentity([]byte(lines[1]), name)
	if err != nil || observed.GetConsumerUuid() != identity.GetConsumerUuid() {
		t.Fatal("durable receipt lost exact native UUID")
	}
	if _, err := createVMRedHatReceipt(directory, "../outside"); err == nil {
		t.Fatal("noncanonical receipt path accepted")
	}
}
