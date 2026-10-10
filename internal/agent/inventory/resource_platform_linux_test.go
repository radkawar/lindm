//go:build linux

package inventory

import (
	"context"
	"errors"
	"io/fs"
	"testing"
)

func TestResourcePlatformNativeIdentity(t *testing.T) {
	for _, test := range []struct {
		name, release, id, product, version, architecture string
	}{
		{"ubuntu", "ID=ubuntu\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID_LIKE=debian\n", "ubuntu", "Ubuntu", "24.04", "x86_64"},
		{"fedora", "ID=fedora\nNAME=\"Fedora Linux\"\nVERSION_ID=44\nVARIANT_ID=cloud\n", "fedora", "Fedora Linux", "44", "aarch64"},
		{"rolling", "ID=arch\nNAME=\"Arch Linux\"\nBUILD_ID=20261001\n", "arch", "Arch Linux", "", "x86_64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			platform, err := hostPlatform(context.Background(), func(string) ([]byte, error) { return []byte(test.release), nil }, func() (string, error) { return test.architecture, nil })
			if err != nil {
				t.Fatal(err)
			}
			if platform.GetOsId() != test.id || platform.GetProduct() != test.product || platform.GetVersion() != test.version || platform.GetArchitecture() != test.architecture {
				t.Fatalf("incorrect native product identity: %v", platform)
			}
		})
	}
}

func TestResourcePlatformRefusesUnavailableIdentity(t *testing.T) {
	for _, release := range []string{"NAME=Ubuntu\nVERSION_ID=24.04\n", "ID=ubuntu\nVERSION_ID=24.04\n", "ID=Ubuntu\nNAME=Ubuntu\nVERSION_ID=24.04\n"} {
		if _, err := hostPlatform(context.Background(), func(string) ([]byte, error) { return []byte(release), nil }, func() (string, error) { return "x86_64", nil }); err == nil {
			t.Fatalf("unavailable or malformed native identity accepted: %q", release)
		}
	}
	_, err := hostPlatform(context.Background(), func(string) ([]byte, error) { return nil, fs.ErrPermission }, func() (string, error) { t.Fatal("uname called after failed product observation"); return "", nil })
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("native observation error hidden: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = hostPlatform(ctx, func(string) ([]byte, error) { t.Fatal("read after cancellation"); return nil, nil }, func() (string, error) { t.Fatal("uname after cancellation"); return "", nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
