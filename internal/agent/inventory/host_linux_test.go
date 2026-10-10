//go:build linux

package inventory

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"buf.build/go/protovalidate"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func TestOSReleaseQuoting(t *testing.T) {
	input := "# vendor identity\nID=debian\nVERSION_ID=\"12\"\nNAME='Debian GNU/Linux'\n" +
		"PRETTY_NAME=\"a \\\"quote\\\" and \\$dollar and \\`tick\\` and \\\\slash\"\n" +
		"CUSTOM=escaped\\ value\nID=ubuntu\n"
	values, err := parseOSRelease([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if values["ID"] != "ubuntu" || values["VERSION_ID"] != "12" || values["NAME"] != "Debian GNU/Linux" ||
		values["PRETTY_NAME"] != "a \"quote\" and $dollar and `tick` and \\slash" || values["CUSTOM"] != "escaped value" {
		t.Fatalf("incorrect quoting: %v", values)
	}
	values, err = parseOSRelease([]byte("NAME='literal $(not-executed)'\n"))
	if err != nil || values["NAME"] != "literal $(not-executed)" {
		t.Fatalf("single-quoted literal=%v err=%v", values, err)
	}
}

func TestOSReleaseRejectsMalformedEvidence(t *testing.T) {
	for _, input := range []string{
		"ID=\"ubuntu", "ID='ubuntu'junk", "ID=\"ub\"\"untu\"", "ID=$(whoami)", "ID=\"$HOME\"",
		"ID=ubuntu;id", "export ID=ubuntu", "ID=ub untu", "ID=ubuntu\x00", "ID=ubuntu\\", "ID=\xff",
	} {
		if _, err := parseOSRelease([]byte(input)); !errors.Is(err, errInvalid) {
			t.Errorf("input %q: err=%v", input, err)
		}
	}
	if _, err := parseOSRelease([]byte(strings.Repeat("x", maxHostFile+1))); !errors.Is(err, errCapacity) {
		t.Fatalf("unbounded os-release: %v", err)
	}
}

func TestOSReleaseFallbackOnlyWhenAbsent(t *testing.T) {
	for _, tc := range []struct {
		name         string
		localErr     error
		wantFallback bool
	}{
		{"absent", fs.ErrNotExist, true},
		{"denied", fs.ErrPermission, false},
		{"invalid", errInvalid, false},
		{"present", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fallback := false
			read := func(path string) ([]byte, error) {
				if path == "/usr/lib/os-release" {
					fallback = true
					return []byte("ID=debian\nVERSION_ID=12\n"), nil
				}
				return []byte("ID=ubuntu\nVERSION_ID=24.04\n"), tc.localErr
			}
			values, err := loadOSRelease(context.Background(), read)
			if fallback != tc.wantFallback {
				t.Fatalf("fallback=%v", fallback)
			}
			if tc.localErr != nil && !tc.wantFallback {
				if !errors.Is(err, tc.localErr) {
					t.Fatalf("lost local error: %v", err)
				}
			} else if err != nil || values["ID"] == "" {
				t.Fatalf("values=%v err=%v", values, err)
			}
		})
	}
}

func TestTypedHostEvidence(t *testing.T) {
	read := func(path string) ([]byte, error) {
		switch path {
		case "/etc/os-release":
			return []byte("ID=ubuntu\nVERSION_ID=24.04\n"), nil
		case "/proc/sys/kernel/random/boot_id":
			return []byte("71b44ad1-6894-451e-8b48-b1efb5b1c0f2\n"), nil
		case "/sys/class/dmi/id/sys_vendor":
			return []byte("Fixture Vendor\n"), nil
		case "/sys/class/dmi/id/product_name":
			return nil, fs.ErrNotExist
		case "/sys/class/dmi/id/product_serial":
			return nil, fs.ErrPermission
		default:
			t.Fatalf("unexpected path %s", path)
			return nil, fs.ErrNotExist
		}
	}
	host, _ := collectHost(context.Background(), read, false)
	if host.BootId.Status != success || host.HardwareVendor.Value != "Fixture Vendor" ||
		host.HardwareModel.Status != unavailable || host.HardwareModel.Value != "" ||
		host.HardwareSerial.Status != inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED || host.HardwareSerial.Value != "" {
		t.Fatalf("incorrect typed evidence: %v", host)
	}
	if err := protovalidate.Validate(host); err != nil {
		t.Fatalf("invalid host observation: %v", err)
	}
	badBoot := func(path string) ([]byte, error) {
		if path == "/proc/sys/kernel/random/boot_id" {
			return []byte("not-a-uuid\n"), nil
		}
		return read(path)
	}
	host, _ = collectHost(context.Background(), badBoot, false)
	if host.BootId.Status != invalid || host.BootId.Value != "" {
		t.Fatalf("invented boot identity: %v", host.BootId)
	}
}

func TestObservedFieldBoundaries(t *testing.T) {
	for _, tc := range []struct {
		value  string
		err    error
		status inventoryv1.CollectionStatus
	}{
		{"", nil, unavailable},
		{" \n", nil, unavailable},
		{"vendor\n", nil, success},
		{"one\ntwo", nil, invalid},
		{"\xff", nil, invalid},
		{"id\x00", nil, invalid},
		{strings.Repeat("x", 4097), nil, invalid},
		{"discarded", fs.ErrPermission, inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED},
		{"discarded", context.Canceled, inventoryv1.CollectionStatus_COLLECTION_STATUS_TIMEOUT},
	} {
		got := observed(tc.value, tc.err)
		if got.Status != tc.status || got.Status != success && got.Value != "" {
			t.Errorf("value=%q err=%v got=%v", tc.value, tc.err, got)
		}
		if err := protovalidate.Validate(got); err != nil {
			t.Fatalf("invalid field evidence: %v", err)
		}
	}
}

func TestHostFileBoundaries(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "evidence")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxHostFile+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readHostFile(path); !errors.Is(err, errCapacity) {
		t.Fatalf("oversized evidence err=%v", err)
	}
	if _, err := readHostFile(root); !errors.Is(err, errInvalid) {
		t.Fatalf("nonregular evidence err=%v", err)
	}
	if _, err := readHostFile(filepath.Join(root, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing evidence err=%v", err)
	}
}
