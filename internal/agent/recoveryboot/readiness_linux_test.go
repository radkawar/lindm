package recoveryboot

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadinessCapacityUsesAvailableAllocationUnits(t *testing.T) {
	free, unit, err := readinessCapacity(unix.Statfs_t{Type: unix.MSDOS_SUPER_MAGIC, Frsize: 4096, Bsize: 512, Bavail: 3, Bfree: 100})
	if err != nil || free != 12288 || unit != 4096 {
		t.Fatalf("capacity counted reserved bytes or wrong units: free=%d unit=%d err=%v", free, unit, err)
	}
	free, unit, err = readinessCapacity(unix.Statfs_t{Type: unix.MSDOS_SUPER_MAGIC, Bsize: 512, Bavail: 3})
	if err != nil || free != 1536 || unit != 512 {
		t.Fatalf("allocation fallback incorrect: free=%d unit=%d err=%v", free, unit, err)
	}
}

func TestReadinessCapacityRejectsUnsupportedFilesystems(t *testing.T) {
	for _, filesystem := range []unix.Statfs_t{
		{Type: unix.EXT4_SUPER_MAGIC, Frsize: 4096, Bavail: 100},
		{Type: unix.MSDOS_SUPER_MAGIC, Flags: unix.ST_RDONLY, Frsize: 4096, Bavail: 100},
		{Type: unix.MSDOS_SUPER_MAGIC},
		{Type: unix.MSDOS_SUPER_MAGIC, Frsize: 4096, Bavail: ^uint64(0)},
	} {
		free, unit, err := readinessCapacity(filesystem)
		if err == nil || free != 0 || unit != 0 {
			t.Fatalf("unsupported filesystem appeared usable: free=%d unit=%d err=%v", free, unit, err)
		}
	}
}

func TestReadinessCancelledDoesNotInspectESP(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	facts, err := ObserveReadiness(ctx, "/not/an/esp")
	if !errors.Is(err, context.Canceled) || facts != (Readiness{}) {
		t.Fatalf("cancelled observation touched native state: facts=%+v err=%v", facts, err)
	}
}

func TestReadinessSecureBootRejectsUnreadableAndUnsupportedFirmware(t *testing.T) {
	for _, tc := range []struct {
		name      string
		secure    []byte
		setup     []byte
		err       error
		available bool
	}{
		{name: "enforced", secure: []byte{0, 0, 0, 0, 1}, setup: []byte{0, 0, 0, 0, 0}, available: true},
		{name: "unreadable", err: unix.EACCES},
		{name: "non_uefi", err: unix.ENOENT},
		{name: "secure_boot_disabled", secure: []byte{0, 0, 0, 0, 0}, setup: []byte{0, 0, 0, 0, 0}},
		{name: "setup_mode", secure: []byte{0, 0, 0, 0, 1}, setup: []byte{0, 0, 0, 0, 1}},
		{name: "malformed", secure: []byte{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enforced, err := readinessSecureBoot(func(path string) ([]byte, error) {
				switch path {
				case efivars + "SecureBoot-" + globalGUID:
					return tc.secure, tc.err
				case efivars + "SetupMode-" + globalGUID:
					return tc.setup, tc.err
				default:
					t.Fatal("observer read a path outside the fixed public EFI variables")
					return nil, unix.EACCES
				}
			})
			if enforced != tc.available || (err == nil) != tc.available {
				t.Fatalf("firmware observation incorrectly qualified: secure=%v err=%v", enforced, err)
			}
		})
	}
}

func TestReadinessESPIdentityWithoutDeviceLinks(t *testing.T) {
	const partition = "1e3c984b-74ac-426e-ad7d-f789af4da7c0"
	const metadata = "I:12345\nE:ID_FS_TYPE=vfat\nE:ID_FS_UUID=1234-ABCD\nE:ID_PART_ENTRY_UUID=" + partition + "\nE:ID_PART_ENTRY_NUMBER=15\n"
	filesystem, observedPartition, err := parseReadinessESPIdentity(metadata)
	if err != nil || filesystem != "1234-ABCD" || observedPartition != partition {
		t.Fatalf("native mounted-device identity unavailable: filesystem=%q partition=%q err=%v", filesystem, observedPartition, err)
	}
	for _, invalid := range []string{
		"",
		strings.Replace(metadata, "vfat", "ext4", 1),
		strings.Replace(metadata, "1234-ABCD", "not-a-uuid", 1),
		strings.Replace(metadata, partition, "", 1),
		metadata + "E:ID_FS_UUID=5678-FFFF\n",
		metadata + "E:ID_PART_ENTRY_UUID=" + partition + "\n",
	} {
		if _, _, err := parseReadinessESPIdentity(invalid); err == nil {
			t.Fatal("ambiguous or incomplete ESP metadata accepted")
		}
	}
}

func TestEFIPartitionUUIDAcceptsSystemdUppercase(t *testing.T) {
	for _, value := range []string{"F923FA2F-C2FA-401B-9021-B4594673BF6F", "f923fa2f-c2fa-401b-9021-b4594673bf6f"} {
		if !efiPartitionUUID(value) {
			t.Fatalf("native EFI partition UUID rejected: %q", value)
		}
	}
	for _, value := range []string{"", "urn:uuid:f923fa2f-c2fa-401b-9021-b4594673bf6f", "f923fa2fc2fa401b9021b4594673bf6f", "g923fa2f-c2fa-401b-9021-b4594673bf6f"} {
		if efiPartitionUUID(value) {
			t.Fatalf("malformed EFI partition UUID accepted: %q", value)
		}
	}
}
