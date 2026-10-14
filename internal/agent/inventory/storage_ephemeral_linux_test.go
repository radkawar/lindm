// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"buf.build/go/protovalidate"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// popSwapLsblk is Pop!_OS 24.04's distinst layout: a LUKS root partition and a
// plain dm-crypt swap on its own partition.
const popSwapLsblk = `{"blockdevices":[{"name":"vda","kname":"vda","type":"disk","size":"25769803776","fstype":null,"fsver":null,"uuid":null,"partuuid":null,"parttype":null,"pttype":"gpt","ptuuid":"0b4f7c2e-5c44-4b8e-9a8f-2f7f8a1e0a11","tran":"virtio","model":null,"serial":"lab","wwn":null,"rev":null,"mountpoints":[null],"pkname":null,
"children":[{"name":"vda3","kname":"vda3","type":"part","size":"16000000000","fstype":"crypto_LUKS","fsver":"2","uuid":"3d4d665b-aa58-4bb0-b0c1-717a43cebe20","partuuid":"11111111-1111-4111-8111-111111111111","parttype":"0fc63daf-8483-4772-8e79-3d69d8477de4","pttype":"gpt","ptuuid":"0b4f7c2e-5c44-4b8e-9a8f-2f7f8a1e0a11","tran":null,"model":null,"serial":null,"wwn":null,"rev":null,"mountpoints":[null],"pkname":"vda"},
{"name":"vda4","kname":"vda4","type":"part","size":"4294967296","fstype":"swap","fsver":"1","uuid":"e44be28a-9a75-4a05-819e-5bc72b620ca2","partuuid":"22222222-2222-4222-8222-222222222222","parttype":"0657fd6d-a4ab-43c4-84e5-0933c84b4f4f","pttype":"gpt","ptuuid":"0b4f7c2e-5c44-4b8e-9a8f-2f7f8a1e0a11","tran":null,"model":null,"serial":null,"wwn":null,"rev":null,"mountpoints":[null],"pkname":"vda",
"children":[{"name":"cryptswap","kname":"dm-1","type":"crypt","size":"4294443008","fstype":"swap","fsver":"1","uuid":"0a02d82e-f2b3-4a4d-bcaf-33c724c446d1","partuuid":null,"parttype":null,"pttype":null,"ptuuid":null,"tran":null,"model":null,"serial":null,"wwn":null,"rev":null,"mountpoints":["[SWAP]"],"pkname":"vda4"}]}]}]}`

const popCrypttab = "cryptdata UUID=3d4d665b-aa58-4bb0-b0c1-717a43cebe20 none luks\ncryptswap UUID=e44be28a-9a75-4a05-819e-5bc72b620ca2 /dev/urandom swap,plain,offset=1024,cipher=aes-xts-plain64,size=512\n"

type ephemeralFixture struct {
	dmUUID, crypttab string
	slaves           []string
	slavesErr        error
	backing          []byte
}

type slaveEntry string

func (e slaveEntry) Name() string             { return string(e) }
func (slaveEntry) IsDir() bool                { return false }
func (slaveEntry) Type() fs.FileMode          { return fs.ModeSymlink }
func (slaveEntry) Info() (fs.FileInfo, error) { return nil, fs.ErrNotExist }

func (f ephemeralFixture) collect(t *testing.T) *inventoryv1.BlockDevice {
	t.Helper()
	dir := t.TempDir()
	backing := filepath.Join(dir, "vda4")
	if err := os.WriteFile(backing, f.backing, 0o600); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"/sys/class/block/dm-1/dm/uuid": f.dmUUID + "\n", "/sys/class/block/dm-1/dm/name": "cryptswap\n", "/etc/crypttab": f.crypttab}
	got := collectStorage(t.Context(), detailSources{
		readFile: func(path string) ([]byte, error) {
			if value, ok := files[path]; ok {
				return []byte(value), nil
			}
			return nil, fs.ErrNotExist
		},
		openBlock: func(path string) (*os.File, error) {
			if path == "/dev/vda4" {
				return os.Open(backing)
			}
			return nil, fs.ErrPermission
		},
		readDir: func(path string) ([]fs.DirEntry, error) {
			if path != "/sys/class/block/dm-1/slaves" {
				return nil, fs.ErrNotExist
			}
			var entries []fs.DirEntry
			for _, name := range f.slaves {
				entries = append(entries, slaveEntry(name))
			}
			return entries, f.slavesErr
		},
		// The root inventory helper has no capabilities, so the proof may run
		// no device-mapper tool (dmsetup and cryptsetup need CAP_SYS_ADMIN and
		// /dev/mapper/control).
		run: func(_ context.Context, b backend, parse func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
			switch b.name {
			case "lsblk":
				return parse(strings.NewReader(popSwapLsblk))
			case "dmsetup", "cryptsetup":
				t.Fatalf("storage collection ran %s %q", b.name, b.args)
			}
			return unavailable
		},
	})
	if got.Status != success {
		t.Fatalf("storage = %v", got)
	}
	if err := protovalidate.Validate(got); err != nil {
		t.Fatal(err)
	}
	for _, device := range got.Devices {
		if device.Name == "vda3" || device.Name == "vda4" || device.Name == "vda" {
			if e := device.Identity.EphemeralKey; e.Status != success || e.Value {
				t.Fatalf("%s ephemeral_key = %v; non-crypt devices are never ephemeral mappings", device.Name, e)
			}
		}
	}
	for _, device := range got.Devices {
		if device.Name == "cryptswap" {
			return device
		}
	}
	t.Fatal("cryptswap not observed")
	return nil
}

// Pop!_OS's distinst random-key swap is proven ephemeral, and nothing else is.
func TestEphemeralKeyRequiresEveryNativeProof(t *testing.T) {
	plain := ephemeralFixture{dmUUID: "CRYPT-PLAIN-cryptswap", crypttab: popCrypttab, slaves: []string{"vda4"}, backing: make([]byte, 8<<20)}
	luksAt := func(offset int, magic string) []byte {
		data := make([]byte, 8<<20)
		copy(data[offset:], magic)
		return data
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ephemeralFixture)
		status inventoryv1.CollectionStatus
		value  bool
	}{
		{"urandom plain swap", func(*ephemeralFixture) {}, success, true},
		{"random plain swap", func(f *ephemeralFixture) {
			f.crypttab = strings.Replace(f.crypttab, "/dev/urandom", "/dev/random", 1)
		}, success, true},
		{"persistent keyfile plain", func(f *ephemeralFixture) {
			f.crypttab = strings.Replace(f.crypttab, "/dev/urandom", "/etc/keys/swap.key", 1)
		}, unavailable, false},
		{"crypttab names no such mapping", func(f *ephemeralFixture) { f.crypttab = "cryptdata UUID=3d4d665b none luks\n" }, unavailable, false},
		{"duplicate crypttab entries", func(f *ephemeralFixture) { f.crypttab += "cryptswap UUID=x /dev/urandom swap\n" }, unavailable, false},
		{"kernel labels a LUKS mapping", func(f *ephemeralFixture) { f.dmUUID = "CRYPT-LUKS2-3d4d665baa584bb0b0c1717a43cebe20-cryptswap" }, success, false},
		{"unlabelled mapping", func(f *ephemeralFixture) { f.dmUUID = "" }, unavailable, false},
		{"LUKS primary header on backing", func(f *ephemeralFixture) { f.backing = luksAt(0, "LUKS\xba\xbe") }, invalid, false},
		{"LUKS2 secondary header on backing", func(f *ephemeralFixture) { f.backing = luksAt(0x4000, "SKUL\xba\xbe") }, invalid, false},
		{"label names another mapping", func(f *ephemeralFixture) { f.dmUUID = "CRYPT-PLAIN-cryptother" }, unavailable, false},
		{"second kernel slave", func(f *ephemeralFixture) { f.slaves = []string{"vda4", "vda3"} }, invalid, false},
		{"slave is not the observed parent", func(f *ephemeralFixture) { f.slaves = []string{"vda3"} }, invalid, false},
		{"slaves unreadable", func(f *ephemeralFixture) { f.slaves, f.slavesErr = nil, fs.ErrPermission },
			inventoryv1.CollectionStatus_COLLECTION_STATUS_PERMISSION_DENIED, false},
		{"null cipher configured", func(f *ephemeralFixture) {
			f.crypttab = strings.Replace(f.crypttab, "aes-xts-plain64", "cipher_null-ecb", 1)
		}, unavailable, false},
		{"urandom key with luks mode", func(f *ephemeralFixture) {
			f.crypttab = strings.Replace(f.crypttab, "swap,plain", "swap,luks", 1)
		}, unavailable, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := plain
			tc.mutate(&f)
			got := f.collect(t).Identity.EphemeralKey
			if got.GetStatus() != tc.status || got.GetValue() != tc.value {
				t.Fatalf("ephemeral_key = %v, want status %s value %t", got, tc.status, tc.value)
			}
		})
	}
}

// Storage reaches the server only through the sandboxed root helper, so the
// ephemeral-key proof's readers must be wired there; a missing reader would
// leave every random-key swap unproven on real machines.
func TestRootObservationSourcesCarryEphemeralKeyReaders(t *testing.T) {
	s := rootObservationSources()
	if s.readFile == nil || s.readDir == nil || s.openBlock == nil || s.run == nil {
		t.Fatalf("root observation sources lack an ephemeral-key reader: readFile %t readDir %t openBlock %t run %t",
			s.readFile != nil, s.readDir != nil, s.openBlock != nil, s.run != nil)
	}
}
