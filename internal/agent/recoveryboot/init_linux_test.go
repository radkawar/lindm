// SPDX-License-Identifier: Apache-2.0

//go:build linux

package recoveryboot

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	testStateUUID = "12345678-1234-1234-1234-123456789abc"
	testESPUUID   = "103C-DA09"
)

var errInjected = errors.New("injected failure")

// fakeInit records every privileged effect in order. failAt and panicAt
// select the 1-based recorded operation that fails or panics.
type fakeInit struct {
	t           *testing.T
	root        string
	ops         []string
	failAt      int
	panicAt     int
	heads       map[string][]byte
	devices     map[string]uint64
	sleeps      int
	now         time.Time
	poweroffErr error
	recovery    func() error
}

var _ initSystem = (*fakeInit)(nil)

func (f *fakeInit) record(format string, args ...any) error {
	f.ops = append(f.ops, fmt.Sprintf(format, args...))
	switch len(f.ops) {
	case f.panicAt:
		panic("injected panic")
	case f.failAt:
		return errInjected
	}
	return nil
}

func (f *fakeInit) Mount(source, target, fstype string, flags uintptr, data string) error {
	return f.record("mount %s %s %s %#x %q", source, target, fstype, flags, data)
}
func (f *fakeInit) Unmount(target string) error        { return f.record("umount %s", target) }
func (f *fakeInit) RebindConsole(console string) error { return f.record("console %s", console) }
func (f *fakeInit) LoadModule(path string) error       { return f.record("module %s", path) }
func (f *fakeInit) KernelRelease() (string, error)     { return "6.8.0-45-generic", nil }
func (f *fakeInit) SetMemlockUnlimited() error         { return f.record("memlock unlimited") }
func (f *fakeInit) LinkUp(iface string) error          { return f.record("link up %s", iface) }
func (f *fakeInit) FlushAddresses(iface string) error  { return f.record("flush %s", iface) }
func (f *fakeInit) TransactionID() (uint32, error)     { return testXID, f.record("xid") }
func (f *fakeInit) Sleep(time.Duration)                { f.sleeps++ }
func (f *fakeInit) Now() time.Time                     { return f.now }
func (f *fakeInit) ConfigureIPv4(iface string, address, netmask [4]byte) error {
	return f.record("address %s %v/%v", iface, address, netmask)
}
func (f *fakeInit) ReplaceDefaultRoute(iface string, gateway [4]byte) error {
	return f.record("route %s via %v", iface, gateway)
}

func (f *fakeInit) ReadBlockHead(path string, device uint64) ([]byte, error) {
	head, ok := f.heads[path]
	if !ok {
		return nil, unix.ENXIO
	}
	if f.devices[path] != device {
		f.t.Fatalf("%s probed with device %d", path, device)
	}
	return head, nil
}

func (f *fakeInit) OpenDHCP(iface string) (dhcpSocket, error) {
	if err := f.record("dhcp %s", iface); err != nil {
		return nil, err
	}
	return &fakeDHCPServer{}, nil
}

func (f *fakeInit) RunRecovery() error {
	if err := f.record("recovery-run"); err != nil {
		return err
	}
	if f.recovery != nil {
		return f.recovery()
	}
	return nil
}

func (f *fakeInit) PowerOff() error {
	f.ops = append(f.ops, "poweroff")
	return f.poweroffErr
}

// fakeDHCPServer answers DISCOVER with OFFER and REQUEST with ACK.
type fakeDHCPServer struct {
	pending []byte
}

func (s *fakeDHCPServer) Send(packet []byte) error {
	xid := binary.BigEndian.Uint32(packet[4:])
	mac := packet[28:34]
	kind := dhcpOffer
	if bytes.Contains(packet[dhcpMinimumReply:], []byte{dhcpOptionMessageType, 1, dhcpRequest}) {
		kind = dhcpAck
	}
	s.pending = testDHCPReply(xid, mac, testLeased,
		dhcpOption{dhcpOptionMessageType, []byte{byte(kind)}},
		dhcpOption{dhcpOptionServerID, testServer[:]},
		dhcpOption{dhcpOptionSubnetMask, []byte{255, 255, 255, 0}},
		dhcpOption{dhcpOptionRouter, testServer[:]},
		dhcpOption{dhcpOptionDNS, []byte{10, 0, 2, 3}})
	return nil
}

func (s *fakeDHCPServer) Receive(buffer []byte, _ time.Time) (int, error) {
	if s.pending == nil {
		return 0, errDHCPTimeout
	}
	n := copy(buffer, s.pending)
	s.pending = nil
	return n, nil
}

func (s *fakeDHCPServer) Close() error { return nil }

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, data := range files {
		target := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func fatHead(serial uint32) []byte {
	head := make([]byte, blockProbeBytes)
	binary.LittleEndian.PutUint16(head[11:], 512)
	head[13], head[16] = 8, 2
	binary.LittleEndian.PutUint16(head[14:], 32)
	head[66] = 0x29
	binary.LittleEndian.PutUint32(head[67:], serial)
	copy(head[82:], "FAT32   ")
	head[510], head[511] = 0x55, 0xaa
	return head
}

func ext4Head(uuid [16]byte) []byte {
	head := make([]byte, blockProbeBytes)
	binary.LittleEndian.PutUint16(head[1024+0x38:], 0xef53)
	copy(head[1024+0x68:], uuid[:])
	return head
}

var testStateBytes = [16]byte{0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}

// newInitFixture builds an initramfs-shaped root with sysfs, efivarfs, ESP and
// network views, using real files for every non-privileged read and write.
func newInitFixture(t *testing.T, params initParams) (*initRun, *fakeInit) {
	t.Helper()
	root := t.TempDir()
	entry := "lindm-recovery-" + testActionID + ".efi"
	writeTree(t, root, map[string]string{
		initParamsPath:                        params.render(),
		moduleLoadPath:                        "virtio_pci\nnvme\nvfat\n",
		"etc/lindm/image-signing.pem":         "certificate",
		"sys/class/block/sda/dev":             "8:0\n",
		"sys/class/block/sda1/dev":            "8:1\n",
		"sys/class/block/sdb/dev":             "8:16\n",
		"sys/class/block/sr0/dev":             "11:0\n",
		"sys/class/net/lo/type":               "772\n",
		"sys/class/net/eth0/type":             "1\n",
		"sys/class/net/eth0/address":          "52:54:00:12:34:56\n",
		"run/recovery-esp/EFI/Linux/" + entry: "signed recovery image",
		"run/recovery-esp/EFI/Linux/lindm-recovery-" + testActionID + ".capsule": "capsule",
	})
	efivar := filepath.Join(root, strings.TrimPrefix(loaderEntrySelected, "/"))
	if err := os.MkdirAll(filepath.Dir(efivar), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(efivar, loaderEntryBytes(entry, true), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	fake := &fakeInit{
		t: t, root: root, now: time.Unix(1700000000, 0),
		heads:   map[string][]byte{"/dev/sda": make([]byte, blockProbeBytes), "/dev/sda1": fatHead(0x103cda09), "/dev/sdb": ext4Head(testStateBytes)},
		devices: map[string]uint64{"/dev/sda": unix.Mkdev(8, 0), "/dev/sda1": unix.Mkdev(8, 1), "/dev/sdb": unix.Mkdev(8, 16)},
	}
	return &initRun{root: root, sys: fake, log: &bytes.Buffer{}}, fake
}

func expectedInitOps(params initParams) []string {
	ops := []string{
		`mount devtmpfs /dev devtmpfs 0x0 ""`,
		"console /dev/console",
		`mount proc /proc proc 0x0 ""`,
		`mount sysfs /sys sysfs 0x0 ""`,
		`mount tmpfs /run tmpfs 0x6 "mode=0755"`,
		"module /lib/modules/6.8.0-45-generic/virtio_pci.ko",
		"module /lib/modules/6.8.0-45-generic/nvme.ko",
		"module /lib/modules/6.8.0-45-generic/vfat.ko",
		`mount efivarfs /sys/firmware/efi/efivars efivarfs 0x0 ""`,
	}
	if params.StateUUID != "" {
		ops = append(ops, `mount /dev/sdb /run/lindm-recovery ext4 0xe ""`)
	}
	switch params.Mode {
	case initModeUKI:
		ops = append(ops, `mount /dev/sda1 /run/recovery-esp vfat 0xf ""`, "umount /run/recovery-esp")
	case initModeMeasuredGRUB:
		ops = append(ops, `mount securityfs /sys/kernel/security securityfs 0x0 ""`)
	}
	return append(ops,
		"link up lo", "link up eth0", "flush eth0", "xid", "dhcp eth0",
		"address eth0 [10 0 2 15]/[255 255 255 0]", "route eth0 via [10 0 2 2]",
		"memlock unlimited", "recovery-run", "poweroff")
}

func consoleText(t *testing.T, run *initRun) string {
	t.Helper()
	console, ok := run.log.(*bytes.Buffer)
	if !ok {
		t.Fatal("fixture console is not a buffer")
	}
	return console.String()
}

func fileModeAndData(t *testing.T, name string) (os.FileMode, string) {
	t.Helper()
	info, err := os.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode(), string(data)
}

func TestRecoveryInitSequenceAndHandoff(t *testing.T) {
	for name, params := range map[string]initParams{
		"uki off-target": {Mode: initModeUKI, ESPUUID: testESPUUID, StateUUID: testStateUUID},
		"uki tpm":        {Mode: initModeUKI, ESPUUID: strings.ToLower(testESPUUID)},
		"measured grub":  {Mode: initModeMeasuredGRUB, StateUUID: testStateUUID},
	} {
		t.Run(name, func(t *testing.T) {
			run, fake := newInitFixture(t, params)
			state := filepath.Join(fake.root, "run/lindm-recovery")
			if err := os.MkdirAll(state, 0755); err != nil {
				t.Fatal(err)
			}
			// A previous boot's replaceable link must be replaced, not followed.
			outside := filepath.Join(fake.root, "outside")
			if err := os.WriteFile(outside, []byte("unrelated"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(state, "booted.efi")); err != nil {
				t.Fatal(err)
			}
			fake.recovery = func() error {
				if params.Mode == initModeUKI {
					want := map[string]string{"booted.efi": "signed recovery image", "image-signing.pem": "certificate"}
					if params.StateUUID == "" {
						want["capsule.pb"] = "capsule"
					}
					for file, content := range want {
						if mode, data := fileModeAndData(t, filepath.Join(state, file)); mode != 0400 || data != content {
							t.Fatalf("%s handed off as %v %q", file, mode, data)
						}
					}
				}
				if _, err := os.Stat(filepath.Join(state, "capsule.pb")); (params.StateUUID == "" && params.Mode == initModeUKI) == os.IsNotExist(err) {
					t.Fatalf("capsule presence wrong for %+v: %v", params, err)
				}
				info, err := os.Stat(state)
				if err != nil {
					t.Fatal(err)
				}
				if wantMode := os.FileMode(0700); params.StateUUID == "" && info.Mode().Perm() != wantMode {
					t.Fatalf("TPM state directory mode %v", info.Mode().Perm())
				}
				if _, resolver := fileModeAndData(t, filepath.Join(fake.root, "etc/resolv.conf")); resolver != "nameserver 10.0.2.3\n" {
					t.Fatalf("resolver = %q", resolver)
				}
				return nil
			}
			run.main()
			if want := expectedInitOps(params); !slices.Equal(fake.ops, want) {
				t.Fatalf("operations:\n%s\nwant:\n%s", strings.Join(fake.ops, "\n"), strings.Join(want, "\n"))
			}
			if _, data := fileModeAndData(t, outside); data != "unrelated" {
				t.Fatal("handoff followed a state-directory symlink")
			}
		})
	}
}

// Every recorded effect is fatal: the next and final effect is poweroff,
// including injected panics and a recovery-run failure or success.
func TestRecoveryInitEveryFailurePowersOff(t *testing.T) {
	params := initParams{Mode: initModeUKI, ESPUUID: testESPUUID, StateUUID: testStateUUID}
	steps := len(expectedInitOps(params)) - 1
	for _, inject := range []string{"fail", "panic"} {
		for step := 1; step <= steps; step++ {
			t.Run(fmt.Sprintf("%s-%d", inject, step), func(t *testing.T) {
				run, fake := newInitFixture(t, params)
				if inject == "fail" {
					fake.failAt = step
				} else {
					fake.panicAt = step
				}
				run.main()
				if len(fake.ops) != step+1 || fake.ops[step] != "poweroff" {
					t.Fatalf("after failing %q: %s", fake.ops[step-1], strings.Join(fake.ops[step:], ", "))
				}
				if !strings.Contains(consoleText(t, run), "lindm-recovery-init:") {
					t.Fatal("failure was not reported on the console")
				}
			})
		}
	}
	run, fake := newInitFixture(t, params)
	fake.recovery = func() error { return errors.New("recovery-run exit status 1") }
	fake.poweroffErr = unix.EPERM
	run.main()
	if fake.ops[len(fake.ops)-1] != "poweroff" || !strings.Contains(consoleText(t, run), "poweroff: operation not permitted") {
		t.Fatalf("refused poweroff not reported: %v", fake.ops)
	}
}

func TestRecoveryInitRefusesUnsafeBootSelection(t *testing.T) {
	params := initParams{Mode: initModeUKI, ESPUUID: testESPUUID, StateUUID: testStateUUID}
	for name, change := range map[string]func(t *testing.T, run *initRun, fake *fakeInit){
		"missing parameters": func(t *testing.T, run *initRun, fake *fakeInit) {
			if err := os.Remove(filepath.Join(fake.root, initParamsPath)); err != nil {
				t.Fatal(err)
			}
		},
		"malformed module list": func(t *testing.T, run *initRun, fake *fakeInit) {
			writeTree(t, fake.root, map[string]string{moduleLoadPath: "nvme"})
		},
		"invalid selected entry": func(t *testing.T, run *initRun, fake *fakeInit) {
			efivar := filepath.Join(fake.root, strings.TrimPrefix(loaderEntrySelected, "/"))
			if err := os.WriteFile(efivar, loaderEntryBytes("lindm-recovery-../../etc/shadow.efi", true), 0644); err != nil {
				t.Fatal(err)
			}
		},
		"ambiguous ESP": func(t *testing.T, run *initRun, fake *fakeInit) {
			writeTree(t, fake.root, map[string]string{"sys/class/block/sdc/dev": "8:32\n"})
			fake.heads["/dev/sdc"], fake.devices["/dev/sdc"] = fatHead(0x103cda09), unix.Mkdev(8, 32)
		},
		"ambiguous state": func(t *testing.T, run *initRun, fake *fakeInit) {
			writeTree(t, fake.root, map[string]string{"sys/class/block/sdc/dev": "8:32\n"})
			fake.heads["/dev/sdc"], fake.devices["/dev/sdc"] = ext4Head(testStateBytes), unix.Mkdev(8, 32)
		},
		"oversized image": func(t *testing.T, run *initRun, fake *fakeInit) {
			image := filepath.Join(fake.root, "run/recovery-esp/EFI/Linux/lindm-recovery-"+testActionID+".efi")
			if err := os.Truncate(image, maxAuthenticodeImageBytes+1); err != nil {
				t.Fatal(err)
			}
		},
		"linked image": func(t *testing.T, run *initRun, fake *fakeInit) {
			image := filepath.Join(fake.root, "run/recovery-esp/EFI/Linux/lindm-recovery-"+testActionID+".efi")
			if err := os.Remove(image); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(fake.root, "etc/lindm/image-signing.pem"), image); err != nil {
				t.Fatal(err)
			}
		},
		"non-ethernet only": func(t *testing.T, run *initRun, fake *fakeInit) {
			writeTree(t, fake.root, map[string]string{"sys/class/net/eth0/type": "65534\n"})
		},
		"hostile interface name": func(t *testing.T, run *initRun, fake *fakeInit) {
			writeTree(t, fake.root, map[string]string{"sys/class/net/a b/type": "1\n"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			run, fake := newInitFixture(t, params)
			change(t, run, fake)
			run.main()
			if slices.Contains(fake.ops, "recovery-run") || fake.ops[len(fake.ops)-1] != "poweroff" {
				t.Fatalf("unsafe selection reached recovery: %v", fake.ops)
			}
		})
	}
}

func TestRecoveryInitFilesystemDiscoveryIsBounded(t *testing.T) {
	run, fake := newInitFixture(t, initParams{Mode: initModeUKI, ESPUUID: testESPUUID, StateUUID: testStateUUID})
	delete(fake.heads, "/dev/sdb")
	run.main()
	if fake.sleeps != filesystemAttempts || fake.ops[len(fake.ops)-1] != "poweroff" || slices.ContainsFunc(fake.ops, func(op string) bool { return strings.Contains(op, "ext4") }) {
		t.Fatalf("missing state volume: %d sleeps, ops %v", fake.sleeps, fake.ops)
	}
}

func TestProbeFilesystemIdentifiers(t *testing.T) {
	if id, ok := probeFilesystem(ext4Head(testStateBytes), filesystemExt4); !ok || id != testStateUUID {
		t.Fatalf("ext4 = %q %v", id, ok)
	}
	if id, ok := probeFilesystem(fatHead(0x103cda09), filesystemVFAT); !ok || id != testESPUUID {
		t.Fatalf("vfat = %q %v", id, ok)
	}
	fat16 := make([]byte, blockProbeBytes)
	binary.LittleEndian.PutUint16(fat16[11:], 512)
	fat16[13], fat16[16], fat16[14], fat16[38] = 4, 2, 1, 0x29
	binary.LittleEndian.PutUint32(fat16[39:], 0xabcd1234)
	copy(fat16[54:], "FAT16   ")
	fat16[510], fat16[511] = 0x55, 0xaa
	if id, ok := probeFilesystem(fat16, filesystemVFAT); !ok || id != "ABCD-1234" {
		t.Fatalf("fat16 = %q %v", id, ok)
	}
	for name, head := range map[string][]byte{
		"short":         fatHead(1)[:1024],
		"no signature":  func() []byte { h := fatHead(1); h[511] = 0; return h }(),
		"bad sector":    func() []byte { h := fatHead(1); h[11] = 7; return h }(),
		"bad cluster":   func() []byte { h := fatHead(1); h[13] = 3; return h }(),
		"no ext sig":    func() []byte { h := fatHead(1); h[66] = 0; return h }(),
		"ext4 as vfat":  ext4Head(testStateBytes),
		"zeroed device": make([]byte, blockProbeBytes),
	} {
		if id, ok := probeFilesystem(head, filesystemVFAT); ok {
			t.Fatalf("%s probed as vfat %q", name, id)
		}
	}
	if _, ok := probeFilesystem(fatHead(1), filesystemExt4); ok {
		t.Fatal("vfat probed as ext4")
	}
}
