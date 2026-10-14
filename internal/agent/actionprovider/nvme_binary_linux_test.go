// SPDX-License-Identifier: Apache-2.0

//go:build linux

package actionprovider

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"testing"
)

// Pure protocol fixtures only. No NVMe device, ioctl, native executable or host
// block device is opened by these tests; native qualification lives in vmlab.
// fakeNVMeAdmin adapts a protocol fixture to the admin ioctl seam: reply's
// bytes are copied into the read-back buffer. No device or ioctl is touched.
func fakeNVMeAdmin(reply func(command nvmeAdminCommand, length int) ([]byte, uint32, error)) nvmeAdminSubmitter {
	return func(_ *os.File, command *nvmeAdminCommand, data []byte) (uint32, error) {
		out, status, err := reply(*command, len(data))
		copy(data, out)
		return status, err
	}
}

func nvmeControllerFixture() []byte {
	data := make([]byte, nvmeIdentifyBytes)
	binary.LittleEndian.PutUint16(data[0:2], 0x1b36)
	binary.LittleEndian.PutUint16(data[2:4], 0x1234)
	copy(data[4:24], []byte("test-controller     "))
	copy(data[24:64], bytes.Repeat([]byte{' '}, 40))
	copy(data[24:64], []byte("disposable NVMe fixture"))
	copy(data[64:72], []byte("1.0     "))
	binary.LittleEndian.PutUint16(data[78:80], 7)
	binary.LittleEndian.PutUint16(data[256:258], 2)
	binary.LittleEndian.PutUint32(data[328:332], 3)
	binary.LittleEndian.PutUint32(data[516:520], 1)
	data[524] = 4
	return data
}

func nvmeNamespaceFixture() []byte {
	data := make([]byte, nvmeIdentifyBytes)
	binary.LittleEndian.PutUint64(data[:8], 8192)
	binary.LittleEndian.PutUint64(data[8:16], 8192)
	data[120] = 0x12
	data[127] = 0x34
	data[130] = 9
	return data
}

func nvmeNamespaceListFixture(ids ...uint32) []byte {
	data := make([]byte, nvmeIdentifyBytes)
	for i, id := range ids {
		binary.LittleEndian.PutUint32(data[i*4:i*4+4], id)
	}
	return data
}

func nvmeSanitizeLogFixture(progress, status uint16, command uint32) []byte {
	data := make([]byte, nvmeSanitizeLogBytes)
	binary.LittleEndian.PutUint16(data[:2], progress)
	binary.LittleEndian.PutUint16(data[2:4], status)
	binary.LittleEndian.PutUint32(data[4:8], command)
	return data
}

func TestNVMeControllerParsing(t *testing.T) {
	controller, err := parseNVMeController(nvmeControllerFixture())
	if err != nil || controller.vid != 0x1b36 || controller.ssvid != 0x1234 || controller.serial != "test-controller" || controller.id != 7 || controller.oacs != 2 || controller.sanicap != 3 || controller.fna != 4 {
		t.Fatalf("identify controller: %+v %v", controller, err)
	}
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return b[:4095] },
		func(b []byte) []byte { return append(b, 0) },
		func(b []byte) []byte { clear(b[0:2]); return b },
		func(b []byte) []byte { b[4] = 0; return b },
		func(b []byte) []byte { clear(b[4:24]); return b },
		func(b []byte) []byte { b[76] = 1; return b },
		func(b []byte) []byte { b[76] = 2; return b },
		func(b []byte) []byte { b[76] = 4; return b },
		func(b []byte) []byte { b[516] = 0; return b },
	} {
		if _, err := parseNVMeController(mutate(nvmeControllerFixture())); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unsafe controller accepted: %v", err)
		}
	}
}

func TestNVMeNamespaceParsingAndStableDigest(t *testing.T) {
	data := nvmeNamespaceFixture()
	namespace, err := parseNVMeNamespace(data)
	if err != nil || namespace.size != 4<<20 || namespace.lbaf != 0 || namespace.shift != 9 || !namespace.matchesWWN("eui.1200000000000034") || namespace.matchesWWN("eui.1200000000000035") {
		t.Fatalf("identify namespace: %+v %v", namespace, err)
	}
	data[16] = 99   // NUSE is not identity.
	data[32] = 0x80 // Supported FPI, no format in progress.
	after, err := parseNVMeNamespace(data)
	if err != nil || namespace.digest != after.digest {
		t.Fatalf("mutable counters changed identity: %v", err)
	}
	data[127]++
	after, err = parseNVMeNamespace(data)
	if err != nil || namespace.digest == after.digest {
		t.Fatalf("changed EUI64 retained identity: %v", err)
	}
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return b[:4095] },
		func(b []byte) []byte { b[26] = 0x10; return b },
		func(b []byte) []byte { b[26] = 1; return b },
		func(b []byte) []byte { b[29] = 1; return b },
		func(b []byte) []byte { b[30] = 1; return b },
		func(b []byte) []byte { b[32] = 0x81; return b },
		func(b []byte) []byte { b[128] = 1; return b },
		func(b []byte) []byte { b[130] = 13; return b },
		func(b []byte) []byte { clear(b[:8]); return b },
		func(b []byte) []byte { binary.LittleEndian.PutUint64(b[:8], ^uint64(0)); return b },
	} {
		if _, err := parseNVMeNamespace(mutate(nvmeNamespaceFixture())); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unsafe namespace accepted: %v", err)
		}
	}
}

func TestNVMeNamespaceWithoutNIDsRetainsLayout(t *testing.T) {
	data := nvmeNamespaceFixture()
	clear(data[104:128])
	data[25], data[26], data[134] = 1, 1, 9
	namespace, err := parseNVMeNamespace(data)
	if err != nil || namespace.size != 4<<20 || namespace.lbaf != 1 || namespace.shift != 9 || namespace.matchesWWN("eui.0000000000000000") {
		t.Fatalf("absent NID layout: %+v %v", namespace, err)
	}
}

func TestNVMeNamespaceListRejectsPartialAmbiguousInventory(t *testing.T) {
	ids, err := parseNVMeNamespaceList(nvmeNamespaceListFixture(1, 4, 19))
	if err != nil || len(ids) != 3 || ids[2] != 19 {
		t.Fatalf("namespace inventory: %v %v", ids, err)
	}
	tests := [][]byte{
		nvmeNamespaceListFixture(),
		nvmeNamespaceListFixture(1, 1),
		nvmeNamespaceListFixture(2, 1),
		nvmeNamespaceListFixture(1, 0, 2),
		nvmeNamespaceListFixture(^uint32(0)),
		nvmeNamespaceListFixture(1)[:4095],
	}
	tooMany := make([]uint32, nvmeMaximumNamespaces+1)
	for i := range tooMany {
		tooMany[i] = uint32(i + 1)
	}
	tests = append(tests, nvmeNamespaceListFixture(tooMany...))
	for _, data := range tests {
		if _, err := parseNVMeNamespaceList(data); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("ambiguous namespace inventory accepted: %v", err)
		}
	}
}

func TestNVMeSanitizeCompletionRequiresExactRetainedCommand(t *testing.T) {
	status, err := parseNVMeSanitizeStatus(nvmeSanitizeLogFixture(0xffff, 0x101, 2))
	if err != nil || !status.complete(2) || status.complete(4) {
		t.Fatalf("completion readback: %+v %v", status, err)
	}
	for _, data := range [][]byte{
		nvmeSanitizeLogFixture(100, 2, 2),
		nvmeSanitizeLogFixture(0xffff, 3, 2),
		nvmeSanitizeLogFixture(0xffff, 1, 2),
		nvmeSanitizeLogFixture(0xffff, 0x104, 2),
		nvmeSanitizeLogFixture(0xffff, 0x101, 4),
		nvmeSanitizeLogFixture(0xffff, 0x109, 2),
	} {
		status, err := parseNVMeSanitizeStatus(data)
		if err != nil || status.complete(2) {
			t.Fatalf("false completion: %+v %v", status, err)
		}
	}
	for _, data := range [][]byte{nil, make([]byte, 511), nvmeSanitizeLogFixture(0, 1, 2), nvmeSanitizeLogFixture(0xffff, 7, 2), nvmeSanitizeLogFixture(0xffff, 0x8101, 2)} {
		if _, err := parseNVMeSanitizeStatus(data); !errors.Is(err, ErrNotVerified) {
			t.Fatalf("malformed log accepted: %v", err)
		}
	}
}
