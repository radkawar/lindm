//go:build linux

package nativehelper

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/privatecustody"
)

func TestHelperChannelRejectsCapacityAndWrongShape(t *testing.T) {
	var oversized [4]byte
	binary.BigEndian.PutUint32(oversized[:], channelLimit+1)
	if _, err := receiveMessage(bytes.NewReader(oversized[:])); err == nil {
		t.Fatal("unbounded helper message accepted")
	}
	if _, err := receiveMessage(bytes.NewReader([]byte{0, 0, 0, 0})); err == nil {
		t.Fatal("empty helper message accepted")
	}
	message := &agentv1.NativeHelperMessage{Message: &agentv1.NativeHelperMessage_Ready{Ready: &agentv1.NativeHelperReady{RequestSha256: bytes.Repeat([]byte{1}, 32), Nonce: bytes.Repeat([]byte{2}, 32)}}}
	var channel bytes.Buffer
	if err := sendMessage(&channel, message); err != nil {
		t.Fatal(err)
	}
	got, err := receiveMessage(&channel)
	if err != nil || !proto.Equal(got, message) {
		t.Fatalf("exact private helper message lost: %v", err)
	}
	message.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	if err := sendMessage(&channel, message); err == nil {
		t.Fatal("unknown helper field accepted")
	}
}

func TestHelperRecordsAreExclusiveAndProtected(t *testing.T) {
	state := t.TempDir()
	// Protected state is exactly 0700 regardless of the test umask.
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	const installation = "341e26dd-13d9-45ae-bdc2-7a2c21d45d1e"
	if err := os.WriteFile(filepath.Join(state, "installation"), []byte(installation+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	custody, err := privatecustody.Initialize(state, installation)
	if err != nil {
		t.Fatal(err)
	}
	custody.Close()
	directory, err := resourceDirectory(state, "packageprovider", "a2bca405-36e9-4a43-b5b5-d0b82a05e551", true)
	if err != nil {
		t.Fatal(err)
	}
	message := &agentv1.NativePackageStagingCancellation{ActionId: "a2bca405-36e9-4a43-b5b5-d0b82a05e551"}
	encoded, err := encodeRecord(message)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeProtected(directory, "cancelled.pb", encoded); err != nil {
		t.Fatal(err)
	}
	if err := writeProtected(directory, "cancelled.pb", encoded); !errors.Is(err, os.ErrExist) {
		t.Fatalf("one-use record overwritten: %v", err)
	}
	got := new(agentv1.NativePackageStagingCancellation)
	if _, err := readRecord(directory, "cancelled.pb", got); err != nil || !proto.Equal(got, message) {
		t.Fatalf("protected receipt lost: %v", err)
	}
	if err := notCancelled(directory); err == nil {
		t.Fatal("durable cancellation tombstone ignored")
	}
	if err := os.Chmod(filepath.Join(directory, "cancelled.pb"), 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecord(directory, "cancelled.pb", got); err == nil {
		t.Fatal("untrusted mutable receipt accepted")
	}
}

func TestPackageUnitsDoNotWidenExecutorOrDownloadDuringApply(t *testing.T) {
	for _, phase := range []string{"prepare", "apply"} {
		properties := transientProperties("/var/lib/lindm/executor/packageprovider/a2bca405-36e9-4a43-b5b5-d0b82a05e551", "a2bca405-36e9-4a43-b5b5-d0b82a05e551", phase)
		values := make(map[string]any)
		for _, property := range properties {
			values[property.Name] = property.Value.Value()
		}
		// Package scriptlets need SELinux domain transitions during apply.
		if values["Restart"] != "no" || values["ProtectSystem"] != "strict" || values["PrivateDevices"] != true || values["NoNewPrivileges"] != (phase == "prepare") {
			t.Fatalf("unsafe package helper confinement for %s", phase)
		}
		command := unitValue[[]unitExec](t, values, "ExecStart")
		if len(command) != 1 || command[0].Path != helperExecutable || command[0].Arguments[1] != "package-transaction" {
			t.Fatal("transient unit has arbitrary executable")
		}
		if strings.Contains(strings.Join(command[0].Arguments, " "), "signing") {
			t.Fatal("operation material leaked into argv")
		}
		if values["PrivateNetwork"] != (phase == "apply") {
			t.Fatal("apply unit permits native network downloads")
		}
		if phase == "prepare" && len(unitValue[[]string](t, values, "ReadWritePaths")) != 1 {
			t.Fatal("preflight can modify native package database/payload")
		}
	}
}

// zypper exits 5 ("The target filesystem is mounted as read-only") unless /
// itself is writable; only its apply unit gains /, never staging or DNF.
func TestZypperApplyUnitKeepsRootWritable(t *testing.T) {
	const directory = "/var/lib/lindm/executor/packageprovider/a2bca405-36e9-4a43-b5b5-d0b82a05e551"
	for _, tc := range []struct {
		product  *resourcev1.PlatformProduct
		phase    string
		writable bool
	}{
		{&resourcev1.PlatformProduct{OsId: "opensuse-tumbleweed", Version: "20261007"}, "apply", true},
		{&resourcev1.PlatformProduct{OsId: "opensuse-tumbleweed", Version: "20261007"}, "prepare", false},
		{&resourcev1.PlatformProduct{OsId: "fedora", Version: "43"}, "apply", false},
	} {
		request := &agentv1.NativePackageTransactionRequest{TransactionId: "a2bca405-36e9-4a43-b5b5-d0b82a05e551", Platform: tc.product}
		values := make(map[string]any)
		for _, property := range packageProperties(directory, request, tc.phase) {
			values[property.Name] = property.Value.Value()
		}
		paths := unitValue[[]string](t, values, "ReadWritePaths")
		if slices.Contains(paths, "/") != tc.writable || values["ProtectSystem"] != "strict" || values["ProtectHome"] != "yes" {
			t.Fatalf("%s %s: ReadWritePaths %q", tc.product.GetOsId(), tc.phase, paths)
		}
	}
}

func TestPackageEffectPermitExpiresOnBootTime(t *testing.T) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		t.Fatal(err)
	}
	permit := &agentv1.NativeEffectPermit{BootId: strings.TrimSpace(string(boot)), StartDeadlineBoottimeNs: uint64(now.Nano())}
	if err := validatePermit(permit); err == nil {
		t.Fatal("expired helper permit accepted")
	}
	permit.StartDeadlineBoottimeNs += uint64(10_000_000_000)
	if err := validatePermit(permit); err != nil {
		t.Fatalf("fresh same-boot permit rejected: %v", err)
	}
	permit.BootId = "a2bca405-36e9-4a43-b5b5-d0b82a05e551"
	if err := validatePermit(permit); err == nil {
		t.Fatal("foreign boot helper permit accepted")
	}
}
