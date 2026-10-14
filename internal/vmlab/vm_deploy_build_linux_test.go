// SPDX-License-Identifier: Apache-2.0
//go:build linux

package vmlab

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestColdReleaseExportRejectsPlaintextCustodyAndEscapingMembers(t *testing.T) {
	for _, name := range []string{"keys/custody.age", "keys/attestation.pub", "keys/pins.sig", "first/release.json", "newer/agent-repository/release.dsse.json", "production-custody-passphrase.age", "keys.log.age"} {
		if !coldReleaseExportMember(name) {
			t.Errorf("required encrypted/public member rejected: %s", name)
		}
	}
	for _, name := range []string{"../outside", "/root/private", "keys/attestation.pem", "keys/package-signing-private.asc", "keys/subdir/custody.age", "source/.git/config", "passphrase.txt", "first/../../private", "first\\secret"} {
		if coldReleaseExportMember(name) {
			t.Errorf("unsafe export accepted: %s", name)
		}
	}
}

func TestColdReleaseRequiresStrictlyNewerNumericVersions(t *testing.T) {
	for _, pair := range [][2]string{{"0.2.0", "0.2.1"}, {"0.9.9", "1.0.0"}} {
		if !coldReleaseVersionsValid(pair[0], pair[1]) {
			t.Errorf("newer pair rejected: %v", pair)
		}
	}
	for _, pair := range [][2]string{{"0.2.1", "0.2.0"}, {"0.2.0", "0.2.0"}, {"01.2.0", "2.0.0"}, {"0.2.0", "0.2.1; echo unsafe"}} {
		if coldReleaseVersionsValid(pair[0], pair[1]) {
			t.Errorf("nonnewer/unsafe pair accepted: %v", pair)
		}
	}
}

func TestColdReleaseOverlayBudgetDoesNotResizeOtherLanes(t *testing.T) {
	for _, test := range []struct {
		base, minimum, want int64
	}{
		{2 << 30, 0, minGuestDiskBytes},
		{16 << 30, 0, 16 << 30},
		{2 << 30, coldReleaseDiskBytes, 32 << 30},
		{64 << 30, coldReleaseDiskBytes, 64 << 30},
	} {
		got, err := guestOverlayBytes(test.base, test.minimum)
		if err != nil || got != test.want {
			t.Fatalf("overlay base=%d minimum=%d got=%d want=%d: %v", test.base, test.minimum, got, test.want, err)
		}
	}
	for _, minimum := range []int64{-1, (32 << 30) + 1} {
		if _, err := guestOverlayBytes(2<<30, minimum); err == nil {
			t.Fatalf("accepted overlay minimum beyond the admitted budget: %d", minimum)
		}
	}
	hardware, err := resolveVMHardware(&VMHardwareOptions{minimumDiskBytes: coldReleaseDiskBytes}, "amd64")
	if err != nil || hardware.minimumDiskBytes != coldReleaseDiskBytes {
		t.Fatalf("hardware resolution lost the cold-only overlay budget: %v", err)
	}
}

func TestColdReleaseScopeCannotClaimNativeLifecycleQualification(t *testing.T) {
	body, err := json.Marshal(VMDeployBuildResult{Scope: coldReleaseScope, Passed: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"scope":"production-cold-release-build-only"`)) || !bytes.Contains(body, []byte(`"lifecycle_qualified":false`)) {
		t.Fatal("builder mislabeled as a full native deployment")
	}
}

func TestColdReleaseLogDrainsExcessWithoutRetainingPlaintext(t *testing.T) {
	var destination bytes.Buffer
	writer := &coldReleaseLogWriter{writer: &destination, remaining: 4}
	count, err := writer.Write([]byte("bounded-secret-output"))
	if err != nil || count != len("bounded-secret-output") || destination.String() != "boun" || !writer.exceeded {
		t.Fatalf("wrong bounded write: %d %v", count, err)
	}
	if _, err := writer.Write([]byte(strings.Repeat("x", 100))); err != nil || destination.Len() != 4 {
		t.Fatalf("excess retained or not drained: %v", err)
	}
}
