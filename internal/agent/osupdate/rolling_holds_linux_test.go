//go:build linux

package osupdate

import (
	"errors"
	"testing"
)

func TestPacmanEffectiveExclusionsRefuseWholeSystemUpgrade(t *testing.T) {
	if err := rejectPacmanExclusions(nil); err != nil {
		t.Fatal(err)
	}
	// pacman-conf's source-derived verbose format is identical whether the
	// directive is in the main file or resolved through Include/globs. These
	// parser cases do not claim native Include resolution was exercised.
	for _, output := range []string{"IgnorePkg = linux\n", "IgnoreGroup = desktop\n", "IgnorePkg = linux*\nIgnoreGroup = xorg\n"} {
		if err := rejectPacmanExclusions([]byte(output)); !errors.Is(err, errRollingNativeHolds) {
			t.Fatalf("effective exclusions %q accepted: %v", output, err)
		}
	}
}

func TestZypperEffectiveLocksRefuseWholeSystemUpgrade(t *testing.T) {
	// Source-derived native output, not captured guest evidence:
	// https://github.com/openSUSE/zypper/blob/master/src/commands/locks/list.cc
	if err := rejectZypperLocks([]byte(`<stream><locks size="0"/></stream>`)); err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{
		`<stream><locks size="1"><lock number="1"><name>kernel-default</name><type>package</type></lock></locks></stream>`,
		`<stream><locks size="1"><lock number="1"><name>openssl*</name><type>package</type><range flag="=" version="3.5" release="1"/></lock></locks></stream>`,
	} {
		if err := rejectZypperLocks([]byte(output)); !errors.Is(err, errRollingNativeHolds) {
			t.Fatalf("effective lock accepted: %v", err)
		}
	}
	for _, output := range []string{
		`<stream/>`, `<stream><locks/></stream>`,
		`<stream><locks size="0"><lock number="1"/></locks></stream>`,
		`<stream><locks size="1"/></stream>`,
		`<stream><locks size="0"/><locks size="0"/></stream>`,
		`<stream><message type="error">cannot read effective locks file</message><locks size="0"/></stream>`,
	} {
		if err := rejectZypperLocks([]byte(output)); err == nil {
			t.Fatalf("incomplete native lock observation accepted: %s", output)
		}
	}
}
