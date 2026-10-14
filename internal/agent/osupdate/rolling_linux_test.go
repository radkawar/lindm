// SPDX-License-Identifier: Apache-2.0

//go:build linux

package osupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/platform"
)

func TestRollingPolicyRejectsPartialAndUnpinnedTransactions(t *testing.T) {
	arch := &resourcev1.OSUpdateDesired{Selection: resourcev1.UpdateSelection_UPDATE_SELECTION_ALL, RollingSnapshot: &resourcev1.RollingUpdateSnapshot{Date: "2026-10-02"}}
	if err := ValidateRollingPolicy(resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN, arch); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*resourcev1.OSUpdateDesired){
		func(d *resourcev1.OSUpdateDesired) {
			d.Selection = resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY
		},
		func(d *resourcev1.OSUpdateDesired) { d.DeferralDays = 1 },
		func(d *resourcev1.OSUpdateDesired) { d.RollingSnapshot = nil },
		func(d *resourcev1.OSUpdateDesired) { d.RollingSnapshot.Date = "2026-02-30" },
		func(d *resourcev1.OSUpdateDesired) {
			d.RollingSnapshot.RepositoryUrl = "https://mirror.example/latest/"
		},
	} {
		desired := proto.CloneOf(arch)
		mutate(desired)
		if err := ValidateRollingPolicy(resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_PACMAN, desired); err == nil {
			t.Fatalf("accepted partial or unpinned policy: %v", desired)
		}
	}
	if err := ValidateRollingPolicy(resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_DNF4_AUTOMATIC, arch); err == nil {
		t.Fatal("numbered backend accepted rolling policy")
	}
	tumbleweed := proto.CloneOf(arch)
	tumbleweed.RollingSnapshot.RepositoryUrl = "https://archive.example/20261002/oss/"
	if err := ValidateRollingPolicy(resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_ZYPPER, tumbleweed); err == nil {
		t.Fatal("accepted repository without metadata pin")
	}
	tumbleweed.RollingSnapshot.MetadataSha256 = bytes.Repeat([]byte{1}, 32)
	if err := ValidateRollingPolicy(resourcev1.OSUpdateBackend_OS_UPDATE_BACKEND_ZYPPER, tumbleweed); err != nil {
		t.Fatal(err)
	}
}

func TestRollingPendingIncludesReplacementAndRemoval(t *testing.T) {
	// Source-derived native XML (not a captured guest result): zypper's
	// Summary::writeXmlResolvableList emits type, despite its stale XML schema
	// documenting kind. https://github.com/openSUSE/zypper/blob/master/src/Summary.cc
	data := []byte(`<stream><install-summary packages-to-change="3"><to-upgrade><solvable type="package" name="kernel-default" edition="6.17-1" edition-old="6.16-1" arch="aarch64"/></to-upgrade><to-remove><solvable type="package" name="obsolete" edition="1-1" arch="noarch"/></to-remove><to-downgrade><solvable type="package" name="openssl" edition="3.5-1" edition-old="3.6-1" arch="aarch64"/></to-downgrade></install-summary></stream>`)
	pending, err := parseRollingPending(data, false)
	if err != nil || len(pending) != 3 {
		t.Fatalf("whole-system pending = %v, %v", pending, err)
	}
	for _, item := range pending {
		if item.security {
			t.Fatal("invented native security classification")
		}
	}
	for _, bad := range []string{`<stream/>`, `<stream><install-summary packages-to-change="1"/></stream>`, `<stream><install-summary/></stream>`, `<stream><install-summary packages-to-change="1"><to-upgrade><solvable type="package" name="bad/name" arch="aarch64"/></to-upgrade></install-summary></stream>`, `<stream><install-summary packages-to-change="1"><to-upgrade><solvable kind="package" name="kernel-default" arch="aarch64"/></to-upgrade></install-summary></stream>`} {
		if _, err := parseRollingPending([]byte(bad), false); err == nil {
			t.Fatalf("accepted incomplete solver output %q", bad)
		}
	}
	if empty, err := parseRollingPending([]byte(`<stream><install-summary packages-to-change="0" download-size="0" space-usage-diff="0" need-restart="false" need-reboot="false"/></stream>`), false); err != nil || len(empty) != 0 {
		t.Fatalf("native no-change summary = %v, %v", empty, err)
	}
	pending, err = parseRollingPending([]byte("linux\tx86_64\t6.18-1\nopenssl\tx86_64\t3.6-1\n"), true)
	if err != nil || len(pending) != 2 {
		t.Fatalf("pacman pending = %v, %v", pending, err)
	}
	if _, err := parseRollingPending([]byte("error: failed to synchronize databases\n"), true); err == nil {
		t.Fatal("accepted pacman error as an empty update list")
	}
}

func TestRollingInstallRefusesPartialBeforeNativeEffects(t *testing.T) {
	backend := &rollingBackend{release: platform.Identify(platform.OSRelease{ID: "arch"})}
	for _, request := range []installRequest{
		{selection: resourcev1.UpdateSelection_UPDATE_SELECTION_SECURITY},
		{selection: resourcev1.UpdateSelection_UPDATE_SELECTION_ALL, deferred: []packageKey{{name: "linux", arch: "x86_64"}}},
	} {
		if err := backend.install(context.Background(), request); err == nil || err.Error() != "rolling_partial_upgrade_refused" {
			t.Fatalf("partial transaction not refused before native work: %v", err)
		}
	}
}

func TestRollingReceiptDoesNotInventCleanSecurityStatus(t *testing.T) {
	r, err := New(Config{Clock: time.Now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Executable: "/usr/libexec/lindm/lindm-agent"})
	if err != nil {
		t.Fatal(err)
	}
	last := &agentv1.PatchRunSummary{Result: agentv1.PatchRunResult_PATCH_RUN_RESULT_SUCCEEDED, RollbackStatus: "unavailable", UpdatedPackages: 12}
	backend := &rollingBackend{release: platform.Identify(platform.OSRelease{ID: "arch"})}
	status, pending := r.observe(context.Background(), backend, &agentv1.OSUpdateRunState{LastRun: last})
	if status.GetAvailable() || status.GetReason() != "rolling_security_classification_unavailable" || status.GetLastRun() != last || pending != nil {
		t.Fatalf("rolling receipt lost or security cleanliness fabricated: %v", status)
	}
}

func TestRollingMetadataPinRejectsChangedAndWrongSnapshot(t *testing.T) {
	metadata := []byte(`<repomd xmlns="http://linux.duke.edu/metadata/repo"><tags><distro cpeid="cpe:/o:opensuse:opensuse:20261007">openSUSE Tumbleweed 20261007</distro></tags></repomd>`)
	digest := sha256.Sum256(metadata)
	pin := &resourcev1.RollingUpdateSnapshot{Date: "2026-10-07", MetadataSha256: digest[:]}
	prefix := platform.Identify(platform.OSRelease{ID: "opensuse-tumbleweed", VersionID: "20261007"}).RollingUpdate.SnapshotCPEPrefix
	if err := verifyRollingMetadata(metadata, pin, prefix); err != nil {
		t.Fatal(err)
	}
	if err := verifyRollingMetadata(append(bytes.Clone(metadata), ' '), pin, prefix); err == nil {
		t.Fatal("changed signed metadata bypassed exact policy digest")
	}
	pin.Date = "2026-10-08"
	if err := verifyRollingMetadata(metadata, pin, prefix); err == nil {
		t.Fatal("metadata for another snapshot accepted despite matching digest")
	}
}
