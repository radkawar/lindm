// SPDX-License-Identifier: Apache-2.0

//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func recoveryPreflightFixture(t *testing.T) (*Provider, *agentv1.DeviceActionSpec, *blockNode, *int) {
	t.Helper()
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}
	target := &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, Wwn: "test-wwn", Serial: "test-serial", SizeBytes: 64 << 20}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	media := sha256.Sum256(encoded)
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Sanitize{Sanitize: &agentv1.SanitizeAction{Target: target, Method: agentv1.SanitizeMethod_SANITIZE_METHOD_OVERWRITE, Recovery: &agentv1.RecoveryBootSpec{ImageSha256: bytes.Repeat([]byte{1}, 32), MediaSha256: media[:], BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI}}}}
	qualification := &agentv1.QualifiedActionTarget{Target: target, AllowOverwrite: true, QualificationId: "read-only-original-root-fixture"}
	p := &Provider{config: &agentv1.DeviceActionProviderConfig{AllowRecoveryHandoff: true, Targets: []*agentv1.QualifiedActionTarget{qualification}}, validate: validator, gate: make(chan struct{}, 1), clock: time.Now}
	mount := "/"
	node := &blockNode{Path: "/dev/qualified-original-root", Type: "disk", Device: "8:0", Size: target.SizeBytes, Rotational: true, Children: []blockNode{{Type: "part", Device: "8:1", Filesystem: "ext4", Mountpoints: []*string{&mount}}}}
	path := filepath.Join(t.TempDir(), "read-only-block-boundary-fixture")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	lookups := new(int)
	p.resolve = func(_ context.Context, lookup *agentv1.DeviceActionSpec, writable bool) (*targetHandle, error) {
		if writable || destructive(lookup) {
			return nil, ErrUnsupported
		}
		if !proto.Equal(specTarget(lookup), target) {
			return nil, ErrConflict
		}
		*lookups++
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		return &targetHandle{file: file, node: *node, qualification: qualification}, nil
	}
	p.run = func(context.Context, nativeRequest) ([]byte, error) {
		return nil, errors.New("unexpected native effect during preflight")
	}
	return p, spec, node, lookups
}

func TestRecoveryPreflightDoesNotAuthorizeMountedRootEffects(t *testing.T) {
	p, spec, _, lookups := recoveryPreflightFixture(t)
	plan, err := p.PrepareRecovery(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.GetBefore().GetSupported() || plan.GetBefore().GetRecoveryEnvironment() || plan.GetBefore().GetOffTargetJournal() || *lookups != 1 {
		t.Fatal("original-root preflight fabricated recovery/custody evidence")
	}
	plan.ActionId = fixtureAction
	paths, err := p.RecoveryTargetDevices(context.Background(), plan)
	if err != nil || len(paths) != 1 || paths[0] != "/dev/qualified-original-root" {
		t.Fatalf("qualified handoff paths: %v %v", paths, err)
	}
	if _, err := p.Observe(context.Background(), spec); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ordinary Observe bypassed offline refusal: %v", err)
	}
	gateCalled := false
	if _, err := p.Apply(context.Background(), plan, nil, func(context.Context) error { gateCalled = true; return nil }); err == nil || gateCalled {
		t.Fatal("read-only handoff plan crossed native effect gate")
	}
}

func TestRecoveryPreflightRequiresExactSignedScopeAndOptIn(t *testing.T) {
	for _, variant := range []string{"no-opt-in", "no-signed-recovery", "wrong-media", "wrong-target", "partition", "encrypted-child", "unqualified-method", "unqualified-hardware"} {
		t.Run(variant, func(t *testing.T) {
			p, spec, node, _ := recoveryPreflightFixture(t)
			switch variant {
			case "no-opt-in":
				p.config.AllowRecoveryHandoff = false
			case "no-signed-recovery":
				spec.GetSanitize().Recovery = nil
			case "wrong-media":
				spec.GetSanitize().Recovery.MediaSha256[0] ^= 1
			case "wrong-target":
				spec.GetSanitize().Target = proto.CloneOf(spec.GetSanitize().Target)
				spec.GetSanitize().Target.Serial = "unapproved-device"
			case "partition":
				node.Type = "part"
			case "encrypted-child":
				node.Children[0].Filesystem = "crypto_LUKS"
			case "unqualified-method":
				p.config.Targets[0].AllowOverwrite = false
			case "unqualified-hardware":
				node.Rotational = false
			}
			if _, err := p.PrepareRecovery(context.Background(), spec); err == nil {
				t.Fatal("unsafe original-root handoff accepted")
			}
		})
	}
}

func TestRecoveryOffTargetScopeIncludesRootMappings(t *testing.T) {
	target := blockNode{Device: "8:0", Children: []blockNode{{Device: "8:1", Children: []blockNode{{Device: "253:0"}}}}}
	if !treeContainsDevice(target, unix.Mkdev(253, 0)) || !treeContainsDevice(target, unix.Mkdev(8, 0)) || treeContainsDevice(target, unix.Mkdev(8, 16)) {
		t.Fatal("off-target identity ignored nested mapped root")
	}
}

func TestRecoveryRAMStateRequiresLiveExactCustodyProof(t *testing.T) {
	p, spec, _, _ := recoveryPreflightFixture(t)
	p.config.RecoveryEnvironment = true
	for _, filesystem := range []int64{unix.TMPFS_MAGIC, unix.RAMFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC} {
		if err := p.checkRecoveryState(t.Context(), spec, filesystem); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("RAM/overlay accepted without custody proof: %v", err)
		}
	}
	if err := p.checkRecoveryState(t.Context(), spec, 0xef53 /* ext4 */); err != nil {
		t.Fatalf("persistent off-target branch changed: %v", err)
	}
	calls := 0
	custodyFailure := errors.New("authenticated NV counter diverged")
	p.recoveryCustody = func(_ context.Context, got *agentv1.DeviceActionSpec) error {
		calls++
		if !proto.Equal(got, spec) {
			t.Fatal("custody callback received a different action")
		}
		return custodyFailure
	}
	if err := p.checkRecoveryState(t.Context(), spec, unix.TMPFS_MAGIC); !errors.Is(err, custodyFailure) || calls != 1 {
		t.Fatalf("broken durable TPM proof accepted: %v", err)
	}
	p.recoveryCustody = func(context.Context, *agentv1.DeviceActionSpec) error { calls++; return nil }
	if err := p.checkRecoveryState(t.Context(), spec, unix.TMPFS_MAGIC); err != nil {
		t.Fatalf("authenticated TPM anchor refused: %v", err)
	}
	for _, variant := range []string{"overlay", "ordinary-sanitize", "not-recovery"} {
		got := proto.CloneOf(spec)
		filesystem := int64(unix.TMPFS_MAGIC)
		switch variant {
		case "overlay":
			filesystem = unix.OVERLAYFS_SUPER_MAGIC
		case "ordinary-sanitize":
			got.GetSanitize().Recovery = nil
		case "not-recovery":
			p.config.RecoveryEnvironment = false
		}
		before := calls
		if err := p.checkRecoveryState(t.Context(), got, filesystem); !errors.Is(err, ErrUnsupported) || calls != before {
			t.Fatalf("%s bypassed scope guard: %v", variant, err)
		}
	}
}
