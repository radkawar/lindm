package trust

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestLiveRootStartRequiresCompleteFrozenEncryptedScope(t *testing.T) {
	f := newDeviceActionAuthorityFixture(t, true)
	rootTarget := &agentv1.StorageTarget{LuksUuid: uuid.NewString(), Serial: "root-disk", SizeBytes: 1 << 30}
	escrowTarget := &agentv1.StorageTarget{LuksUuid: uuid.NewString(), Serial: "escrow-data-disk", SizeBytes: 2 << 30}
	f.intent.Spec.Action = &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_LIVE_ROOT_HEADER, Targets: []*agentv1.StorageTarget{rootTarget, escrowTarget}}}
	specDigest, err := DeviceActionDigest(f.intent.Spec)
	if err != nil {
		t.Fatal(err)
	}
	f.intent.SpecSha256 = specDigest[:]
	intentDigest := sha256.Sum256(executionSign(t, f.authority, f.intent, f.planKey))
	f.challenge.IntentSha256, f.challenge.SpecSha256 = intentDigest[:], bytes.Clone(specDigest[:])
	plan := f.challenge.NativePlan
	plan.Spec = proto.CloneOf(f.intent.Spec)
	plan.Before.RecoveryEnvironment, plan.Before.OffTargetJournal, plan.Before.Encrypted = false, false, true
	plan.CryptoEraseTargets = []*agentv1.CryptoEraseTargetPlan{
		{Target: proto.CloneOf(rootTarget), MetadataSha256: bytes.Repeat([]byte{1}, 32), LuksHeaderBytes: 16 << 20, RootBacking: true, RootMappingSha256: bytes.Repeat([]byte{3}, 32)},
		{Target: proto.CloneOf(escrowTarget), MetadataSha256: bytes.Repeat([]byte{2}, 32), LuksHeaderBytes: 16 << 20, RootMappingSha256: bytes.Repeat([]byte{4}, 32)},
	}
	for _, target := range plan.CryptoEraseTargets {
		plan.Before.CryptoEraseTargets = append(plan.Before.CryptoEraseTargets, proto.CloneOf(target))
	}
	planDigest, err := DeviceActionDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	f.challenge.NativePlanSha256 = planDigest[:]
	f.grant.Challenge = proto.CloneOf(f.challenge)
	for _, approval := range f.grant.Approvals {
		approval.Binding.SpecSha256 = bytes.Clone(specDigest[:])
	}
	if _, err := f.verifier.VerifyDeviceActionStart(t.Context(), f.root, f.delegation, executionSign(t, f.authority, f.grant, f.startKey), f.intent, f.challenge, f.now); err != nil {
		t.Fatalf("qualified live-root grant rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*agentv1.DeviceActionChallenge)
	}{
		{name: "escrow volume omitted", change: func(c *agentv1.DeviceActionChallenge) {
			c.NativePlan.CryptoEraseTargets = c.NativePlan.CryptoEraseTargets[:1]
		}},
		{name: "additional unapproved volume", change: func(c *agentv1.DeviceActionChallenge) {
			c.NativePlan.CryptoEraseTargets[1].Target.LuksUuid = uuid.NewString()
		}},
		{name: "duplicate root volume", change: func(c *agentv1.DeviceActionChallenge) {
			c.NativePlan.CryptoEraseTargets[1] = proto.CloneOf(c.NativePlan.CryptoEraseTargets[0])
		}},
		{name: "no root backing", change: func(c *agentv1.DeviceActionChallenge) {
			c.NativePlan.CryptoEraseTargets[0].RootBacking = false
			c.NativePlan.Before.CryptoEraseTargets[0].RootBacking = false
		}},
		{name: "raw unencrypted root", change: func(c *agentv1.DeviceActionChallenge) { c.NativePlan.Before.Encrypted = false }},
		{name: "header extent changed", change: func(c *agentv1.DeviceActionChallenge) { c.NativePlan.CryptoEraseTargets[1].LuksHeaderBytes += 4096 }},
		{name: "mapping topology changed", change: func(c *agentv1.DeviceActionChallenge) { c.NativePlan.CryptoEraseTargets[0].RootMappingSha256[0] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			challenge := proto.CloneOf(f.challenge)
			tc.change(challenge)
			digest, err := DeviceActionDigest(challenge.NativePlan)
			if err != nil {
				t.Fatal(err)
			}
			challenge.NativePlanSha256 = digest[:]
			grant := proto.CloneOf(f.grant)
			grant.Challenge = proto.CloneOf(challenge)
			if _, err := f.verifier.VerifyDeviceActionStart(t.Context(), f.root, f.delegation, executionSign(t, f.authority, grant, f.startKey), f.intent, challenge, f.now); err == nil {
				t.Fatal("unsafe aggregate accepted by fresh signer")
			}
		})
	}
}

func TestNativeSanitizeGrantRequiresExactObservedNamespace(t *testing.T) {
	f := newDeviceActionAuthorityFixture(t, true)
	for _, delegate := range f.delegation.Delegates {
		delegate.Capabilities = []string{"device.sanitize.v1"}
	}
	var err error
	f.delegation, err = f.verifier.VerifyDelegation(t.Context(), f.root, executionSign(t, f.authority, f.delegation, f.keys...), 0, 0, f.now)
	if err != nil {
		t.Fatal(err)
	}
	scope := &agentv1.NVMeSanitizeScope{NamespaceId: 1}
	f.intent.Spec.Action = &agentv1.DeviceActionSpec_Sanitize{Sanitize: &agentv1.SanitizeAction{Target: &agentv1.StorageTarget{Serial: "native-nvme", SizeBytes: 1 << 30}, Method: agentv1.SanitizeMethod_SANITIZE_METHOD_NVME_FORMAT_USER_DATA, NvmeScope: scope}}
	specDigest, err := DeviceActionDigest(f.intent.Spec)
	if err != nil {
		t.Fatal(err)
	}
	f.intent.SpecSha256 = specDigest[:]
	f.challenge.SpecSha256 = bytes.Clone(specDigest[:])
	f.challenge.NativePlan.Spec = proto.CloneOf(f.intent.Spec)
	f.challenge.NativePlan.Before.NvmeSanitize = &agentv1.NVMeSanitizePlan{Scope: proto.CloneOf(scope), ControllerSerial: "native-nvme", ControllerModel: "qualified-model", ControllerFirmware: "qualified-version", AllocatedNamespaceIds: []uint32{1}, IdentifyControllerSha256: bytes.Repeat([]byte{1}, 32), IdentifyNamespaceSha256: bytes.Repeat([]byte{2}, 32), NamespaceInventorySha256: bytes.Repeat([]byte{3}, 32)}
	for _, approval := range f.grant.Approvals {
		approval.Binding.SpecSha256 = bytes.Clone(specDigest[:])
	}
	for _, tc := range []struct {
		name   string
		change func(*agentv1.DeviceActionChallenge)
		valid  bool
	}{
		{name: "matching scope", valid: true},
		{name: "missing native proof", change: func(c *agentv1.DeviceActionChallenge) { c.NativePlan.Before.NvmeSanitize = nil }},
		{name: "different namespace", change: func(c *agentv1.DeviceActionChallenge) { c.NativePlan.Before.NvmeSanitize.Scope.NamespaceId = 2 }},
		{name: "widened controller scope", change: func(c *agentv1.DeviceActionChallenge) { c.NativePlan.Before.NvmeSanitize.Scope.ControllerWide = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			challenge := proto.CloneOf(f.challenge)
			if tc.change != nil {
				tc.change(challenge)
			}
			digest, err := DeviceActionDigest(challenge.NativePlan)
			if err != nil {
				t.Fatal(err)
			}
			challenge.NativePlanSha256 = digest[:]
			grant := proto.CloneOf(f.grant)
			grant.Challenge = proto.CloneOf(challenge)
			_, err = f.verifier.VerifyDeviceActionStart(t.Context(), f.root, f.delegation, executionSign(t, f.authority, grant, f.startKey), f.intent, challenge, f.now)
			if tc.valid && err != nil {
				t.Fatal(err)
			}
			if !tc.valid && err == nil {
				t.Fatal("unapproved native scope accepted")
			}
		})
	}
}
