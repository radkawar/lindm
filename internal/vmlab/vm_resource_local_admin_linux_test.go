//go:build linux

package vmlab

import (
	"crypto/rand"
	"testing"
	"time"

	"buf.build/go/protovalidate"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

func TestResourceKindSelectionSecretGroups(t *testing.T) {
	selected, err := ResourceKindSelection("secret-password,local-admin")
	if err != nil {
		t.Fatal(err)
	}
	if !selected["secret-password"] || !selected["local-admin"] || len(selected) != 2 {
		t.Fatalf("secret kind groups not selected exactly: %v", selected)
	}
	for _, value := range []string{"local_admin", "secret-password,", "laps"} {
		if _, err := ResourceKindSelection(value); err == nil {
			t.Fatalf("unknown kind list %q accepted", value)
		}
	}
}

func TestValidLocalAdminPasswordAcceptsOnlyRandText(t *testing.T) {
	for range 64 {
		if !validLocalAdminPassword([]byte(rand.Text())) {
			t.Fatal("crypto/rand.Text output refused")
		}
	}
	for _, value := range []string{"", "ABCDEFGHIJKLMNOPQRSTUVWXY", "ABCDEFGHIJKLMNOPQRSTUVWXYZ2", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWX01", "ABCDEFGHIJKLMNOPQRSTUVWX8="} {
		if validLocalAdminPassword([]byte(value)) {
			t.Fatalf("non-base32 password %q accepted", value)
		}
	}
}

func TestLocalAdminEvidenceFailsClosed(t *testing.T) {
	now := time.Now()
	evidence := &VMLocalAdminEvidence{Steps: []VMLocalAdminStep{{Name: "rotate", StartedAt: now, FinishedAt: now, Passed: true, Action: &agentv1.DeviceActionStatus{State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED}}}}
	if err := qualifyLocalAdminEvidence(evidence, []string{"rotate"}); err == nil {
		t.Fatal("step without native, denial or status evidence qualified")
	}
	evidence.Steps[0].Native = []VMResourceNativeRecord{resourceNativeRecord("passwd", []byte("lindm-laps P\n"))}
	evidence.Steps[0].Action.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_FAILED
	if err := qualifyLocalAdminEvidence(evidence, []string{"rotate"}); err == nil {
		t.Fatal("failed rotation qualified")
	}
	evidence.Steps[0].Action.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED
	evidence.Steps[0].Native[0].Bytes[0] ^= 1
	if err := qualifyLocalAdminEvidence(evidence, []string{"rotate"}); err == nil {
		t.Fatal("altered native record qualified")
	}
	evidence.Steps[0].Native[0].Bytes[0] ^= 1
	evidence.Unproven = []string{"post-reveal supersession"}
	if err := qualifyLocalAdminEvidence(evidence, []string{"rotate"}); err != nil {
		t.Fatal(err)
	}
	if evidence.NativeQualified {
		t.Fatal("unproven dimension ignored")
	}
	if err := qualifyLocalAdminEvidence(evidence, []string{"rotate", "reveal"}); err == nil {
		t.Fatal("missing step accepted")
	}
}

func TestResourceSecretUserDesiredContract(t *testing.T) {
	ref := &resourcev1.SecretRef{SecretId: "2f6c3f0e-0b39-4c43-9f43-6a1d2d6b9a10", Version: 2, Purpose: resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH, SubjectBindingId: "8c0e7b8e-50c6-4f0c-9c0b-0f3e9f6d2a77"}
	desired := resourceSecretUserDesired(ref)
	if err := protovalidate.Validate(desired); err != nil {
		t.Fatal(err)
	}
	if err := resource.ValidateDesired(desired); err != nil {
		t.Fatal(err)
	}
	if desired.GetLocalUser().GetUid() == resourceLabUserID || desired.GetLocalUser().GetName() == resourceLabUser {
		t.Fatal("secret password account collides with the accounts kind")
	}
}
