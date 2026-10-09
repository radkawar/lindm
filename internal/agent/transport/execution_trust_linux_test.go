//go:build linux

package transport

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
)

func TestTrustReceiptRequiresAllProtectedCounters(t *testing.T) {
	receipt := &agentv1.UpdateExecutionTrustResponse{
		RootVersion: 4, DelegationVersion: 19, MinimumRecoveryEpoch: 7,
		ExpiresAt: timestamppb.New(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)),
	}
	desired := &devicev1.GetExecutionTrustResponse{RootVersion: 4, DelegationVersion: 19, MinimumRecoveryEpoch: 7}
	// The root can return an expired historical receipt for exact replay. The
	// relay compares admitted facts; it must not rewrite expiry or grant life.
	if err := checkTrustReceipt(receipt, desired); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"root", "delegation", "recovery"} {
		for _, direction := range []string{"lower", "higher"} {
			t.Run(field+"-"+direction, func(t *testing.T) {
				other := proto.CloneOf(desired)
				var counter *uint64
				switch field {
				case "root":
					counter = &other.RootVersion
				case "delegation":
					counter = &other.DelegationVersion
				case "recovery":
					counter = &other.MinimumRecoveryEpoch
				}
				if direction == "higher" {
					*counter++
				} else {
					*counter--
				}
				if err := checkTrustReceipt(receipt, other); err == nil {
					t.Fatal("server desired metadata was accepted instead of the protected receipt")
				}
			})
		}
	}
	unknown := proto.CloneOf(receipt)
	unknown.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	if err := checkTrustReceipt(unknown, desired); err == nil {
		t.Fatal("accepted unknown protected receipt semantics")
	}
	incomplete := proto.CloneOf(receipt)
	incomplete.ExpiresAt = nil
	if err := checkTrustReceipt(incomplete, desired); err == nil {
		t.Fatal("accepted an incomplete protected receipt")
	}
	if err := checkTrustReceipt(nil, desired); err == nil {
		t.Fatal("accepted a missing protected receipt")
	}
}

func TestTrustResponseWithoutSignedUpdateCannotSelectNewCounters(t *testing.T) {
	view := &agentv1.GetExecutionTrustResponse{RootVersion: 4, DelegationVersion: 19, MinimumRecoveryEpoch: 7}
	before := proto.CloneOf(view)
	for _, desired := range []*devicev1.GetExecutionTrustResponse{
		{}, // Unprovisioned does not erase the already accepted local authority.
		{RootVersion: 4, DelegationVersion: 19, MinimumRecoveryEpoch: 7},
	} {
		if err := checkUnchangedTrust(view, desired); err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(view, before) {
			t.Fatal("unsigned server facts changed protected local authority")
		}
	}
	for _, desired := range []*devicev1.GetExecutionTrustResponse{
		{RootVersion: 5, DelegationVersion: 19, MinimumRecoveryEpoch: 7},
		{RootVersion: 3, DelegationVersion: 19, MinimumRecoveryEpoch: 7},
		{RootVersion: 4, DelegationVersion: 20, MinimumRecoveryEpoch: 7},
		{RootVersion: 4, DelegationVersion: 18, MinimumRecoveryEpoch: 7},
		{RootVersion: 4, DelegationVersion: 19, MinimumRecoveryEpoch: 8},
		{RootVersion: 4, DelegationVersion: 19, MinimumRecoveryEpoch: 6},
		{RootVersion: 4},
		{MinimumRecoveryEpoch: 7},
	} {
		if err := checkUnchangedTrust(view, desired); err == nil {
			t.Fatalf("accepted changed counters without signed documents: %v", desired)
		}
	}
}
