// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
)

// Corrupt or unrelated receipt bytes must not qualify a promotion merely because
// the database contains the expected number of idempotency rows.
func TestDecodeHARolloutReceiptRequiresCommittedCampaign(t *testing.T) {
	id := uuid.NewString()
	valid := &adminv1.ControlRolloutResponse{Rollout: &adminv1.RolloutState{Rollout: &policyv1.RolloutSpec{RolloutId: id}, Revision: 3, RingIndex: 2}}
	for _, test := range []struct {
		name     string
		response *adminv1.ControlRolloutResponse
		want     bool
	}{
		{"committed", valid, true},
		{"empty", &adminv1.ControlRolloutResponse{}, false},
		{"missing_revision", &adminv1.ControlRolloutResponse{Rollout: &adminv1.RolloutState{Rollout: &policyv1.RolloutSpec{RolloutId: id}}}, false},
		{"missing_campaign", &adminv1.ControlRolloutResponse{Rollout: &adminv1.RolloutState{Revision: 2}}, false},
		{"invalid_campaign", &adminv1.ControlRolloutResponse{Rollout: &adminv1.RolloutState{Revision: 2, Rollout: &policyv1.RolloutSpec{RolloutId: "invalid"}}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, err := proto.Marshal(test.response)
			if err != nil {
				t.Fatal(err)
			}
			state, err := decodeHARolloutReceipt(data)
			if (err == nil) != test.want {
				t.Fatalf("accepted=%t want=%t error=%v", err == nil, test.want, err)
			}
			if test.want && !proto.Equal(state, valid.GetRollout()) {
				t.Fatal("receipt lost committed campaign, ring or revision")
			}
		})
	}
	if _, err := decodeHARolloutReceipt([]byte{0xff}); err == nil {
		t.Fatal("accepted corrupt protobuf receipt")
	}
}
