// SPDX-License-Identifier: Apache-2.0

package loadlab

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// officeNetwork publishes the "Office network" profile whose Wi-Fi connection
// uses the demo Wi-Fi secret, so /secrets shows where a secret is used. It is
// published only, never assigned: no simulated device receives the key.
func (s *demoSeed) officeNetwork(ctx context.Context, secret *adminv1.SecretSummary) error {
	connection := uuid.NewString()
	desired := &resourcev1.ResourceDesiredState{
		Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NETWORK_CONNECTION, CanonicalKey: connection},
		State: &resourcev1.ResourceDesiredState_NetworkConnection{NetworkConnection: &resourcev1.NetworkConnectionDesired{
			ConnectionUuid: connection, DisplayName: "Office", Presence: resourcev1.Presence_PRESENCE_PRESENT,
			Device:      &resourcev1.InterfaceSelector{Identity: &resourcev1.InterfaceSelector_HardwareId{HardwareId: "wlan"}},
			Autoconnect: true, Activation: resourcev1.ActivationPolicy_ACTIVATION_POLICY_PERSIST_ONLY,
			Medium: &resourcev1.NetworkConnectionDesired_Wifi{Wifi: &resourcev1.WiFi{
				Ssid: []byte("Office"), Security: resourcev1.WiFiSecurity_WI_FI_SECURITY_WPA2_PERSONAL,
				Authentication: &resourcev1.WiFi_Psk{Psk: &resourcev1.SecretRef{SecretId: secret.GetSecretId(), Version: secret.GetCurrentVersion(), Purpose: secret.GetPurpose(), SubjectBindingId: secret.GetSubjectBindingId()}},
			}},
		}},
	}
	resource := &policyv1.ProfileResource{
		ResourceId:   uuid.NewString(),
		Desired:      desired,
		Ownership:    &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED},
		Verification: &resourcev1.VerificationPolicy{MaxAgeSeconds: 3600, Checks: []resourcev1.HealthCheck{resourcev1.HealthCheck_HEALTH_CHECK_NATIVE_STATE}},
	}
	if _, err := s.owner.Admin.PublishProfileRevision(ctx, connect.NewRequest(&adminv1.PublishProfileRevisionRequest{
		RequestId: uuid.NewString(), ProfileId: uuid.NewString(), Reason: "Office wireless network for staff laptops",
		Spec: &policyv1.ResourceProfile{Name: "Office network", Description: "Joins the office Wi-Fi with the stored network key.", Resources: []*policyv1.ProfileResource{resource}},
	})); err != nil {
		return fmt.Errorf("publish demo office network: %w", err)
	}
	return nil
}
