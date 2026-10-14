// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func secretRef(purpose resourcev1.SecretPurpose) *resourcev1.SecretRef {
	return &resourcev1.SecretRef{SecretId: uuid.NewString(), Version: 1, Purpose: purpose, SubjectBindingId: uuid.NewString()}
}

func hashedUser(ref *resourcev1.SecretRef) *resourcev1.ResourceDesiredState {
	return &resourcev1.ResourceDesiredState{
		Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, CanonicalKey: "alice"},
		State: &resourcev1.ResourceDesiredState_LocalUser{LocalUser: &resourcev1.LocalUserDesired{Name: "alice", Presence: resourcev1.Presence_PRESENCE_PRESENT,
			Password: &resourcev1.PasswordState{State: &resourcev1.PasswordState_Hashed{Hashed: &resourcev1.HashedPasswordPolicy{Hash: ref, Algorithm: resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_YESCRYPT}}}}},
	}
}

// The server mints and the executor verifies against this same order; a
// changed order or purpose would let one delivery stand in for another.
func TestSecretRefsDeterministicPurposeBound(t *testing.T) {
	ref := secretRef(resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH)
	refs, err := SecretRefs(hashedUser(ref), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil || len(refs) != 1 || !proto.Equal(refs[0], ref) {
		t.Fatalf("hashed password reference = %v, %v", refs, err)
	}
	refs[0].Version = 9
	if ref.GetVersion() != 1 {
		t.Fatal("returned reference aliases desired state")
	}
	if refs, err := SecretRefs(hashedUser(ref), resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE); err != nil || refs != nil {
		t.Fatal("release requested secret material")
	}
	wrong := secretRef(resourcev1.SecretPurpose_SECRET_PURPOSE_WIFI_PSK)
	if _, err := SecretRefs(hashedUser(wrong), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrSecretRefs) {
		t.Fatal("password field accepted another purpose")
	}

	peers := make([]*resourcev1.WireGuardPeer, 0, MaxSecretRefs)
	for range MaxSecretRefs {
		peers = append(peers, &resourcev1.WireGuardPeer{PresharedKey: secretRef(resourcev1.SecretPurpose_SECRET_PURPOSE_WIREGUARD_PRESHARED_KEY)})
	}
	wireguard := &resourcev1.WireGuard{PrivateKey: secretRef(resourcev1.SecretPurpose_SECRET_PURPOSE_WIREGUARD_PRIVATE_KEY), Peers: peers[:MaxSecretRefs-1]}
	desired := &resourcev1.ResourceDesiredState{State: &resourcev1.ResourceDesiredState_NetworkConnection{NetworkConnection: &resourcev1.NetworkConnectionDesired{Medium: &resourcev1.NetworkConnectionDesired_Vpn{Vpn: &resourcev1.VPN{Plugin: &resourcev1.VPN_Wireguard{Wireguard: wireguard}}}}}}
	refs, err = SecretRefs(desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil || len(refs) != MaxSecretRefs || !proto.Equal(refs[0], wireguard.GetPrivateKey()) || !proto.Equal(refs[MaxSecretRefs-1], peers[MaxSecretRefs-2].GetPresharedKey()) {
		t.Fatalf("field-number/list order not preserved: %v", err)
	}
	wireguard.Peers = peers
	if _, err := SecretRefs(desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); !errors.Is(err, ErrSecretRefs) {
		t.Fatal("more than the bounded number of deliveries accepted")
	}
}

func TestPasswordHashMatchesDeclaredAlgorithm(t *testing.T) {
	for _, test := range []struct {
		algorithm resourcev1.PasswordHashAlgorithm
		hash      string
		want      bool
	}{
		{resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_YESCRYPT, "$y$j9T$salt$hash", true},
		{resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT, "$6$salt$hash", true},
		{resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_BCRYPT, "$2b$12$hash", true},
		{resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT, "$y$j9T$salt$hash", false},
		{resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_BCRYPT, "$6$salt$hash", false},
		{resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_UNSPECIFIED, "$6$salt$hash", false},
	} {
		if got := PasswordHashMatches(test.algorithm, []byte(test.hash)); got != test.want {
			t.Errorf("%s %q = %v", test.algorithm, test.hash, got)
		}
	}
}
