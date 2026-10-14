// SPDX-License-Identifier: Apache-2.0

package secretseal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// Fixed recipient scalar for the delivery known-answer vector below (the
// RFC 9180 A.2.1 recipient key; any fixed scalar works).
const goldenPrivate = "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb"

const goldenHash = "$6$saltsalt$jLp9TY5kTYtXj5o1ne5Pl0DS.8KVNpBfPg51uqD07/z9FUFaK7vRpXlxycHLB5yTiXZdvu5QtezzbuWJ4.bYQ/"

// goldenSealed was produced once by Seal for goldenBinding/goldenMaterial. A
// change to the suite, info string, AAD encoding or material framing breaks it,
// which would strand every delivery already minted for deployed agents.
const goldenSealed = "93a64de868a51e7a8e27d6b02bc6e5b1aeb513b5942106aae250d3763407d00d6a365a1d21bd5f97e6a2195d30a8e7ec1f5cdda656ef78a528ebfdc9da21a6b5a1b080400e50b8170901d413a9544ecc4ff5089412ca1f2e773562123e2249a818a4ebb9cbbb5a46aac71783aaf8b2e9d96361542142f325e0b11e791769e8c7a01722ef1fa93e8c0827433138c2412027a857d7"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func goldenMaterial() *agentv1.SecretMaterial {
	return &agentv1.SecretMaterial{Material: &agentv1.SecretMaterial_PasswordHash{PasswordHash: []byte(goldenHash)}}
}

func goldenBinding(t *testing.T, public []byte) *agentv1.SecretDeliveryBinding {
	t.Helper()
	return &agentv1.SecretDeliveryBinding{
		DeploymentId:         "6f1c7f7e-3a59-4f3c-9d1e-2b6a3f0c9a11",
		DeviceId:             "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
		EnrollmentGeneration: "9a0e5c4d-2f1b-4e8a-8c7d-6b5a4f3e2d1c",
		ActionId:             "2c1d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
		Resource:             &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, CanonicalKey: "alice"},
		Secret:               &resourcev1.SecretRef{SecretId: "7d444840-9dc0-11d1-b245-5ffdce74fad2", Version: 3, Purpose: resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH, SubjectBindingId: "0f8fad5b-d9cb-469f-a165-70867728950e"},
		RecipientKeySha256:   KeyID(public),
	}
}

// The executor must decrypt with exactly the RFC 9180 suite it attests
// (KEM 0x0020, KDF 0x0001, AEAD 0x0003); RFC 9180 A.2.1 sequence 0.
func TestSuiteMatchesRFC9180Vector(t *testing.T) {
	key, err := ecdh.X25519().NewPrivateKey(mustHex(t, "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb"))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(key.PublicKey().Bytes()); got != "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a" {
		t.Fatalf("pkRm = %s", got)
	}
	sealed := append(mustHex(t, "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"), mustHex(t, "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28")...)
	plaintext, err := openSuite(key, mustHex(t, "4f6465206f6e2061204772656369616e2055726e"), mustHex(t, "436f756e742d30"), sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "Beauty is truth, truth beauty" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestGoldenDeliveryOpens(t *testing.T) {
	private := mustHex(t, goldenPrivate)
	public, err := PublicKey(private)
	if err != nil {
		t.Fatal(err)
	}
	material, err := Open(private, goldenBinding(t, public), mustHex(t, goldenSealed))
	if err != nil {
		t.Fatal(err)
	}
	defer Clear(material)
	if !proto.Equal(material, goldenMaterial()) {
		t.Fatal("golden delivery decoded to different material")
	}
}

func sealFixture(t *testing.T) (private, public, sealed []byte) {
	t.Helper()
	private, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err = PublicKey(private)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err = Seal(public, goldenBinding(t, public), goldenMaterial())
	if err != nil {
		t.Fatal(err)
	}
	return private, public, sealed
}

func TestRoundTripClearsMaterial(t *testing.T) {
	private, public, sealed := sealFixture(t)
	if bytes.Contains(sealed, []byte(goldenHash)) || bytes.Contains(sealed, []byte("saltsalt")) {
		t.Fatal("sealed delivery contains plaintext")
	}
	material, err := Open(private, goldenBinding(t, public), sealed)
	if err != nil {
		t.Fatal(err)
	}
	hash := material.GetPasswordHash()
	if string(hash) != goldenHash {
		t.Fatalf("material = %q", hash)
	}
	Clear(material)
	if !bytes.Equal(hash, make([]byte, len(hash))) || material.GetMaterial() != nil {
		t.Fatal("Clear left plaintext in memory")
	}
}

// Replaying ciphertext under any other action, device, generation, resource,
// secret version, purpose, subject or recipient must fail authentication.
func TestRebindingRefused(t *testing.T) {
	private, public, sealed := sealFixture(t)
	mutations := map[string]func(*agentv1.SecretDeliveryBinding){
		"deployment": func(b *agentv1.SecretDeliveryBinding) { b.DeploymentId = "6f1c7f7e-3a59-4f3c-9d1e-2b6a3f0c9a12" },
		"device":     func(b *agentv1.SecretDeliveryBinding) { b.DeviceId = "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bee" },
		"generation": func(b *agentv1.SecretDeliveryBinding) {
			b.EnrollmentGeneration = "9a0e5c4d-2f1b-4e8a-8c7d-6b5a4f3e2d1d"
		},
		"action":   func(b *agentv1.SecretDeliveryBinding) { b.ActionId = "2c1d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e60" },
		"resource": func(b *agentv1.SecretDeliveryBinding) { b.Resource.CanonicalKey = "mallory" },
		"kind": func(b *agentv1.SecretDeliveryBinding) {
			b.Resource.Kind = resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_GROUP
		},
		"secret":  func(b *agentv1.SecretDeliveryBinding) { b.Secret.SecretId = "7d444840-9dc0-11d1-b245-5ffdce74fad3" },
		"version": func(b *agentv1.SecretDeliveryBinding) { b.Secret.Version = 2 },
		"purpose": func(b *agentv1.SecretDeliveryBinding) {
			b.Secret.Purpose = resourcev1.SecretPurpose_SECRET_PURPOSE_WIFI_PSK
		},
		"subject": func(b *agentv1.SecretDeliveryBinding) {
			b.Secret.SubjectBindingId = "0f8fad5b-d9cb-469f-a165-70867728950f"
		},
		"recipientID": func(b *agentv1.SecretDeliveryBinding) { b.RecipientKeySha256 = KeyID([]byte("other")) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			binding := goldenBinding(t, public)
			mutate(binding)
			if _, err := Open(private, binding, sealed); !errors.Is(err, ErrOpen) {
				t.Fatalf("Open = %v, want ErrOpen", err)
			}
		})
	}
}

func TestWrongDeviceKeyRefused(t *testing.T) {
	_, public, sealed := sealFixture(t)
	other, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The other device even presents the sender's recipient digest.
	if _, err := Open(other, goldenBinding(t, public), sealed); !errors.Is(err, ErrOpen) {
		t.Fatalf("Open with another device key = %v", err)
	}
	otherPublic, err := PublicKey(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(other, goldenBinding(t, otherPublic), sealed); !errors.Is(err, ErrOpen) {
		t.Fatalf("Open with another device binding = %v", err)
	}
}

func TestTamperedOrTruncatedRefused(t *testing.T) {
	private, public, sealed := sealFixture(t)
	for _, i := range []int{0, 31, 32, len(sealed) - 1} {
		tampered := bytes.Clone(sealed)
		tampered[i] ^= 1
		if _, err := Open(private, goldenBinding(t, public), tampered); !errors.Is(err, ErrOpen) {
			t.Fatalf("tampered byte %d accepted: %v", i, err)
		}
	}
	for _, n := range []int{0, 32, len(sealed) - 1} {
		if _, err := Open(private, goldenBinding(t, public), sealed[:n]); !errors.Is(err, ErrOpen) {
			t.Fatalf("truncated %d accepted: %v", n, err)
		}
	}
}

func TestSealRequiresNamedRecipient(t *testing.T) {
	_, public, _ := sealFixture(t)
	other, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, err := PublicKey(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Seal(otherPublic, goldenBinding(t, public), goldenMaterial()); !errors.Is(err, ErrBinding) {
		t.Fatalf("Seal to unnamed recipient = %v", err)
	}
}
