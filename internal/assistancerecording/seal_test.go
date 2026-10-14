// SPDX-License-Identifier: Apache-2.0

package assistancerecording

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/google/uuid"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func testRecipient(t *testing.T) *Recipient {
	t.Helper()
	seed := make([]byte, PrivateKeySeedBytes)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	recipient, err := NewRecipient(seed)
	if err != nil {
		t.Fatal(err)
	}
	return recipient
}

func TestSealedSegmentsOpenOnlyInTheirExactPosition(t *testing.T) {
	recipient := testRecipient(t)
	id := uuid.New()
	sealer, err := NewSealer(recipient.PublicKey(), recipient.KeyID(), id)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealer.EncapsulatedKey()) != EncapsulatedKeyBytes || len(recipient.PublicKey()) != PublicKeyBytes {
		t.Fatalf("suite sizes changed: enc %d public %d", len(sealer.EncapsulatedKey()), len(recipient.PublicKey()))
	}
	first, sealedFirst, err := sealer.Seal(false, []byte("header"))
	if err != nil || first != 0 {
		t.Fatalf("first = %d, %v", first, err)
	}
	last, sealedLast, err := sealer.Seal(true, bytes.Repeat([]byte{7}, SegmentPlaintextBytes))
	if err != nil || last != 1 {
		t.Fatalf("last = %d, %v", last, err)
	}
	if _, _, err := sealer.Seal(false, []byte("after final")); !errors.Is(err, ErrSequence) {
		t.Fatalf("seal after final = %v", err)
	}
	opener, err := recipient.Open(id, sealer.EncapsulatedKey())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := opener.Open(0, false, sealedFirst); err != nil || string(got) != "header" {
		t.Fatalf("open first = %q, %v", got, err)
	}
	if got, err := opener.Open(1, true, sealedLast); err != nil || len(got) != SegmentPlaintextBytes {
		t.Fatalf("open last = %d, %v", len(got), err)
	}
	tampered := bytes.Clone(sealedFirst)
	tampered[0] ^= 1
	for name, open := range map[string]func() ([]byte, error){
		"reordered":        func() ([]byte, error) { return opener.Open(1, false, sealedFirst) },
		"finality flipped": func() ([]byte, error) { return opener.Open(1, false, sealedLast) },
		"truncation claim": func() ([]byte, error) { return opener.Open(0, true, sealedFirst) },
		"tampered":         func() ([]byte, error) { return opener.Open(0, false, tampered) },
		"oversized":        func() ([]byte, error) { return opener.Open(0, false, make([]byte, MaxSegmentBytes+1)) },
	} {
		if _, err := open(); !errors.Is(err, ErrSegment) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	other, err := recipient.Open(uuid.New(), sealer.EncapsulatedKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Open(0, false, sealedFirst); !errors.Is(err, ErrSegment) {
		t.Fatalf("spliced into another recording: %v", err)
	}
	// ML-KEM decapsulation with another deployment key implicitly rejects:
	// the derived key exists but authenticates nothing.
	wrong, err := testRecipient(t).Open(id, sealer.EncapsulatedKey())
	if err == nil {
		if _, err := wrong.Open(0, false, sealedFirst); !errors.Is(err, ErrSegment) {
			t.Fatalf("another deployment key opened the segment: %v", err)
		}
	}
}

func TestSealerRefusesUnboundOrSubstitutedKeys(t *testing.T) {
	recipient := testRecipient(t)
	if _, err := NewSealer(recipient.PublicKey(), KeyID([]byte("other")), uuid.New()); !errors.Is(err, ErrKey) {
		t.Fatalf("mismatched key id: %v", err)
	}
	if _, err := NewSealer(recipient.PublicKey()[:100], recipient.KeyID(), uuid.New()); !errors.Is(err, ErrKey) {
		t.Fatalf("short key: %v", err)
	}
	if _, err := NewSealer(recipient.PublicKey(), recipient.KeyID(), uuid.Nil); !errors.Is(err, ErrKey) {
		t.Fatalf("nil recording: %v", err)
	}
	if _, err := NewRecipient(make([]byte, 31)); !errors.Is(err, ErrKey) {
		t.Fatalf("short seed: %v", err)
	}
	sealer, err := NewSealer(recipient.PublicKey(), recipient.KeyID(), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sealer.Seal(false, make([]byte, SegmentPlaintextBytes+1)); !errors.Is(err, ErrSegment) {
		t.Fatalf("oversized plaintext: %v", err)
	}
	if _, err := recipient.Open(uuid.New(), make([]byte, EncapsulatedKeyBytes-1)); !errors.Is(err, ErrKey) {
		t.Fatalf("short encapsulated key: %v", err)
	}
}

func TestRecordingPolicyIntersectionNeverWidens(t *testing.T) {
	a := &agentv1.AssistanceRecordingPolicy{RetentionDays: 30, MaxBytes: 512 << 20}
	b := &agentv1.AssistanceRecordingPolicy{RetentionDays: 400, MaxBytes: 64 << 20}
	got := Intersect(a, b)
	if got.GetRetentionDays() != 30 || got.GetMaxBytes() != 64<<20 {
		t.Fatalf("intersection = %v", got)
	}
	if Intersect(a, nil) != nil || Intersect(a, &agentv1.AssistanceRecordingPolicy{RetentionDays: 1, MaxBytes: 1}) != nil {
		t.Fatal("absent or unbounded side enabled recording")
	}
	on, limited := agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON, agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED
	if !Required(on, on) || Required(on, limited) || Required(limited, on) {
		t.Fatal("required recording must be requested and permitted as on")
	}
}
