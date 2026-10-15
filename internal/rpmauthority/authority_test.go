// SPDX-License-Identifier: Apache-2.0

package rpmauthority

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/ed25519"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func nativeFixture(t *testing.T, name string) *inventoryv1.Package {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ ImmutableHeader, Signature []byte }
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	identity, err := Parse(fixture.ImmutableHeader)
	if err != nil {
		t.Fatal(err)
	}
	return &inventoryv1.Package{Name: identity.Name, Version: identity.Version, Architecture: identity.Architecture, Manager: "rpm", SourceName: identity.SourceName, SourceVersion: identity.SourceVersion, SourceArchitecture: identity.SourceArchitecture, Module: identity.Module,
		RpmAuthority: &inventoryv1.RpmAuthority{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, ImmutableHeader: fixture.ImmutableHeader, Signature: fixture.Signature}}
}

func TestOfficialRHEL9And10NativeHeaders(t *testing.T) {
	for _, name := range []string{"dbus", "fuse-common", "dbus10", "bash", "openssl"} {
		t.Run(name, func(t *testing.T) {
			p := nativeFixture(t, name)
			signer, reason := Verify(p)
			if signer != Fingerprint || reason != "" {
				t.Fatalf("official header rejected: %q %q", signer, reason)
			}
			if name == "fuse-common" && p.SourceName == p.Name {
				t.Fatal("native source identity was guessed from binary name")
			}
		})
	}
}

func TestRPMHeaderTamperAndIdentityForgery(t *testing.T) {
	original := nativeFixture(t, "fuse-common")
	for _, tc := range []struct {
		name   string
		mutate func(*inventoryv1.Package)
	}{
		{"name", func(p *inventoryv1.Package) { p.Name = "openssl-libs" }},
		{"version", func(p *inventoryv1.Package) { p.Version = "0:99-1.el9" }},
		{"architecture", func(p *inventoryv1.Package) { p.Architecture = "aarch64" }},
		{"source-name", func(p *inventoryv1.Package) { p.SourceName = "openssl" }},
		{"source-version", func(p *inventoryv1.Package) { p.SourceVersion = "9:99-1" }},
		{"source-architecture", func(p *inventoryv1.Package) { p.SourceArchitecture = "nosrc" }},
		{"module", func(p *inventoryv1.Package) {
			p.Module.Modular = true
			p.Module.Name = "nodejs"
			p.Module.Stream = "20"
		}},
		{"missing-module", func(p *inventoryv1.Package) { p.Module = nil }},
		{"signature-bit", func(p *inventoryv1.Package) { p.RpmAuthority.Signature[len(p.RpmAuthority.Signature)-1] ^= 1 }},
		{"header-bit", func(p *inventoryv1.Package) {
			p.RpmAuthority.ImmutableHeader[len(p.RpmAuthority.ImmutableHeader)-17] ^= 1
		}},
		{"trailing-header", func(p *inventoryv1.Package) {
			p.RpmAuthority.ImmutableHeader = append(p.RpmAuthority.ImmutableHeader, 0)
		}},
		{"trailing-signature", func(p *inventoryv1.Package) { p.RpmAuthority.Signature = append(p.RpmAuthority.Signature, 0) }},
		{"swapped-signature", func(p *inventoryv1.Package) {
			p.RpmAuthority.Signature = nativeFixture(t, "dbus").RpmAuthority.Signature
		}},
		{"unsigned", func(p *inventoryv1.Package) { p.RpmAuthority.Signature = nil }},
		{"historical", func(p *inventoryv1.Package) { p.RpmAuthority = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := proto.CloneOf(original)
			tc.mutate(p)
			if signer, reason := Verify(p); signer != "" || reason == "" {
				t.Fatalf("forgery gained authority: %q %q", signer, reason)
			}
		})
	}
}

func testSigningKey(t *testing.T) *packet.PrivateKey {
	t.Helper()
	key, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return packet.NewEd25519PrivateKey(time.Unix(1700000000, 0), key)
}

func signHeader(t *testing.T, header []byte, key *packet.PrivateKey, issuer uint64, created time.Time) []byte {
	t.Helper()
	sig := &packet.Signature{Version: 4, SigType: packet.SigTypeBinary, PubKeyAlgo: key.PubKeyAlgo, Hash: crypto.SHA256, CreationTime: created, IssuerKeyId: &issuer}
	h, err := sig.PrepareSign(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = h.Write(magic)
	_, _ = h.Write(header)
	if err := sig.Sign(h, key, nil); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := sig.Serialize(&out); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestForgedPinnedIssuerIsNotAuthority(t *testing.T) {
	p := nativeFixture(t, "dbus")
	p.RpmAuthority.Signature = signHeader(t, p.RpmAuthority.ImmutableHeader, testSigningKey(t), 0x199e2f91fd431d51, time.Unix(1700000001, 0))
	if signer, reason := Verify(p); signer != "" || reason != "rpm_signature_unverified" {
		t.Fatalf("forged official key ID trusted: %q %q", signer, reason)
	}
}

func TestSignedModuleSourceAndEpochBinding(t *testing.T) {
	// Authored header, signed with an explicitly test-only deterministic key.
	// It is never added to the production roots or used by integration tests.
	tags := []struct {
		tag   uint32
		value string
	}{{1000, "nodejs-libs"}, {1001, "18.19.0"}, {1002, "1.module.el9"}, {1022, "x86_64"}, {1044, "nodejs-18.19.0-1.module.el9.src.rpm"}, {5096, "nodejs:18:9020020240101000000:abcdef01"}}
	n := len(tags) + 1
	var data bytes.Buffer
	entries := make([]byte, 16*n)
	put := func(at int, tag, kind, offset, count uint32) {
		binary.BigEndian.PutUint32(entries[at:], tag)
		binary.BigEndian.PutUint32(entries[at+4:], kind)
		binary.BigEndian.PutUint32(entries[at+8:], offset)
		binary.BigEndian.PutUint32(entries[at+12:], count)
	}
	for i, tag := range tags {
		put(16*(i+1), tag.tag, 6, uint32(data.Len()), 1)
		data.WriteString(tag.value)
		data.WriteByte(0)
	}
	put(0, 63, 7, uint32(data.Len()), 16)
	trailer := make([]byte, 16)
	binary.BigEndian.PutUint32(trailer, 63)
	binary.BigEndian.PutUint32(trailer[4:], 7)
	binary.BigEndian.PutUint32(trailer[8:], uint32(-int32(16*n)))
	binary.BigEndian.PutUint32(trailer[12:], 16)
	data.Write(trailer)
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header, uint32(n))
	binary.BigEndian.PutUint32(header[4:], uint32(data.Len()))
	header = append(header, entries...)
	header = append(header, data.Bytes()...)
	identity, err := Parse(header)
	if err != nil {
		t.Fatal(err)
	}
	if identity.SourceName != "nodejs" || identity.SourceVersion != "18.19.0-1.module.el9" || !identity.Module.Modular || identity.Module.Stream != "18" || identity.Version != "0:18.19.0-1.module.el9" {
		t.Fatalf("signed identity = %+v", identity)
	}
	entity := testEntity(t, 0)
	key := entity.PrivateKey
	p := &inventoryv1.Package{Name: identity.Name, Version: identity.Version, Architecture: identity.Architecture, Manager: "rpm", SourceName: identity.SourceName, SourceVersion: identity.SourceVersion, SourceArchitecture: identity.SourceArchitecture, Module: identity.Module, RpmAuthority: &inventoryv1.RpmAuthority{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS, ImmutableHeader: header, Signature: signHeader(t, header, key, key.KeyId, time.Unix(1700000001, 0))}}
	keys := openpgp.EntityList{entity}
	now := time.Unix(1700001000, 0)
	if signer, reason := verify(p, keys, now); signer == "" || reason != "" {
		t.Fatalf("test signature rejected: %q %q", signer, reason)
	}
	for _, mutate := range []func(*inventoryv1.Package){func(p *inventoryv1.Package) { p.Module.Context = "ffffffff" }, func(p *inventoryv1.Package) { p.Module.Version = "9020020240101000001" }, func(p *inventoryv1.Package) { p.SourceVersion = "1:18.19.0-1.module.el9" }} {
		changed := proto.CloneOf(p)
		mutate(changed)
		if signer, reason := verify(changed, keys, now); signer != "" || reason != "rpm_identity_mismatch" {
			t.Fatalf("signed identity was not bound: %q %q", signer, reason)
		}
	}
}

func testEntity(t *testing.T, lifetime uint32) *openpgp.Entity {
	t.Helper()
	entity, err := openpgp.NewEntity("Deterministic RPM authority test", "", "rpm@example.invalid", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, DefaultHash: crypto.SHA256, Rand: bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096)), Time: func() time.Time { return time.Unix(1700000000, 0) }, KeyLifetimeSecs: lifetime})
	if err != nil {
		t.Fatal(err)
	}
	return entity
}

func TestRPMFutureSignatureRevokedAndExpiredRootAreRejected(t *testing.T) {
	for _, kind := range []string{"future-signature", "zero-signature-time", "revoked-root", "expired-root"} {
		t.Run(kind, func(t *testing.T) {
			lifetime := uint32(0)
			if kind == "expired-root" {
				lifetime = 30
			}
			entity := testEntity(t, lifetime)
			p := nativeFixture(t, "dbus")
			created := time.Unix(1700000001, 0)
			if kind == "zero-signature-time" {
				created = time.Unix(0, 0)
			}
			p.RpmAuthority.Signature = signHeader(t, p.RpmAuthority.ImmutableHeader, entity.PrivateKey, entity.PrimaryKey.KeyId, created)
			now := time.Unix(1700001000, 0)
			if kind == "future-signature" {
				now = time.Unix(1700000000, 0)
			}
			if kind == "revoked-root" {
				if err := entity.Revoke(packet.KeyRetired, "controlled test revocation", &packet.Config{Time: func() time.Time { return time.Unix(1700000002, 0) }}); err != nil {
					t.Fatal(err)
				}
			}
			if signer, reason := verify(p, openpgp.EntityList{entity}, now); signer != "" || reason != "rpm_signature_unverified" {
				t.Fatalf("invalid signing authority admitted: %q %q", signer, reason)
			}
		})
	}
}
