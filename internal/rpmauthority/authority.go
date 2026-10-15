// SPDX-License-Identifier: Apache-2.0

// Package rpmauthority verifies installed RPM identity, not repository or product
// membership. Only immutable signed header bytes confer package authority.
package rpmauthority

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

const Fingerprint = "567E347AD0044ADE55BA8A5F199E2F91FD431D51"
const MaxHeaderBytes = 1 << 20

//go:embed redhat-release2.asc
var releaseRoot []byte

var roots = sync.OnceValues(func() (openpgp.EntityList, error) {
	keys, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(releaseRoot))
	if err != nil || len(keys) != 1 || strings.ToUpper(hex.EncodeToString(keys[0].PrimaryKey.Fingerprint)) != Fingerprint {
		return nil, errors.New("rpmauthority: invalid pinned release root")
	}
	return keys, nil
})

// ProtonMail caches verified key bindings; protect the shared parsed root.
var rootMu sync.Mutex

var rootDigest = sha256.Sum256(releaseRoot)

// PolicyIdentity binds cached coverage to the exact embedded public root and
// its current signing validity. Revocation/expiry cannot leave a previously
// admitted signer implicitly covered, even while inventory is still fresh.
func PolicyIdentity() ([32]byte, bool) {
	keys, err := roots()
	if err != nil {
		return rootDigest, false
	}
	rootMu.Lock()
	defer rootMu.Unlock()
	now := time.Now()
	config := &packet.Config{Time: func() time.Time { return now }}
	key, ok := keys[0].SigningKeyById(now, keys[0].PrimaryKey.KeyId, config)
	return rootDigest, ok && bytes.Equal(key.PublicKey.Fingerprint, keys[0].PrimaryKey.Fingerprint)
}

var magic = []byte{0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0}
var errHeader = errors.New("rpmauthority: invalid immutable RPM header")

// Identity is extracted only from the immutable region. Source RPM filenames
// contain no epoch: SourceVersion retains exactly that signed version-release,
// rather than borrowing a possibly different binary epoch.
type Identity struct {
	Name, Version, Architecture, SourceName, SourceVersion, SourceArchitecture string
	Module                                                                     *inventoryv1.ModuleObservation
}

// Parse returns identity from headerGet(RPMTAG_HEADERIMMUTABLE)'s exact region.
// It does not verify the signature; callers must never treat parsing as trust.
func Parse(raw []byte) (Identity, error) {
	var result Identity
	if len(raw) < 40 || len(raw) > MaxHeaderBytes {
		return result, errHeader
	}
	n, size := int(binary.BigEndian.Uint32(raw)), int(binary.BigEndian.Uint32(raw[4:]))
	if n < 2 || n > 65535 || size < 16 || 8+16*n+size != len(raw) {
		return result, errHeader
	}
	entries, data := raw[8:8+16*n], raw[8+16*n:]
	if binary.BigEndian.Uint32(entries) != 63 || binary.BigEndian.Uint32(entries[4:]) != 7 || binary.BigEndian.Uint32(entries[12:]) != 16 {
		return result, errHeader
	}
	trailerOffset := int(binary.BigEndian.Uint32(entries[8:]))
	if trailerOffset != size-16 {
		return result, errHeader
	}
	trailer := data[trailerOffset:]
	if binary.BigEndian.Uint32(trailer) != 63 || binary.BigEndian.Uint32(trailer[4:]) != 7 || int32(binary.BigEndian.Uint32(trailer[8:])) != -int32(16*n) || binary.BigEndian.Uint32(trailer[12:]) != 16 {
		return result, errHeader
	}
	values := make(map[uint32]string, 7)
	var previous uint32
	for i := 1; i < n; i++ {
		e := entries[16*i : 16*(i+1)]
		tag, kind, offset, count := binary.BigEndian.Uint32(e), binary.BigEndian.Uint32(e[4:]), int(binary.BigEndian.Uint32(e[8:])), binary.BigEndian.Uint32(e[12:])
		if tag <= previous || tag < 100 || offset < 0 || offset >= trailerOffset {
			return result, errHeader
		}
		previous = tag
		switch tag {
		case 1000, 1001, 1002, 1022, 1044, 5096: // NAME, VERSION, RELEASE, ARCH, SOURCERPM, MODULARITYLABEL
			if kind != 6 || count != 1 {
				return result, errHeader
			}
			end := bytes.IndexByte(data[offset:trailerOffset], 0)
			if end < 0 || end > 2048 || !utf8.Valid(data[offset:offset+end]) {
				return result, errHeader
			}
			value := string(data[offset : offset+end])
			if value == "" || strings.IndexFunc(value, func(r rune) bool { return r <= ' ' || r == 127 }) >= 0 {
				return result, errHeader
			}
			values[tag] = value
		case 1003: // EPOCH is optional; absence means zero in RPM ordering.
			if kind != 4 || count != 1 || offset%4 != 0 || offset+4 > trailerOffset {
				return result, errHeader
			}
			values[tag] = strconv.FormatUint(uint64(binary.BigEndian.Uint32(data[offset:])), 10)
		}
	}
	for _, tag := range []uint32{1000, 1001, 1002, 1022, 1044} {
		if values[tag] == "" {
			return result, errHeader
		}
	}
	epoch := values[1003]
	if epoch == "" {
		epoch = "0"
	}
	result.Name, result.Version, result.Architecture = values[1000], epoch+":"+values[1001]+"-"+values[1002], values[1022]
	result.SourceArchitecture = "src"
	source, ok := strings.CutSuffix(values[1044], ".src.rpm")
	if !ok {
		source, ok = strings.CutSuffix(values[1044], ".nosrc.rpm")
		result.SourceArchitecture = "nosrc"
	}
	last := strings.LastIndexByte(source, '-')
	if !ok || last <= 0 {
		return Identity{}, errHeader
	}
	before := strings.LastIndexByte(source[:last], '-')
	if before <= 0 || before+1 == last || last+1 == len(source) {
		return Identity{}, errHeader
	}
	result.SourceName, result.SourceVersion = source[:before], source[before+1:]
	if len(result.SourceName) > 512 {
		return Identity{}, errHeader
	}
	result.Module = &inventoryv1.ModuleObservation{Status: inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS}
	if label := values[5096]; label != "" {
		parts := strings.Split(label, ":")
		if len(parts) != 4 || parts[0] == "" || parts[1] == "" || parts[2] == "" || parts[3] == "" {
			return Identity{}, errHeader
		}
		if _, err := strconv.ParseUint(parts[2], 10, 64); err != nil {
			return Identity{}, errHeader
		}
		result.Module.Modular, result.Module.Name, result.Module.Stream, result.Module.Version, result.Module.Context = true, parts[0], parts[1], parts[2], parts[3]
	}
	return result, nil
}

// Verify independently binds every matching input to the signed immutable
// header, then checks the actual signature with the pinned full public key.
// Display vendor strings, key IDs, local RPM trust and claimed signer fields
// are deliberately absent from this decision. A signer proves Red Hat origin,
// NOT RHEL product membership: coverage must separately prove that membership.
func Verify(pkg *inventoryv1.Package) (string, string) {
	keys, err := roots()
	if err != nil {
		return "", "rpm_authority_unavailable"
	}
	rootMu.Lock()
	defer rootMu.Unlock()
	return verify(pkg, keys, time.Now())
}

func verify(pkg *inventoryv1.Package, keys openpgp.EntityList, now time.Time) (string, string) {
	a := pkg.GetRpmAuthority()
	if pkg.GetManager() != "rpm" || a.GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS {
		return "", "rpm_authority_unavailable"
	}
	if len(a.GetSignature()) == 0 {
		return "", "rpm_unsigned"
	}
	identity, err := Parse(a.GetImmutableHeader())
	if err != nil {
		return "", "rpm_header_invalid"
	}
	if identity.Name != pkg.GetName() || identity.Version != pkg.GetVersion() || identity.Architecture != pkg.GetArchitecture() || identity.SourceName != pkg.GetSourceName() || identity.SourceVersion != pkg.GetSourceVersion() || identity.SourceArchitecture != pkg.GetSourceArchitecture() || !proto.Equal(identity.Module, pkg.GetModule()) {
		return "", "rpm_identity_mismatch"
	}
	if len(a.GetSignature()) > 16384 {
		return "", "rpm_signature_unverified"
	}
	r := bytes.NewReader(a.GetSignature())
	p, err := packet.Read(r)
	sig, ok := p.(*packet.Signature)
	if err != nil || !ok || r.Len() != 0 || sig.SigType != packet.SigTypeBinary || (sig.Hash != crypto.SHA256 && sig.Hash != crypto.SHA384 && sig.Hash != crypto.SHA512) {
		return "", "rpm_signature_unverified"
	}
	if now.IsZero() || sig.CreationTime.Unix() <= 0 || sig.CreationTime.After(now) {
		return "", "rpm_signature_unverified"
	}
	config := &packet.Config{Time: func() time.Time { return now }}
	// Issuer IDs only select candidates within the pinned keyring; they are
	// never authority. Verify key bindings and the exact detached signature.
	verified, signer, err := openpgp.VerifyDetachedSignature(keys, io.MultiReader(bytes.NewReader(magic), bytes.NewReader(a.GetImmutableHeader())), bytes.NewReader(a.GetSignature()), config)
	if err != nil || signer == nil || verified.IssuerKeyId == nil {
		return "", "rpm_signature_unverified"
	}
	// Signature-time validity is not sufficient: the root/signing key must
	// also remain non-revoked and unexpired at admission time.
	key, ok := signer.SigningKeyById(now, *verified.IssuerKeyId, config)
	if !ok || !bytes.Equal(key.PublicKey.Fingerprint, signer.PrimaryKey.Fingerprint) {
		return "", "rpm_signature_unverified"
	}
	return strings.ToUpper(hex.EncodeToString(signer.PrimaryKey.Fingerprint)), ""
}
