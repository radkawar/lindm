// SPDX-License-Identifier: Apache-2.0

// Package assistancerecording holds the support-recording contract shared by
// the session helper and the server: recording policy bounds, the sealed
// segment format and the WebM stream the helper records.
//
// Each recording has its own key. The helper runs HPKE (RFC 9180) in export-only
// mode to the deployment's ML-KEM-768+X25519 recipient key and exports one
// AES-256-GCM segment key. Segment nonces are the segment sequence; additional
// data binds recording identity, sequence and finality, so reordering,
// splicing between recordings and undetected truncation of a complete
// recording fail authentication. Only the holder of the deployment private key
// can derive the segment key.
//
// Non-goals: no key rotation or re-encryption of retained recordings, no
// transport, no storage and no media decoding.
package assistancerecording

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/google/uuid"
)

const (
	// SegmentPlaintextBytes bounds one segment so a sealed segment fits the
	// 256 KiB session-socket message bound with room for framing.
	SegmentPlaintextBytes = 192 << 10
	// SegmentOverhead is the AES-GCM tag.
	SegmentOverhead       = 16
	MaxSegmentBytes       = SegmentPlaintextBytes + SegmentOverhead
	MaxSegments           = 1 << 16
	EncapsulatedKeyBytes  = 1120
	PublicKeyBytes        = 1216
	PrivateKeySeedBytes   = 32
	MinRecordingBytes     = 1 << 20
	MaxRecordingBytes     = 1 << 30
	MaxRetentionDays      = 365
	MediaType             = "video/webm"
	segmentKeyContext     = "lindm assistance recording v1 segment key"
	recordingInfoPrefix   = "lindm assistance recording v1"
	segmentNonceSizeBytes = 12
)

var (
	ErrKey      = errors.New("recording_key_invalid")
	ErrSequence = errors.New("recording_sequence_invalid")
	ErrSegment  = errors.New("recording_segment_invalid")
)

func suite() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return hpke.MLKEM768X25519(), hpke.HKDFSHA256(), hpke.ExportOnly()
}

func info(recordingID uuid.UUID) []byte {
	return append([]byte(recordingInfoPrefix+"\x00"), recordingID[:]...)
}

// KeyID is the lowercase hex SHA-256 of a recipient public key.
func KeyID(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

// Recipient is the deployment's recording private key. It never leaves the
// server process and is used only for authorized retrieval.
type Recipient struct {
	key    hpke.PrivateKey
	public []byte
	keyID  string
}

// NewRecipient derives the recipient from exactly 32 CSPRNG bytes.
func NewRecipient(seed []byte) (*Recipient, error) {
	if len(seed) != PrivateKeySeedBytes {
		return nil, ErrKey
	}
	kem, _, _ := suite()
	key, err := kem.NewPrivateKey(seed)
	if err != nil {
		return nil, ErrKey
	}
	public := key.PublicKey().Bytes()
	if len(public) != PublicKeyBytes {
		return nil, ErrKey
	}
	return &Recipient{key: key, public: public, keyID: KeyID(public)}, nil
}

// PublicKey returns a copy of the recipient public key.
func (r *Recipient) PublicKey() []byte { return append([]byte(nil), r.public...) }

func (r *Recipient) KeyID() string { return r.keyID }

// Opener decrypts the segments of one recording.
type Opener struct {
	aead cipher.AEAD
	id   uuid.UUID
}

// Open derives the segment key of recordingID from its encapsulated key.
func (r *Recipient) Open(recordingID uuid.UUID, encapsulated []byte) (*Opener, error) {
	if len(encapsulated) != EncapsulatedKeyBytes || recordingID == uuid.Nil {
		return nil, ErrKey
	}
	_, kdf, aead := suite()
	recipient, err := hpke.NewRecipient(encapsulated, r.key, kdf, aead, info(recordingID))
	if err != nil {
		return nil, ErrKey
	}
	key, err := recipient.Export(segmentKeyContext, 32)
	if err != nil {
		return nil, ErrKey
	}
	gcm, err := segmentAEAD(key)
	if err != nil {
		return nil, err
	}
	return &Opener{aead: gcm, id: recordingID}, nil
}

// Open authenticates and decrypts one segment.
func (o *Opener) Open(sequence uint32, final bool, ciphertext []byte) ([]byte, error) {
	if sequence >= MaxSegments || len(ciphertext) < SegmentOverhead || len(ciphertext) > MaxSegmentBytes {
		return nil, ErrSegment
	}
	nonce := segmentNonce(sequence)
	plaintext, err := o.aead.Open(nil, nonce[:], ciphertext, segmentAAD(o.id, sequence, final))
	if err != nil {
		return nil, ErrSegment
	}
	return plaintext, nil
}

// Sealer encrypts the segments of one recording in order. It is not safe for
// concurrent use.
type Sealer struct {
	aead         cipher.AEAD
	id           uuid.UUID
	encapsulated []byte
	next         uint32
	finished     bool
}

// NewSealer establishes a fresh segment key for recordingID. keyID must match
// publicKey so a substituted key cannot be presented under another identity.
func NewSealer(publicKey []byte, keyID string, recordingID uuid.UUID) (*Sealer, error) {
	if len(publicKey) != PublicKeyBytes || recordingID == uuid.Nil || subtle.ConstantTimeCompare([]byte(KeyID(publicKey)), []byte(keyID)) != 1 {
		return nil, ErrKey
	}
	kem, kdf, aead := suite()
	public, err := kem.NewPublicKey(publicKey)
	if err != nil {
		return nil, ErrKey
	}
	encapsulated, sender, err := hpke.NewSender(public, kdf, aead, info(recordingID))
	if err != nil {
		return nil, ErrKey
	}
	key, err := sender.Export(segmentKeyContext, 32)
	if err != nil {
		return nil, ErrKey
	}
	gcm, err := segmentAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(encapsulated) != EncapsulatedKeyBytes {
		return nil, ErrKey
	}
	return &Sealer{aead: gcm, id: recordingID, encapsulated: encapsulated}, nil
}

// EncapsulatedKey is carried with segment zero.
func (s *Sealer) EncapsulatedKey() []byte { return append([]byte(nil), s.encapsulated...) }

// Next is the sequence of the next segment.
func (s *Sealer) Next() uint32 { return s.next }

// Seal encrypts the next segment. After a final segment no other is sealed.
func (s *Sealer) Seal(final bool, plaintext []byte) (uint32, []byte, error) {
	if s.finished || s.next >= MaxSegments || (s.next == MaxSegments-1 && !final) {
		return 0, nil, ErrSequence
	}
	if len(plaintext) > SegmentPlaintextBytes {
		return 0, nil, ErrSegment
	}
	sequence := s.next
	nonce := segmentNonce(sequence)
	sealed := s.aead.Seal(nil, nonce[:], plaintext, segmentAAD(s.id, sequence, final))
	s.next++
	s.finished = final
	return sequence, sealed, nil
}

func segmentAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrKey
	}
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return nil, ErrKey
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrKey
	}
	return gcm, nil
}

func segmentNonce(sequence uint32) [segmentNonceSizeBytes]byte {
	var nonce [segmentNonceSizeBytes]byte
	binary.BigEndian.PutUint32(nonce[segmentNonceSizeBytes-4:], sequence)
	return nonce
}

func segmentAAD(id uuid.UUID, sequence uint32, final bool) []byte {
	aad := make([]byte, 0, len(recordingInfoPrefix)+16+5)
	aad = append(aad, recordingInfoPrefix...)
	aad = append(aad, id[:]...)
	aad = binary.BigEndian.AppendUint32(aad, sequence)
	if final {
		return append(aad, 1)
	}
	return append(aad, 0)
}
