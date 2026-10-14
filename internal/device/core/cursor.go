// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"time"

	"github.com/google/uuid"
)

func EncodeCursor(t time.Time, id uuid.UUID) (string, error) {
	if id == uuid.Nil {
		return "", Invalid("page_token")
	}
	var buf [1 + 8 + 16]byte
	buf[0] = 1
	binary.BigEndian.PutUint64(buf[1:9], uint64(t.UTC().UnixMicro()))
	copy(buf[9:], id[:])
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

func DecodeCursor(token string) (time.Time, uuid.UUID, error) {
	if token == "" || len(token) > 512 {
		return time.Time{}, uuid.Nil, Invalid("page_token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 1+8+16 || raw[0] != 1 {
		return time.Time{}, uuid.Nil, Invalid("page_token")
	}
	micros := int64(binary.BigEndian.Uint64(raw[1:9]))
	if micros < 0 {
		return time.Time{}, uuid.Nil, Invalid("page_token")
	}
	when := time.UnixMicro(micros).UTC()
	if when.Year() < 2000 || when.Year() > 2200 {
		return time.Time{}, uuid.Nil, Invalid("page_token")
	}
	id, err := uuid.FromBytes(raw[9:])
	if err != nil || id == uuid.Nil {
		return time.Time{}, uuid.Nil, Invalid("page_token")
	}
	return when, id, nil
}

// EncodeFilteredCursor is EncodeCursor bound to a list's filter: an empty filter
// keeps the plain token; otherwise the token carries the first 16 bytes of the
// filter's SHA-256, so it continues only that filter.
func EncodeFilteredCursor(t time.Time, id uuid.UUID, filter []byte) (string, error) {
	token, err := EncodeCursor(t, id)
	if err != nil || len(filter) == 0 {
		return token, err
	}
	raw, _ := base64.RawURLEncoding.DecodeString(token)
	raw[0] = 2
	digest := sha256.Sum256(filter)
	return base64.RawURLEncoding.EncodeToString(append(raw, digest[:16]...)), nil
}

// DecodeFilteredCursor accepts only a token encoded for the same filter.
func DecodeFilteredCursor(token string, filter []byte) (time.Time, uuid.UUID, error) {
	if len(filter) == 0 {
		return DecodeCursor(token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(token) > 512 || len(raw) != 1+8+16+16 || raw[0] != 2 {
		return time.Time{}, uuid.Nil, Invalid("page_token")
	}
	digest := sha256.Sum256(filter)
	if !bytes.Equal(raw[25:], digest[:16]) {
		return time.Time{}, uuid.Nil, Invalid("page_token")
	}
	raw[0] = 1
	return DecodeCursor(base64.RawURLEncoding.EncodeToString(raw[:25]))
}
