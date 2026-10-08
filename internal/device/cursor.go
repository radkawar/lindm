package device

import (
	"encoding/base64"
	"encoding/binary"
	"time"

	"github.com/google/uuid"
)

func encodeCursor(t time.Time, id uuid.UUID) (string, error) {
	if id == uuid.Nil {
		return "", invalid("page_token")
	}
	var buf [1 + 8 + 16]byte
	buf[0] = 1
	binary.BigEndian.PutUint64(buf[1:9], uint64(t.UTC().UnixMicro()))
	copy(buf[9:], id[:])
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

func decodeCursor(token string) (time.Time, uuid.UUID, error) {
	if token == "" || len(token) > 512 {
		return time.Time{}, uuid.Nil, invalid("page_token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 1+8+16 || raw[0] != 1 {
		return time.Time{}, uuid.Nil, invalid("page_token")
	}
	micros := int64(binary.BigEndian.Uint64(raw[1:9]))
	if micros < 0 {
		return time.Time{}, uuid.Nil, invalid("page_token")
	}
	when := time.UnixMicro(micros).UTC()
	if when.Year() < 2000 || when.Year() > 2200 {
		return time.Time{}, uuid.Nil, invalid("page_token")
	}
	id, err := uuid.FromBytes(raw[9:])
	if err != nil || id == uuid.Nil {
		return time.Time{}, uuid.Nil, invalid("page_token")
	}
	return when, id, nil
}
