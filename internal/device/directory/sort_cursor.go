// SPDX-License-Identifier: Apache-2.0

package directory

import (
	"encoding/base64"
	"unicode/utf8"

	"github.com/google/uuid"

	"lindm/internal/device/core"
)

// maxSortKeyBytes bounds a device sort key: SearchDevices keys hold at most 80
// characters (4 bytes each in UTF-8), so a page token stays within 512 bytes.
const maxSortKeyBytes = 320

const sortCursorVersion = 2

// encodeSortCursor encodes a device list keyset position: whether the row sorts
// among those without the sort value, its bounded sort key and its ID.
func encodeSortCursor(last bool, key string, id uuid.UUID) (string, error) {
	if id == uuid.Nil || len(key) > maxSortKeyBytes || !utf8.ValidString(key) {
		return "", core.ErrInternalState
	}
	raw := make([]byte, 0, 2+16+len(key))
	raw = append(raw, sortCursorVersion, 0)
	if last {
		raw[1] = 1
	}
	raw = append(raw, id[:]...)
	raw = append(raw, key...)
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeSortCursor(position string) (last bool, key string, id uuid.UUID, err error) {
	raw, decodeErr := base64.RawURLEncoding.DecodeString(position)
	if decodeErr != nil || len(raw) < 2+16 || len(raw) > 2+16+maxSortKeyBytes || raw[0] != sortCursorVersion || raw[1] > 1 {
		return false, "", uuid.Nil, core.Invalid("page_token")
	}
	id, parseErr := uuid.FromBytes(raw[2:18])
	key = string(raw[18:])
	if parseErr != nil || id == uuid.Nil || !utf8.ValidString(key) {
		return false, "", uuid.Nil, core.Invalid("page_token")
	}
	return raw[1] == 1, key, id, nil
}
