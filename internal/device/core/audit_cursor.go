// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"math"
	"time"

	"github.com/google/uuid"
)

// Audit cursors pin the append-only chain head, caller and normalized selection.
// Like other keyset cursors these are positions, never authorization credentials.
// Every page independently requires unrestricted read.audit authority.
type auditCursor struct {
	Snapshot int64
	Occurred time.Time
	ID       uuid.UUID
}

func encodeAuditCursor(cursor auditCursor, actor uuid.UUID, digest [32]byte) string {
	var data [81]byte
	data[0] = 1
	binary.BigEndian.PutUint64(data[1:9], uint64(cursor.Snapshot))
	binary.BigEndian.PutUint64(data[9:17], uint64(cursor.Occurred.UnixMicro()))
	copy(data[17:33], cursor.ID[:])
	copy(data[33:49], actor[:])
	copy(data[49:], digest[:])
	return base64.RawURLEncoding.EncodeToString(data[:])
}

func decodeAuditCursor(token string, actor uuid.UUID, digest [32]byte) (auditCursor, error) {
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(data) != 81 || data[0] != 1 || !bytes.Equal(data[33:49], actor[:]) || !bytes.Equal(data[49:], digest[:]) {
		return auditCursor{}, Invalid("page_token")
	}
	snapshot := binary.BigEndian.Uint64(data[1:9])
	id, err := uuid.FromBytes(data[17:33])
	occurred := time.UnixMicro(int64(binary.BigEndian.Uint64(data[9:17]))).UTC()
	if err != nil || id == uuid.Nil || snapshot > math.MaxInt64 || occurred.Year() < 1 || occurred.Year() > 9999 {
		return auditCursor{}, Invalid("page_token")
	}
	return auditCursor{Snapshot: int64(snapshot), Occurred: occurred, ID: id}, nil
}
