package dispatch

import (
	"encoding/base64"
	"encoding/binary"
	"math"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	"lindm/internal/device/core"
)

func TestProfileRevisionCursor(t *testing.T) {
	id := uuid.New()
	for _, before := range []int64{0, 1, 200, math.MaxInt64} {
		token := EncodeProfileRevisionCursor(id, before)
		got, err := decodeProfileRevisionCursor(token, id)
		if err != nil || got != before {
			t.Fatalf("round trip %d: got %d, %v", before, got, err)
		}
	}
	var overflow [25]byte
	overflow[0] = 'R'
	copy(overflow[1:17], id[:])
	binary.BigEndian.PutUint64(overflow[17:], uint64(math.MaxInt64)+1)
	for _, token := range []string{"invalid", core.EncodeProfileCursor(id), EncodeProfileRevisionCursor(uuid.New(), 1), base64.RawURLEncoding.EncodeToString(overflow[:])} {
		if _, err := decodeProfileRevisionCursor(token, id); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("accepted invalid cursor %q: %v", token, err)
		}
	}
	binary.BigEndian.PutUint64(overflow[17:], 0)
	if _, err := decodeProfileRevisionCursor(base64.RawURLEncoding.EncodeToString(overflow[:]), id); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("accepted zero cursor: %v", err)
	}
}
