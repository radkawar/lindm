package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuditCursorBindsCallerSelectionAndSnapshot(t *testing.T) {
	actor := uuid.MustParse("5b1dcd2c-b257-4da4-a16e-57458454eefe")
	id := uuid.MustParse("fabdfd71-c01c-49bc-8f14-6588ffb4d4e0")
	digest := sha256.Sum256([]byte("normalized selection"))
	cursor := auditCursor{Snapshot: 41, Occurred: time.Date(2026, 10, 5, 0, 0, 0, 123000, time.UTC), ID: id}
	token := encodeAuditCursor(cursor, actor, digest)
	got, err := decodeAuditCursor(token, actor, digest)
	if err != nil || got != cursor {
		t.Fatalf("audit cursor round trip: %+v %v", got, err)
	}
	if _, err := decodeAuditCursor(token, id, digest); err == nil {
		t.Fatal("cursor changed caller")
	}
	if _, err := decodeAuditCursor(token, actor, sha256.Sum256([]byte("another selection"))); err == nil {
		t.Fatal("cursor changed selection")
	}
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint64(data[1:9], ^uint64(0))
	for _, malformed := range []string{"", "not-a-cursor", token[:len(token)-1], base64.RawURLEncoding.EncodeToString(data)} {
		if _, err := decodeAuditCursor(malformed, actor, digest); err == nil {
			t.Fatalf("malformed audit cursor accepted: %q", malformed)
		}
	}
}
