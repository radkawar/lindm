//go:build linux

package inventory

import (
	"context"
	"encoding/json"
	"io"
	"time"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// busctl makes fixed logind D-Bus calls through the existing bounded runner.
// Identities are parsed only to count rows, never copied into the observation.
// Unlike an in-process D-Bus decoder, the native stdout limit also bounds the
// size of a malicious bus reply before allocating its decoded array.
func collectSessions(ctx context.Context) *inventoryv1.SessionCounts {
	return collectSessionCounts(ctx, runNative)
}

func collectSessionCounts(ctx context.Context, run nativeRunner) *inventoryv1.SessionCounts {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	count := func(method, signature string) *inventoryv1.ObservedUint64 {
		var value uint64
		status := run(ctx, backend{name: "busctl", path: "/usr/bin/busctl", args: []string{"--system", "--json=short", "--timeout=5s", "--auto-start=no", "call", "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", method}}, func(reader io.Reader) inventoryv1.CollectionStatus {
			var parsed inventoryv1.CollectionStatus
			value, parsed = parseSessionCount(reader, signature)
			return parsed
		})
		if status != success {
			return &inventoryv1.ObservedUint64{Status: status}
		}
		return number(value, nil)
	}
	return &inventoryv1.SessionCounts{Users: count("ListUsers", "a(uso)"), Sessions: count("ListSessions", "a(susso)")}
}

func parseSessionCount(reader io.Reader, signature string) (uint64, inventoryv1.CollectionStatus) {
	var reply struct {
		Type string            `json:"type"`
		Data []json.RawMessage `json:"data"`
	}
	status := decodeNative(reader, &reply)
	if status != success {
		return 0, status
	}
	if reply.Type != signature || len(reply.Data) != 1 {
		return 0, invalid
	}
	var rows [][]json.RawMessage
	if err := json.Unmarshal(reply.Data[0], &rows); err != nil || rows == nil {
		return 0, invalid
	}
	if len(rows) > 4096 {
		return 0, capacity
	}
	for _, row := range rows {
		uidIndex := 0
		if signature == "a(susso)" {
			if len(row) != 5 {
				return 0, invalid
			}
			uidIndex = 1
		} else if len(row) != 3 {
			return 0, invalid
		}
		for i, field := range row {
			if i == uidIndex {
				var uid uint32
				if err := json.Unmarshal(field, &uid); err != nil {
					return 0, invalid
				}
			} else {
				var text string
				if err := json.Unmarshal(field, &text); err != nil || len(text) > 4096 {
					return 0, invalid
				}
			}
		}
	}
	return uint64(len(rows)), success
}
