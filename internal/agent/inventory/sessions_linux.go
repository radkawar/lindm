//go:build linux

package inventory

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"time"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// busctl makes fixed logind D-Bus calls through the existing bounded runner.
// Unlike an in-process D-Bus decoder, the native stdout limit also bounds the
// size of a malicious bus reply before allocating its decoded array.
func collectSessions(ctx context.Context) *inventoryv1.SessionCounts {
	return collectSessionCounts(ctx, runNative)
}

// busctlJSONSince is the first systemd release whose busctl accepts --json
// (v240). EL8 ships systemd 239, whose busctl rejects the option; it is read
// through busctl's fixed text format_cmdline output instead.
const busctlJSONSince = 240

func busctl(args ...string) backend {
	return backend{name: "busctl", path: "/usr/bin/busctl", args: args}
}

func collectSessionCounts(ctx context.Context, run nativeRunner) *inventoryv1.SessionCounts {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result := &inventoryv1.SessionCounts{}
	// The JSON interface is used unless busctl itself failed and natively
	// reports a systemd release that predates it. Other failures stand.
	text, probed := false, false
	call := func(jsonArgs, textArgs []string, parseJSON, parseText func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		if !text {
			status := run(ctx, busctl(append([]string{"--system", "--json=short", "--timeout=5s", "--auto-start=no"}, jsonArgs...)...), parseJSON)
			if status != commandFailure || probed {
				return status
			}
			probed = true
			release, versionStatus := busctlRelease(ctx, run)
			if versionStatus != success || release >= busctlJSONSince {
				return status
			}
			text = true
		}
		return run(ctx, busctl(append([]string{"--system", "--timeout=5s", "--auto-start=no"}, textArgs...)...), parseText)
	}
	var sessions [][]json.RawMessage
	count := func(method, signature string) *inventoryv1.ObservedUint64 {
		var rows [][]json.RawMessage
		args := []string{"call", "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", method}
		status := call(args, args, func(reader io.Reader) inventoryv1.CollectionStatus {
			var parsed inventoryv1.CollectionStatus
			rows, parsed = parseSessionRows(reader, signature)
			return parsed
		}, func(reader io.Reader) inventoryv1.CollectionStatus {
			var parsed inventoryv1.CollectionStatus
			rows, parsed = parseSessionRowsText(reader, signature)
			return parsed
		})
		if status != success {
			return &inventoryv1.ObservedUint64{Status: status}
		}
		if method == "ListSessions" {
			sessions = rows
		}
		return number(uint64(len(rows)), nil)
	}
	result.Users = count("ListUsers", "a(uso)")
	result.Sessions = count("ListSessions", "a(susso)")
	result.ActiveSessions = &inventoryv1.ActiveSessions{Status: result.Sessions.Status}
	if result.Sessions.Status != success {
		return result
	}
	for _, row := range sessions {
		var path string
		if err := json.Unmarshal(row[4], &path); err != nil || !validSessionPath(path) {
			result.ActiveSessions = &inventoryv1.ActiveSessions{Status: invalid}
			return result
		}
		var session *inventoryv1.ActiveSession
		status := call(
			[]string{"call", "org.freedesktop.login1", path, "org.freedesktop.DBus.Properties", "GetAll", "s", "org.freedesktop.login1.Session"},
			append([]string{"get-property", "org.freedesktop.login1", path, "org.freedesktop.login1.Session"}, textSessionProperties...),
			func(reader io.Reader) inventoryv1.CollectionStatus {
				var parsed inventoryv1.CollectionStatus
				session, parsed = parseActiveSession(reader)
				return parsed
			}, func(reader io.Reader) inventoryv1.CollectionStatus {
				var parsed inventoryv1.CollectionStatus
				session, parsed = parseActiveSessionText(reader)
				return parsed
			})
		if status != success {
			result.ActiveSessions = &inventoryv1.ActiveSessions{Status: status}
			return result
		}
		if session != nil {
			result.ActiveSessions.Sessions = append(result.ActiveSessions.Sessions, session)
		}
	}
	return result
}

func parseSessionRows(reader io.Reader, signature string) ([][]json.RawMessage, inventoryv1.CollectionStatus) {
	var reply struct {
		Type string            `json:"type"`
		Data []json.RawMessage `json:"data"`
	}
	status := decodeNative(reader, &reply)
	if status != success {
		return nil, status
	}
	if reply.Type != signature || len(reply.Data) != 1 {
		return nil, invalid
	}
	var rows [][]json.RawMessage
	if err := json.Unmarshal(reply.Data[0], &rows); err != nil || rows == nil {
		return nil, invalid
	}
	if len(rows) > 4096 {
		return nil, capacity
	}
	for _, row := range rows {
		uidIndex := 0
		if signature == "a(susso)" {
			if len(row) != 5 {
				return nil, invalid
			}
			uidIndex = 1
		} else if len(row) != 3 {
			return nil, invalid
		}
		for i, field := range row {
			if i == uidIndex {
				var uid uint32
				if string(field) == "null" || json.Unmarshal(field, &uid) != nil {
					return nil, invalid
				}
			} else {
				var text string
				if string(field) == "null" || json.Unmarshal(field, &text) != nil || len(text) > 4096 {
					return nil, invalid
				}
			}
		}
	}
	return rows, success
}

func validSessionPath(path string) bool {
	suffix, ok := strings.CutPrefix(path, "/org/freedesktop/login1/session/")
	if !ok || suffix == "" {
		return false
	}
	for _, c := range suffix {
		if c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

type sessionProperty struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

func parseActiveSession(reader io.Reader) (*inventoryv1.ActiveSession, inventoryv1.CollectionStatus) {
	var reply struct {
		Type string                       `json:"type"`
		Data []map[string]sessionProperty `json:"data"`
	}
	if status := decodeNative(reader, &reply); status != success {
		return nil, status
	}
	if reply.Type != "a{sv}" || len(reply.Data) != 1 || reply.Data[0] == nil {
		return nil, invalid
	}
	properties := reply.Data[0]
	active := sessionBoolProperty(properties, "Active")
	if active.Status != success {
		return nil, active.Status
	}
	if !active.Value {
		return nil, success
	}
	result := &inventoryv1.ActiveSession{
		UserName:     sessionStringProperty(properties, "Name"),
		SessionClass: sessionStringProperty(properties, "Class"),
		SessionType:  sessionStringProperty(properties, "Type"),
		Remote:       sessionBoolProperty(properties, "Remote"),
		Seat:         &inventoryv1.ObservedString{Status: unavailable},
	}
	seatAbsent := true
	if seat, ok := properties["Seat"]; ok {
		var fields []json.RawMessage
		var name, path string
		if seat.Type != "(so)" || json.Unmarshal(seat.Data, &fields) != nil || len(fields) != 2 ||
			string(fields[0]) == "null" || string(fields[1]) == "null" ||
			json.Unmarshal(fields[0], &name) != nil || json.Unmarshal(fields[1], &path) != nil {
			result.Seat.Status = invalid
		} else {
			result.Seat = observed(name, nil)
			seatAbsent = name == ""
		}
	}
	// Only native, successfully decoded context proves that a seat does not
	// apply. A local graphical user's missing seat remains a collection failure.
	if seatAbsent && result.Seat.Status == unavailable &&
		result.SessionClass.Status == success && result.SessionType.Status == success && result.Remote.Status == success &&
		(result.SessionClass.Value == "manager" || result.SessionClass.Value == "background" ||
			result.Remote.Value || result.SessionType.Value == "tty") {
		result.Seat.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE
	}
	return result, success
}

func sessionStringProperty(properties map[string]sessionProperty, name string) *inventoryv1.ObservedString {
	property, ok := properties[name]
	if !ok {
		return &inventoryv1.ObservedString{Status: unavailable}
	}
	var value string
	if property.Type != "s" || string(property.Data) == "null" || json.Unmarshal(property.Data, &value) != nil {
		return &inventoryv1.ObservedString{Status: invalid}
	}
	return observed(value, nil)
}

func sessionBoolProperty(properties map[string]sessionProperty, name string) *inventoryv1.ObservedBool {
	property, ok := properties[name]
	if !ok {
		return &inventoryv1.ObservedBool{Status: unavailable}
	}
	var value bool
	if property.Type != "b" || string(property.Data) == "null" || json.Unmarshal(property.Data, &value) != nil {
		return &inventoryv1.ObservedBool{Status: invalid}
	}
	return boolean(value, nil)
}
