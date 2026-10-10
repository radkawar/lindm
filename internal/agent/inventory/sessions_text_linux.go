//go:build linux

package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// systemd 239's busctl prints one reply per line through format_cmdline: the
// signature, then space-separated values. Arrays print their element count,
// structs print their members inline, and strings/object paths are quoted with
// systemd cescape (\a \b \f \n \r \t \v \\ \" \' or three-digit octal). The
// text is converted into the JSON shape busctl ≥240 emits so both formats share
// one set of logind validation rules.

// textSessionProperties are read with get-property, one output line each, in
// this order. GetAll's a{sv} dump is not used because its text form has no
// unambiguous framing for unknown variant contents.
var textSessionProperties = []string{"Active", "Name", "Class", "Type", "Remote", "Seat"}

var textSessionSignatures = map[string]string{"Active": "b", "Name": "s", "Class": "s", "Type": "s", "Remote": "b", "Seat": "(so)"}

type busctlField struct {
	value  string
	quoted bool
}

func busctlRelease(ctx context.Context, run nativeRunner) (int, inventoryv1.CollectionStatus) {
	release := 0
	status := run(ctx, busctl("--version"), func(reader io.Reader) inventoryv1.CollectionStatus {
		lines, status := busctlLines(reader)
		if status != success {
			return status
		}
		rest, ok := strings.CutPrefix(lines[0], "systemd ")
		if !ok {
			return invalid
		}
		digits, _, _ := strings.Cut(rest, " ")
		value, err := strconv.Atoi(digits)
		if err != nil || value <= 0 || strconv.Itoa(value) != digits {
			return invalid
		}
		release = value
		return success
	})
	return release, status
}

// busctlLines returns complete newline-terminated lines of bounded output.
func busctlLines(reader io.Reader) ([]string, inventoryv1.CollectionStatus) {
	data, err := io.ReadAll(io.LimitReader(reader, maxDetailFile+1))
	if err != nil {
		return nil, invalid
	}
	if len(data) > maxDetailFile {
		return nil, capacity
	}
	text := string(data)
	if !strings.HasSuffix(text, "\n") || !utf8.ValidString(text) {
		return nil, invalid
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n"), success
}

func busctlFields(line string) ([]busctlField, bool) {
	var fields []busctlField
	for i := 0; i < len(line); {
		if len(fields) > 0 {
			if line[i] != ' ' || i+1 == len(line) {
				return nil, false
			}
			i++
		}
		if line[i] != '"' {
			start := i
			for i < len(line) && line[i] != ' ' && line[i] != '"' {
				i++
			}
			if i == start {
				return nil, false
			}
			fields = append(fields, busctlField{value: line[start:i]})
			continue
		}
		var value strings.Builder
		for i++; ; i++ {
			if i == len(line) {
				return nil, false
			}
			c := line[i]
			if c == '"' {
				i++
				break
			}
			if c < ' ' || c >= 127 {
				return nil, false
			}
			if c != '\\' {
				value.WriteByte(c)
				continue
			}
			if i++; i == len(line) {
				return nil, false
			}
			switch e := line[i]; e {
			case 'a':
				value.WriteByte('\a')
			case 'b':
				value.WriteByte('\b')
			case 'f':
				value.WriteByte('\f')
			case 'n':
				value.WriteByte('\n')
			case 'r':
				value.WriteByte('\r')
			case 't':
				value.WriteByte('\t')
			case 'v':
				value.WriteByte('\v')
			case '\\', '"', '\'':
				value.WriteByte(e)
			default:
				if i+3 > len(line) {
					return nil, false
				}
				octal, err := strconv.ParseUint(line[i:i+3], 8, 8)
				if err != nil {
					return nil, false
				}
				value.WriteByte(byte(octal))
				i += 2
			}
		}
		if !utf8.ValidString(value.String()) {
			return nil, false
		}
		fields = append(fields, busctlField{value: value.String(), quoted: true})
	}
	return fields, len(fields) > 0
}

func parseSessionRowsText(reader io.Reader, signature string) ([][]json.RawMessage, inventoryv1.CollectionStatus) {
	lines, status := busctlLines(reader)
	if status != success {
		return nil, status
	}
	if len(lines) != 1 {
		return nil, invalid
	}
	fields, ok := busctlFields(lines[0])
	if !ok || len(fields) < 2 || fields[0].quoted || fields[0].value != signature || fields[1].quoted {
		return nil, invalid
	}
	count, err := strconv.ParseUint(fields[1].value, 10, 32)
	if err != nil || strconv.FormatUint(count, 10) != fields[1].value {
		return nil, invalid
	}
	if count > 4096 {
		return nil, capacity
	}
	members := strings.TrimSuffix(strings.TrimPrefix(signature, "a("), ")")
	values := fields[2:]
	if uint64(len(values)) != count*uint64(len(members)) {
		return nil, invalid
	}
	rows := make([][]any, 0, count)
	for len(values) > 0 {
		row := make([]any, len(members))
		for i, kind := range []byte(members) {
			field := values[i]
			if kind == 'u' {
				uid, err := strconv.ParseUint(field.value, 10, 32)
				if field.quoted || err != nil || strconv.FormatUint(uid, 10) != field.value {
					return nil, invalid
				}
				row[i] = uid
			} else {
				if !field.quoted {
					return nil, invalid
				}
				row[i] = field.value
			}
		}
		rows = append(rows, row)
		values = values[len(members):]
	}
	document, err := json.Marshal(map[string]any{"type": signature, "data": []any{rows}})
	if err != nil {
		return nil, invalid
	}
	return parseSessionRows(bytes.NewReader(document), signature)
}

func parseActiveSessionText(reader io.Reader) (*inventoryv1.ActiveSession, inventoryv1.CollectionStatus) {
	lines, status := busctlLines(reader)
	if status != success {
		return nil, status
	}
	if len(lines) != len(textSessionProperties) {
		return nil, invalid
	}
	properties := make(map[string]map[string]any, len(textSessionProperties))
	for i, name := range textSessionProperties {
		fields, ok := busctlFields(lines[i])
		if !ok || fields[0].quoted {
			return nil, invalid
		}
		signature, values := fields[0].value, fields[1:]
		var data any
		// A different native type is retained so the shared rules classify that
		// one property exactly as they would a JSON reply of that type.
		switch {
		case signature != textSessionSignatures[name]:
		case signature == "b" && len(values) == 1 && !values[0].quoted && (values[0].value == "true" || values[0].value == "false"):
			data = values[0].value == "true"
		case signature == "s" && len(values) == 1 && values[0].quoted:
			data = values[0].value
		case signature == "(so)" && len(values) == 2 && values[0].quoted && values[1].quoted:
			data = []string{values[0].value, values[1].value}
		default:
			return nil, invalid
		}
		properties[name] = map[string]any{"type": signature, "data": data}
	}
	document, err := json.Marshal(map[string]any{"type": "a{sv}", "data": []any{properties}})
	if err != nil {
		return nil, invalid
	}
	return parseActiveSession(bytes.NewReader(document))
}
