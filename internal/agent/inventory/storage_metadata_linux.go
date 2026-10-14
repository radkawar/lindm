// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"encoding/json"
	"io"
	"slices"
	"strings"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// parseLUKSMetadata consumes native LUKS2 JSON, including public-only capture
// projections in the same shape. UUID and version are not present in this format;
// the caller must cross-check the text header from the same pinned descriptor.
// Only counts and token types survive parsing. Unknown values (including token
// payloads, salts and digests) are streamed past, never decoded into a retained
// map, RawMessage or a public result. Input bytes and nesting are bounded.
func parseLUKSMetadata(reader io.Reader) (*luksSummary, inventoryv1.CollectionStatus) {
	limited := &io.LimitedReader{R: reader, N: maxDetailFile + 1}
	decoder := json.NewDecoder(limited)
	decoder.UseNumber()
	summary := &luksSummary{version: "2"}
	seenSlots, seenTokens := false, false
	err := readLUKSObject(decoder, func(key string) error {
		switch key {
		case "keyslots":
			if seenSlots {
				return errInvalid
			}
			seenSlots = true
			return readLUKSEntries(decoder, false, summary)
		case "tokens":
			if seenTokens {
				return errInvalid
			}
			seenTokens = true
			return readLUKSEntries(decoder, true, summary)
		default:
			return skipLUKSValue(decoder, 0)
		}
	})
	if err == nil {
		_, err = decoder.Token()
		if err == io.EOF && seenSlots && seenTokens {
			if limited.N == 0 {
				return nil, capacity
			}
			slices.Sort(summary.types)
			return summary, success
		}
	}
	if limited.N == 0 {
		return nil, capacity
	}
	return nil, invalid
}

func readLUKSObject(decoder *json.Decoder, field func(string) error) error {
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return errInvalid
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errInvalid
		}
		if err := field(key); err != nil {
			return err
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return errInvalid
	}
	return nil
}

func readLUKSEntries(decoder *json.Decoder, tokens bool, summary *luksSummary) error {
	var seen [32]bool
	return readLUKSObject(decoder, func(key string) error {
		index, err := decimal(key)
		if err != nil || index >= uint64(len(seen)) || seen[index] {
			return errInvalid
		}
		seen[index] = true
		kind := ""
		if err := readLUKSObject(decoder, func(field string) error {
			if field != "type" {
				return skipLUKSValue(decoder, 0)
			}
			if kind != "" {
				return errInvalid
			}
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			value, ok := token.(string)
			if !ok || value == "" || len(value) > 256 || strings.ContainsAny(value, " \t\r\n,") || !nativeText([]byte(value)) {
				return errInvalid
			}
			kind = value
			return nil
		}); err != nil {
			return err
		}
		if kind == "" || (!tokens && kind != "luks2") {
			return errInvalid
		}
		if tokens {
			summary.tokens++
			summary.types = append(summary.types, kind)
		} else {
			summary.keyslots++
		}
		return nil
	})
}

func skipLUKSValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		for decoder.More() {
			if _, err := decoder.Token(); err != nil {
				return err
			}
			if err := skipLUKSValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := skipLUKSValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errInvalid
	}
	_, err = decoder.Token()
	return err
}

// parseUdevProperties accepts the native --query=property format. Captured
// --export-db block records use the same lines with an "E: " record prefix;
// fixture consumers strip that framing per record before calling this parser.
func parseUdevProperties(reader io.Reader) (map[string]string, inventoryv1.CollectionStatus) {
	data, status := readApplicationOutput(reader)
	if status != success {
		return nil, status
	}
	if !nativeText(data) {
		return nil, invalid
	}
	properties := make(map[string]string, 2)
	for line := range strings.SplitSeq(strings.TrimSuffix(string(data), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, invalid
		}
		if key != "ID_BUS" && key != "ID_REVISION" {
			continue
		}
		if _, exists := properties[key]; exists {
			return nil, invalid
		}
		properties[key] = value
	}
	return properties, success
}
