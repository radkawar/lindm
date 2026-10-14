// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

type redHatJSONChunkReader struct {
	io.Reader
	size int
}

func (r redHatJSONChunkReader) Read(p []byte) (int, error) {
	return r.Reader.Read(p[:min(len(p), r.size)])
}

func redHatTestJSON(raw string, chunk int) *redHatJSON {
	return &redHatJSON{reader: &redHatJSONReader{reader: redHatJSONChunkReader{Reader: strings.NewReader(raw), size: chunk}}}
}

func TestRedHatJSONScannerGrammar(t *testing.T) {
	for _, test := range []struct {
		name, raw string
		valid     bool
	}{
		{"empty-object", `{}`, true},
		{"empty-array", `[]`, true},
		{"literals", `[null,true,false,0,-0,1.2e-3,1E+9999]`, true},
		{"unicode", "{\"text\":\"café 日本語 \U0001f600 \\uD83D\\uDE00 \\ud800\"}", true},
		{"escaped", `"\"\\\/\b\f\n\r\t\u0000"`, true},
		{"ignored-duplicate", `{"a":0,"a":1}`, true},
		{"whitespace", " \r\n\t[1, 2]\n", true},
		{"empty", ``, false},
		{"array-comma", `[1,]`, false},
		{"object-comma", `{"a":1,}`, false},
		{"missing-comma", `[1 2]`, false},
		{"adjacent-strings", `["a""b"]`, false},
		{"adjacent-containers", `[{}{}]`, false},
		{"missing-colon", `{"a" 1}`, false},
		{"missing-value", `{"a":}`, false},
		{"unquoted-key", `{a:1}`, false},
		{"invalid-escape", `"\q"`, false},
		{"invalid-unicode-escape", `"\u12x4"`, false},
		{"truncated-escape", `"\`, false},
		{"control", "\"a\x00b\"", false},
		{"invalid-utf8", "\"\xff\"", false},
		{"truncated-utf8", "\"\xe2\x82", false},
		{"leading-zero", `01`, false},
		{"missing-fraction", `1.`, false},
		{"missing-exponent", `1e+`, false},
		{"nonfinite", `NaN`, false},
		{"literal-prefix", `truefalse`, false},
		{"second-document", `{} {}`, false},
		{"comment", `[]//comment`, false},
		{"mismatched-close", `[}`, false},
		{"truncated-container", `{"a":[]`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, chunk := range []int{1, 7, 32768} {
				j := redHatTestJSON(test.raw, chunk)
				err := j.skip()
				if err == nil {
					if _, end := j.peek(); end != io.EOF {
						err = errors.New("trailing JSON")
					}
				}
				if (err == nil) != test.valid {
					t.Fatalf("chunk=%d valid=%v err=%v", chunk, test.valid, err)
				}
			}
		})
	}
}

func TestRedHatJSONScannerProjection(t *testing.T) {
	for _, test := range []struct {
		name, raw, text string
		valid           bool
	}{
		{"null-container", `null`, "unchanged", true},
		{"null-text", `{"text":null}`, "unchanged", true},
		{"empty-text", `{"text":""}`, "", true},
		{"escaped-text", `{"text":"café\n\uD83D\uDE00\ud800"}`, "café\n\U0001f600\ufffd", true},
		{"escaped-key", `{"te\u0078t":"value"}`, "value", true},
		{"duplicate-key", `{"text":"a","text":"b"}`, "", false},
		{"escaped-duplicate-key", `{"text":"a","te\u0078t":"b"}`, "", false},
		{"unknown-duplicate-key", `{"ignored":1,"ignored":2}`, "", false},
		{"ignored-nested-duplicate", `{"ignored":{"a":1,"a":2}}`, "unchanged", true},
		{"nonstring-text", `{"text":false}`, "", false},
		{"nonobject", `[]`, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, chunk := range []int{1, 7, 32768} {
				j := redHatTestJSON(test.raw, chunk)
				text := "unchanged"
				err := j.container('{', func(key string) error {
					if key == "text" {
						return j.text(&text)
					}
					return j.skip()
				})
				if (err == nil) != test.valid || (test.valid && text != test.text) {
					t.Fatalf("chunk=%d text=%q err=%v", chunk, text, err)
				}
			}
		})
	}
}

func TestRedHatJSONScannerBounds(t *testing.T) {
	for _, test := range []struct {
		name, raw string
		valid     bool
	}{
		{"scalar-exact", `"` + strings.Repeat("x", redHatScalarBytes) + `"`, true},
		{"scalar-over", `"` + strings.Repeat("x", redHatScalarBytes+1) + `"`, false},
		{"escaped-scalar-exact", `"` + strings.Repeat(`\n`, redHatScalarBytes/2) + `"`, true},
		{"escaped-scalar-over", `"` + strings.Repeat(`\n`, redHatScalarBytes/2) + `x"`, false},
		{"number-exact", strings.Repeat("1", redHatScalarBytes), true},
		{"number-over", strings.Repeat("1", redHatScalarBytes+1), false},
		{"depth-exact", strings.Repeat("[", redHatJSONDepth) + "0" + strings.Repeat("]", redHatJSONDepth), true},
		{"depth-over", strings.Repeat("[", redHatJSONDepth+1) + "0" + strings.Repeat("]", redHatJSONDepth+1), false},
		{"entries-exact", "[" + strings.Repeat("0,", maxEntries-1) + "0]", true},
		{"entries-over", "[" + strings.Repeat("0,", maxEntries) + "0]", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			j := redHatTestJSON(test.raw, 32768)
			if err := j.skip(); (err == nil) != test.valid {
				t.Fatalf("valid=%v err=%v", test.valid, err)
			}
		})
	}
	for _, count := range []int{128, 129} {
		var raw strings.Builder
		raw.WriteByte('{')
		for i := range count {
			if i != 0 {
				raw.WriteByte(',')
			}
			fmt.Fprintf(&raw, `"key%d":null`, i)
		}
		raw.WriteByte('}')
		j := redHatTestJSON(raw.String(), 32768)
		if err := j.container('{', func(string) error { return j.skip() }); (err == nil) != (count == 128) {
			t.Fatalf("keys=%d err=%v", count, err)
		}
	}
}

func TestRedHatJSONScannerRetainsAcrossRefills(t *testing.T) {
	// Force opening/closing quotes, escapes and multibyte UTF-8 across reads.
	for _, padding := range []int{32755, 32756, 32757, 32758, 32759, 32760} {
		text := strings.Repeat("x", padding) + "\U0001f600\nend"
		encoded, err := json.Marshal(text)
		if err != nil {
			t.Fatal(err)
		}
		raw := `{"text":` + string(encoded) + `,"ignored":"` + strings.Repeat("y", 40000) + `"}`
		j := redHatTestJSON(raw, 32768)
		var got string
		if err := j.container('{', func(key string) error {
			if key == "text" {
				return j.text(&got)
			}
			return j.skip()
		}); err != nil || got != text {
			t.Fatalf("padding=%d retained text changed: length=%d err=%v", padding, len(got), err)
		}
	}
}

// Keep the former token walk only as an independent fuzz oracle for strict
// ignored-field JSON grammar and its depth/container/scalar/UTF-8 bounds.
func redHatJSONTokenReference(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	open, container := token.(json.Delim)
	if !container {
		return nil
	}
	if (open != '{' && open != '[') || depth >= redHatJSONDepth {
		return errors.New("invalid container or depth")
	}
	for count := 0; decoder.More(); count++ {
		if count >= maxEntries {
			return errors.New("entry limit")
		}
		if open == '{' {
			if _, err := decoder.Token(); err != nil {
				return err
			}
		}
		if err := redHatJSONTokenReference(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func FuzzRedHatJSONScanner(f *testing.F) {
	for _, raw := range []string{`null`, `{"a":[null,true,1e9999,"\ud800"]}`, `{"a":1,"a":2}`, `[1,]`, `"\u1234"`, "\"café\U0001f600\"", strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65)} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 128<<10 {
			return
		}
		decoder := json.NewDecoder(&redHatJSONReader{reader: bytes.NewReader(raw)})
		decoder.UseNumber()
		want := redHatJSONTokenReference(decoder, 0) == nil
		if want {
			_, err := decoder.Token()
			want = err == io.EOF
		}
		j := redHatTestJSON(string(raw), 7)
		got := j.skip() == nil
		if got {
			_, err := j.peek()
			got = err == io.EOF
		}
		if got != want {
			t.Fatalf("scanner accepted=%v token parser accepted=%v input=%q", got, want, raw)
		}
	})
}
