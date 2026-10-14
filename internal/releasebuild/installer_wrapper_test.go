// SPDX-License-Identifier: Apache-2.0

//go:build linux

package releasebuild

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestInstallerWrapperPublicArguments(t *testing.T) {
	script, err := os.ReadFile("../../deploy/server/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	// Execute the actual parser without root custody or terminal side effects.
	start := strings.Index(string(script), "key=''\n")
	end := strings.Index(string(script), "prompt() {")
	if start < 0 || end <= start {
		t.Fatal("public argument parser boundaries missing")
	}
	parser := string(script[start:end]) + "printf '%s\\n' \"$key\" \"$pin\" \"$origin\" \"$recipient\"\n"
	flags := []string{"release-key-file", "release-key-id", "origin", "backup-recipient-file"}
	for _, prefix := range []string{"--", "-"} {
		for _, equals := range []bool{false, true} {
			name := prefix + "separated"
			if equals {
				name = prefix + "equals"
			}
			t.Run(name, func(t *testing.T) {
				args := []string{"-eu", "-c", parser, "installer"}
				for _, flag := range flags {
					if equals {
						args = append(args, prefix+flag+"=value with spaces=tail")
					} else {
						args = append(args, prefix+flag, "value with spaces=tail")
					}
				}
				output, err := exec.CommandContext(t.Context(), "sh", args...).CombinedOutput()
				if err != nil || string(output) != strings.Repeat("value with spaces=tail\n", 4) {
					t.Fatalf("required inputs not recognized: %v: %q", err, output)
				}
			})
		}
	}
	for _, final := range []string{"last", ""} {
		t.Run("final="+final, func(t *testing.T) {
			args := []string{"-eu", "-c", parser, "installer"}
			for _, flag := range flags {
				args = append(args, "--"+flag, "first", "-"+flag+"=middle", "--"+flag+"="+final)
			}
			output, err := exec.CommandContext(t.Context(), "sh", args...).CombinedOutput()
			if err != nil || string(output) != strings.Repeat(final+"\n", 4) {
				t.Fatalf("final occurrence not authoritative: %v: %q", err, output)
			}
		})
	}
	t.Run("final separated consumes flag-like value", func(t *testing.T) {
		args := []string{"-eu", "-c", parser, "installer"}
		for _, flag := range flags {
			args = append(args, "--"+flag+"=first", "-"+flag, "--literal=value")
		}
		output, err := exec.CommandContext(t.Context(), "sh", args...).CombinedOutput()
		if err != nil || string(output) != strings.Repeat("--literal=value\n", 4) {
			t.Fatalf("separated final value not authoritative: %v: %q", err, output)
		}
	})
}
