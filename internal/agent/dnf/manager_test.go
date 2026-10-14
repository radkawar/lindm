// SPDX-License-Identifier: Apache-2.0

package dnf

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestParseVersion(t *testing.T) {
	for _, test := range []struct {
		text    string
		kind    Kind
		version string
	}{
		{"dnf5 version 5.4.6.0\ndnf5 plugin API version 2.0\nlibdnf5 version 5.4.6.0\n", DNF5, "5.4.6.0"},
		{"4.14.0\n  Installed: dnf-0:4.14.0-1.el9.noarch\n", DNF4, "4.14.0"},
	} {
		got, err := ParseVersion([]byte(test.text))
		if err != nil || got.Kind != test.kind || got.Version != test.version {
			t.Fatalf("identity = %+v, %v", got, err)
		}
	}
	for _, text := range []string{"", "dnf5 version 4.4.0.0\n", "dnf5 version 5.4.6\n", "5.4.6.0\n", "dnf5 version 5.4.x.0\n", "warning\ndnf5 version 5.4.6.0\n", "4.14.0 injected\n"} {
		if got, err := ParseVersion([]byte(text)); err == nil {
			t.Fatalf("accepted unsupported identity %q: %+v", text, got)
		}
	}
}

func TestAtLeastComparesNumericComponents(t *testing.T) {
	for _, test := range []struct {
		manager Manager
		want    bool
	}{
		{Manager{DNF5, "5.4.6.0"}, true},
		{Manager{DNF5, "5.4.10.0"}, true},
		{Manager{DNF5, "5.10.0.0"}, true},
		{Manager{DNF5, "5.4.1.0"}, false},
		{Manager{DNF4, "5.4.6"}, false},
	} {
		if got := test.manager.AtLeast(DNF5, "5.4.6.0"); got != test.want {
			t.Fatalf("%+v AtLeast 5.4.6.0 = %v", test.manager, got)
		}
	}
}

func TestExecutableSelectsNativeManagerNotDistribution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "native-manager")
	if err := os.WriteFile(path, nil, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, dnf5Present := range []bool{true, false} {
		got, err := Executable(func(path string) (fs.FileInfo, error) {
			if path == "/usr/bin/dnf5" && !dnf5Present {
				return nil, fs.ErrNotExist
			}
			return info, nil
		})
		want := "/usr/bin/dnf"
		if dnf5Present {
			want = "/usr/bin/dnf5"
		}
		if err != nil || got != want {
			t.Fatalf("selection = %q, %v", got, err)
		}
	}
	_, err = Executable(func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission })
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("permission failure hidden: %v", err)
	}
	_, err = Executable(func(string) (fs.FileInfo, error) { return nil, fs.ErrNotExist })
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("absence hidden: %v", err)
	}
}

// Native EL entrypoints name their own interpreter; adapters must run under
// exactly that one, never an arbitrary command line. The isolated adapter
// already implies -s, the only option EL10's entrypoint passes.
func TestInterpreterIsTheNativeEntrypointShebang(t *testing.T) {
	for entrypoint, want := range map[string]string{
		"#!/usr/bin/python3.9\nimport dnf.cli.main\n":    "/usr/bin/python3.9",
		"#!/usr/libexec/platform-python\nimport sys\n":   "/usr/libexec/platform-python",
		"#!/usr/bin/python3\n# -*- coding: utf-8 -*-\n":  "/usr/bin/python3",
		"#! /usr/bin/python3 -s\n# The dnf executable\n": "/usr/bin/python3",
	} {
		if got, err := Interpreter([]byte(entrypoint)); err != nil || got != want {
			t.Fatalf("%q = %q, %v", entrypoint, got, err)
		}
	}
	for _, entrypoint := range []string{"", "#!/usr/bin/python3.9", "#!/usr/bin/env python3\n", "#!/usr/bin/python3 -E\n", "#!/usr/bin/python3 -s -u\n", "#!/tmp/python3.9\n", "#!/usr/bin/python3.x\n", "#!\n", "import dnf\n"} {
		if got, err := Interpreter([]byte(entrypoint)); err == nil {
			t.Fatalf("%q accepted as %q", entrypoint, got)
		}
	}
}
