//go:build linux

package packageprovider

import (
	"errors"
	"strings"
	"testing"

	"lindm/internal/agent/nativeexec"
)

// Exercise the actual provider -> nativeexec -> execve boundary, not a mocked
// p.run that would accept an environment forbidden by the shared runner.
func TestZypperEnvironmentRealNativeDispatch(t *testing.T) {
	const directory = "/var/lib/lindm/package-stage"
	t.Setenv("ZYPP_LOCKFILE_ROOT", "/untrusted-inherited-lock-root")
	for _, preparation := range []bool{true, false} {
		runner := runNative
		if !preparation {
			runner = commitNative
		}
		env := zypperEnv(directory, preparation)
		result, err := runner(t.Context(), "/usr/bin/env", nil, "/", env)
		if err != nil {
			t.Fatal(err)
		}
		got := string(result.stdout)
		for _, entry := range env {
			if !strings.Contains("\n"+got, "\n"+entry+"\n") {
				t.Fatalf("native environment omitted %q: %q", entry, got)
			}
		}
		if strings.Contains(got, "ZYPP_LOCKFILE_ROOT=") != preparation || strings.Contains(got, "untrusted-inherited-lock-root") {
			t.Fatalf("private/live lock boundary changed: preparation=%t environment=%q", preparation, got)
		}
		_, err = runner(t.Context(), "/usr/bin/env", nil, "/", append(env, "ZYPP_FULLLOG=1"))
		if !errors.Is(err, nativeexec.ErrInvalidCommand) {
			t.Fatalf("unapproved zypp override reached native command: %v", err)
		}
	}
}
