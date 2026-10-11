//go:build linux

package passwordprovider

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"testing"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestNativeModuleVersionSemanticsAreClosed(t *testing.T) {
	for _, tc := range []struct {
		os, release, version string
		feature              agentv1.PasswordNativeFeature
		want                 bool
	}{
		{"ubuntu", "24.04", "1.4.5-3build1", 1, true},
		{"fedora", "44", "1.4.5-15.fc44", 1, true},
		{"ubuntu", "24.04", "1.5.3-5ubuntu5.4", 2, true},
		{"fedora", "44", "1.7.2-3.fc44", 3, true},
		{"fedora", "44", "1:1.7.2-3.fc44", 2, true},
		{"fedora", "44", "1.4.6-1.fc44", 1, false},
		{"ubuntu", "24.04", "1.7.2-1", 3, false},
		{"fedora", "45", "1.7.2-1.fc45", 2, false},
		{"debian", "13", "1.4.5-1", 1, false},
		{"fedora", "44", "1.7.2-3.fc44", 0, false},
		// EL 9.8 ships libpwquality 1.4.4 and pam 1.5.1; neither Fedora's nor a
		// neighbouring EL minor's releases may stand in for them.
		{"almalinux", "9.8", "1.4.4-8.el9", 1, true},
		{"rhel", "9.8", "1.5.1-28.el9_8.1", 3, true},
		{"rhel", "9.8", "1.4.5-15.fc44", 1, false},
		{"almalinux", "9.8", "1.7.2-3.fc44", 2, false},
		{"almalinux", "9.7", "1.5.1-26.el9", 2, false},
		{"rocky", "9.8", "1.4.4-8.el9", 1, false},
	} {
		if got := moduleVersionSupported(&resourcev1.PlatformProduct{OsId: tc.os, Version: tc.release}, tc.feature, tc.version); got != tc.want {
			t.Errorf("%s %s feature %d version %s = %t", tc.os, tc.release, tc.feature, tc.version, got)
		}
	}
}

func TestPackageObservationUsesFixedReadOnlyQueries(t *testing.T) {
	rpmArch := runtime.GOARCH
	switch rpmArch {
	case "amd64":
		rpmArch = "x86_64"
	case "arm64":
		rpmArch = "aarch64"
	}
	for _, tc := range []struct {
		os, release, name, path, output, want string
		args                                  []string
	}{
		{"ubuntu", "24.04", "libpam-modules", "/usr/bin/dpkg-query", "ii \t1.5.3-5ubuntu5.4\n", "1.5.3-5ubuntu5.4", []string{"-W", "-f=${db:Status-Abbrev}\t${Version}\n", "libpam-modules:" + runtime.GOARCH}},
		{"fedora", "44", "pam", "/usr/bin/rpm", "1.7.2-3.fc44\n", "1.7.2-3.fc44", []string{"-q", "--qf", "%{VERSION}-%{RELEASE}\n", "pam." + rpmArch}},
		{"rhel", "9.8", "libpwquality", "/usr/bin/rpm", "1.4.4-8.el9\n", "1.4.4-8.el9", []string{"-q", "--qf", "%{VERSION}-%{RELEASE}\n", "libpwquality." + rpmArch}},
	} {
		calls := 0
		run := func(_ context.Context, path string, args ...string) ([]byte, error) {
			calls++
			if path != tc.path || !slices.Equal(args, tc.args) {
				t.Fatalf("unexpected native query %s %v", path, args)
			}
			return []byte(tc.output), nil
		}
		got, err := packageVersion(context.Background(), &resourcev1.PlatformProduct{OsId: tc.os, Version: tc.release}, tc.name, run)
		if err != nil || got != tc.want || calls != 1 {
			t.Fatalf("package version=%q calls=%d err=%v", got, calls, err)
		}
	}
}

func TestPackageObservationRejectsMissingAndAmbiguousVersions(t *testing.T) {
	platform := &resourcev1.PlatformProduct{OsId: "ubuntu", Version: "24.04"}
	for _, output := range []string{"rc \t1.5.3-5ubuntu5", "ii \t", "ii \t1.5.3\n1.7.2", "ii \t1.5.3;command"} {
		run := func(context.Context, string, ...string) ([]byte, error) { return []byte(output), nil }
		if _, err := packageVersion(context.Background(), platform, "libpam-modules", run); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("ambiguous package state %q accepted: %v", output, err)
		}
	}
	calls := 0
	run := func(context.Context, string, ...string) ([]byte, error) { calls++; return nil, nil }
	if _, err := packageVersion(context.Background(), platform, "client-selected-package", run); !errors.Is(err, ErrUnsupported) || calls != 0 {
		t.Fatal("arbitrary package query executed")
	}
}

func TestNativeManagerVersionsMatchSupportedTransactionSemantics(t *testing.T) {
	for _, tc := range []struct {
		os, release, output string
		want                bool
	}{
		{"fedora", "44", "1.7.1-1.fc44", true}, {"fedora", "44", "1.8.0-1.fc44", false},
		{"ubuntu", "24.04", "ii \t1.5.3-5ubuntu5.4", true}, {"ubuntu", "24.04", "ii \t1.6.1-1", false},
		// EL 9 authselect 1.2 has its own profile set and CLI; 1.7 semantics differ.
		{"almalinux", "9.8", "1.2.6-3.el9", true}, {"rhel", "9.8", "1.7.1-1.fc44", false}, {"rhel", "10.1", "1.5.0-8.el10", false},
	} {
		run := func(context.Context, string, ...string) ([]byte, error) { return []byte(tc.output), nil }
		_, err := managerVersion(context.Background(), &resourcev1.PlatformProduct{OsId: tc.os, Version: tc.release}, run)
		if tc.want && err != nil || !tc.want && !errors.Is(err, ErrUnsupported) {
			t.Fatalf("manager %s version %q accepted=%t err=%v", tc.os, tc.output, tc.want, err)
		}
	}
}
