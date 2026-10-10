package labhost

import (
	"io"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
)

func TestBaselineExactPins(t *testing.T) {
	pins, err := parseBaselinePins("# reviewed package versions\nqemu-utils=1:8.2.2+ds-0ubuntu1.18\n\ngpg=2.4.4-2ubuntu17.6\n")
	if err != nil || !reflect.DeepEqual(pins, []string{"qemu-utils=1:8.2.2+ds-0ubuntu1.18", "gpg=2.4.4-2ubuntu17.6"}) {
		t.Fatalf("parse exact pins = %v, %v", pins, err)
	}
	for _, invalid := range []string{
		"", "# only a comment", "qemu-utils", "qemu-utils=", "qemu-utils=latest*",
		"qemu-utils=1\nqemu-utils=2", "--allow-unauthenticated=1", "qemu-utils=1;id",
		"qemu-utils=$(id)", "qemu-utils=1 2", "qemu-utils=1=2", "QEMU=1", "qemu/utils=1",
	} {
		if _, err := parseBaselinePins(invalid); err == nil {
			t.Errorf("accepted unsafe or nonexact package pin %q", invalid)
		}
	}
}

func TestBaselineExactInstalledState(t *testing.T) {
	pins := []string{"qemu-utils=1:8.2.2+ds-0ubuntu1.18"}
	for _, tc := range []struct {
		name  string
		state BaselinePackage
		ready bool
	}{
		{"exact", BaselinePackage{Status: "installed", Version: "1:8.2.2+ds-0ubuntu1.18"}, true},
		{"unconfigured", BaselinePackage{Status: "unpacked", Version: "1:8.2.2+ds-0ubuntu1.18"}, false},
		{"older", BaselinePackage{Status: "installed", Version: "1:8.2.2+ds-0ubuntu1.16"}, false},
		{"newer", BaselinePackage{Status: "installed", Version: "1:8.2.2+ds-0ubuntu1.19"}, false},
		{"absent", BaselinePackage{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := baselinePackagesReady(map[string]BaselinePackage{"qemu-utils": tc.state}, pins); got != tc.ready {
				t.Fatalf("ready = %t, want %t", got, tc.ready)
			}
		})
	}
}

func TestBaselineRecordsDependencyChanges(t *testing.T) {
	before := map[string]BaselinePackage{
		"kept":       {Status: "installed", Version: "1"},
		"dependency": {Status: "installed", Version: "1"},
		"removed":    {Status: "config-files", Version: "1"},
	}
	after := map[string]BaselinePackage{
		"kept":       {Status: "installed", Version: "1"},
		"dependency": {Status: "installed", Version: "2"},
		"added":      {Status: "installed", Version: "3"},
	}
	changes := baselineChanges(before, after)
	if len(changes) != 3 || changes[0].Package != "added" || changes[1].Package != "dependency" || changes[2].Package != "removed" {
		t.Fatalf("dependency-inclusive stable change list = %+v", changes)
	}
	if changes[0].Before != (BaselinePackage{}) || changes[1].Before.Version != "1" || changes[1].After.Version != "2" || changes[2].After != (BaselinePackage{}) {
		t.Fatalf("lost before/after evidence: %+v", changes)
	}
	if got := baselineChanges(after, after); len(got) != 0 {
		t.Fatalf("idempotent observation reports changes: %+v", got)
	}
}

func TestBaselineCapacityBoundsAndNativeIdentity(t *testing.T) {
	requested := &labv1.LabHost{Name: "worker", Transport: "ssh", SshAlias: "worker.internal", Runtime: "container", RunnerImage: "old", WorkDirectory: "~/work/lab"}
	original := proto.Clone(requested)
	for _, tc := range []struct {
		cpus, memory               uint32
		vcpus, guestMemory, guests uint32
	}{
		{20, 124610, 4, 8192, 4},
		{2, 4096, 1, 3072, 1},
		{1, 1024, 1, 768, 1},
		{64, 16384, 4, 8192, 1},
	} {
		host, err := baselineHost(requested, &BaselineSnapshot{CPUs: tc.cpus, MemoryMib: tc.memory, Architecture: "arm64", Home: "/home/operator"})
		if err != nil {
			t.Fatal(err)
		}
		if host.MaxVcpus != tc.vcpus || host.MaxMemoryMib != tc.guestMemory || host.MaxGuests != tc.guests {
			t.Fatalf("CPU=%d memory=%d: capacity = %d/%d/%d", tc.cpus, tc.memory, host.MaxVcpus, host.MaxMemoryMib, host.MaxGuests)
		}
		if !host.Kvm || host.Runtime != "native" || host.RunnerImage != "" || !reflect.DeepEqual(host.Architectures, []string{"arm64"}) || host.WorkDirectory != "/home/operator/work/lab" {
			t.Fatalf("incorrect native host identity: %v", host)
		}
		if err := Validate(&labv1.LabConfig{Hosts: []*labv1.LabHost{host}}); err != nil {
			t.Fatalf("ready host violates shared schema: %v", err)
		}
	}
	if !proto.Equal(requested, original) {
		t.Fatal("baseline rewrote caller's host configuration")
	}
}

func TestBaselineKeepsConfiguredLimits(t *testing.T) {
	requested := &labv1.LabHost{MaxGuests: 2, MaxVcpus: 2, MaxMemoryMib: 4096, WorkDirectory: "/srv/lab"}
	host, err := baselineHost(requested, &BaselineSnapshot{CPUs: 20, MemoryMib: 124610, Architecture: "amd64"})
	if err != nil || host.MaxGuests != 2 || host.MaxVcpus != 2 || host.MaxMemoryMib != 4096 {
		t.Fatalf("configured ceilings were raised: %v, %v", host, err)
	}
	requested.MaxGuests, requested.MaxVcpus, requested.MaxMemoryMib = 100, 100, 100000
	host, err = baselineHost(requested, &BaselineSnapshot{CPUs: 4, MemoryMib: 4096, Architecture: "amd64"})
	if err != nil || host.MaxGuests != 1 || host.MaxVcpus != 3 || host.MaxMemoryMib != 3072 {
		t.Fatalf("oversized ceilings were not bounded: %v, %v", host, err)
	}
	for _, observed := range []*BaselineSnapshot{{CPUs: 0, MemoryMib: 8192}, {CPUs: 4, MemoryMib: 512}} {
		if _, err := baselineHost(requested, observed); err == nil {
			t.Fatal("accepted unusable physical capacity")
		}
	}
}

func TestBaselineSSHArgumentBoundary(t *testing.T) {
	for _, alias := range []string{"worker", "worker.internal", "worker-2", "worker_2", "192.0.2.1"} {
		if !baselineAlias(alias) {
			t.Errorf("rejected plain SSH alias %q", alias)
		}
	}
	for _, alias := range []string{"", "-oProxyCommand=touch", "r@worker", "worker;id", "worker\ntrue", "$(id)", "worker name", "worker'", "worker/../other"} {
		if baselineAlias(alias) {
			t.Errorf("accepted non-alias SSH operand %q", alias)
		}
	}
}

func TestBaselineBashLiteralBoundary(t *testing.T) {
	// Exercise the actual shell tokenizer, not an assertion about generated
	// source. Substitutions must survive as data and never execute.
	for _, value := range []string{"", "ordinary", "with spaces", "quote'and\"double", "$(exit 9); `exit 8`", "line\nbreak"} {
		cmd := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", "printf '%s' "+baselineQuote(value))
		data, err := cmd.Output()
		if err != nil || string(data) != value {
			t.Fatalf("literal round trip %q = %q, %v", value, data, err)
		}
	}
}

func TestBaselineOutputEvidenceBound(t *testing.T) {
	out := &baselineOutput{limit: 5}
	for _, part := range []string{"123", "456", "789"} {
		n, err := out.Write([]byte(part))
		if n != len(part) || err != nil {
			t.Fatalf("bounded drain = %d, %v", n, err)
		}
	}
	if !out.exceeded || out.String() != "12345" {
		t.Fatalf("unbounded or silently truncated evidence: %q exceeded=%t", out.String(), out.exceeded)
	}
	if _, err := parseBaselinePins(strings.Repeat("x", 70<<10)); err == nil {
		t.Fatal("accepted oversized pin line")
	}
}

func TestBaselineOutputCannotBypassBoundThroughCopy(t *testing.T) {
	out := &baselineOutput{limit: 5}
	source := struct{ io.Reader }{strings.NewReader("123456789")}
	if n, err := io.Copy(out, source); err != nil || n != 9 {
		t.Fatalf("drain command output = %d, %v", n, err)
	}
	if !out.exceeded || out.String() != "12345" {
		t.Fatalf("io.Copy bypassed evidence bound: %q exceeded=%t", out.String(), out.exceeded)
	}
}
