//go:build linux

package sysctlprovider

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestEffectiveSysctlOrderingAndConflicts(t *testing.T) {
	key := "net.ipv4.ip_forward"
	owned := StanzaPath(key)
	cases := []struct {
		name          string
		files         []configFile
		value, source string
		conflict      bool
	}{
		{"owned beats vendor", []configFile{{path: "/usr/lib/sysctl.d/10-vendor.conf", data: []byte(key + "=0\n")}, {path: owned, data: stanza(key, "1")}}, "1", owned, false},
		{"later admin wins", []configFile{{path: owned, data: stanza(key, "1")}, {path: "/etc/sysctl.d/99-sysctl.conf", data: []byte(key + "=0\n")}}, "0", "/etc/sysctl.d/99-sysctl.conf", true},
		{"same value is not same ownership", []configFile{{path: owned, data: stanza(key, "1")}, {path: "/etc/sysctl.d/99-admin.conf", data: []byte(key + "=1\n")}}, "1", "/etc/sysctl.d/99-admin.conf", true},
		{"explicit excludes later glob", []configFile{{path: owned, data: stanza(key, "1")}, {path: "/etc/sysctl.d/99-glob.conf", data: []byte("net.ipv4.*=0\n")}}, "1", owned, false},
		{"glob works without explicit", []configFile{{path: "/etc/sysctl.d/90-glob.conf", data: []byte("net.ipv4.*=0\n")}}, "0", "/etc/sysctl.d/90-glob.conf", true},
		{"explicit exclusion", []configFile{{path: "/etc/sysctl.d/90-glob.conf", data: []byte("net.ipv4.*=0\n-" + key + "\n")}}, "", "", false},
		{"dev null mask", []configFile{{path: "/etc/sysctl.d/90-vendor.conf", masked: true}}, "", "", false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, err := effectivePersistence(test.files, key)
			if err != nil {
				t.Fatal(err)
			}
			value, source := "", ""
			if got.value != nil {
				value = *got.value
			}
			if got.source != nil {
				source = *got.source
			}
			if value != test.value || source != test.source || got.conflict != test.conflict {
				t.Fatalf("effective = %q %q %v", value, source, got.conflict)
			}
			if len(got.graph) != 32 {
				t.Fatal("unbound graph")
			}
		})
	}
}
func TestParserCanonicalSeparatorsAndNumericVectors(t *testing.T) {
	for _, key := range []string{"net.ipv4.conf.enp3s0/200.forwarding", "net/ipv4/conf/enp3s0.200/forwarding"} {
		if got := sysctlPath(key); got != "net/ipv4/conf/enp3s0.200/forwarding" {
			t.Fatalf("native key changed: %s", got)
		}
	}
	got, err := effectivePersistence([]configFile{{path: "/etc/sysctl.d/99.conf", data: []byte("; comment\n # comment\n-net/ipv4/ip_local_port_range = 32768\t60999\n")}}, "net.ipv4.ip_local_port_range")
	if err != nil {
		t.Fatal(err)
	}
	if got.value == nil || *got.value != "32768 60999" {
		t.Fatal("kernel vector representation not normalized")
	}
	if normalizeValue("host  name") == normalizeValue("host name") {
		t.Fatal("string whitespace silently changed")
	}
}
func TestParserRejectsUnknownSyntaxAndBindsGraph(t *testing.T) {
	for _, line := range []string{"include /tmp/options", "key=1\\", "net.ipv4.[broken=1", "../kernel/key=1", "net.ipv4.key=1\x00"} {
		if _, err := effectivePersistence([]configFile{{path: "/etc/sysctl.d/99.conf", data: []byte(line)}}, "net.ipv4.ip_forward"); err == nil {
			t.Fatalf("unsafe syntax accepted: %q", line)
		}
	}
	first, _ := effectivePersistence([]configFile{{path: "/etc/sysctl.d/99.conf", data: []byte("net.ipv4.ip_forward=0")}}, "net.ipv4.ip_forward")
	second, _ := effectivePersistence([]configFile{{path: "/etc/sysctl.d/99.conf", data: []byte("net.ipv4.ip_forward=1")}}, "net.ipv4.ip_forward")
	if bytes.Equal(first.graph, second.graph) {
		t.Fatal("configuration change absent from graph")
	}
	if !strings.HasPrefix(StanzaPath("vm.swappiness"), "/etc/sysctl.d/60-lindm-") || StanzaPath("vm.swappiness") == StanzaPath("vm.dirty_ratio") {
		t.Fatal("stanza identity collision")
	}
}
func TestLiveProcReadPreservesKernelRepresentation(t *testing.T) {
	proc, err := openProc("kernel.osrelease", false)
	if err != nil {
		if errors.Is(err, ErrUnsupported) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	defer func() {
		if err := proc.close(); err != nil {
			t.Error(err)
		}
	}()
	value, err := proc.read()
	if err != nil {
		t.Fatal(err)
	}
	if value == "" || strings.Contains(value, "\n") || len(proc.identity) != 32 {
		t.Fatal("incomplete live kernel observation")
	}
	if err := proc.unchanged(value); err != nil {
		t.Fatal(err)
	}
}
func TestRootAllowlistDoesNotDelegateAuthorityKnobs(t *testing.T) {
	for _, key := range []string{"kernel.panic", "kernel.panic_on_oops", "kernel.sysrq", "kernel.kexec_load_disabled", "kernel.modprobe", "kernel.core_pattern", "kernel.yama.ptrace_scope", "vm.panic_on_oom", "user.max_user_namespaces"} {
		if !authorityKey(key) {
			t.Fatalf("authority key not denied: %s", key)
		}
	}
	for _, key := range []string{"vm.swappiness", "net.ipv4.ip_forward"} {
		if authorityKey(key) {
			t.Fatalf("approved tuning key unrepresentable: %s", key)
		}
	}
}

func TestStanzaAdoptionCannotAcquireOtherKernelAuthority(t *testing.T) {
	for _, data := range []string{"# original formatting\nvm.swappiness = 60\n", "vm/swappiness=60\n", ""} {
		if err := validateOwnedStanza("vm.swappiness", []byte(data)); err != nil {
			t.Fatalf("safe exact baseline rejected: %v", err)
		}
	}
	for _, data := range []string{"vm.swappiness=60\nkernel.panic=1\n", "vm.*=60\n", "-vm.swappiness=60\n", "vm.swappiness=60 # ignored failure\n", "include /etc/sysctl.conf"} {
		if err := validateOwnedStanza("vm.swappiness", []byte(data)); err == nil {
			t.Fatalf("unrelated or untyped authority acquired: %q", data)
		}
	}
	for _, key := range []string{"vm.drop_caches", "vm.compact_memory", "net.ipv4.route.flush", "kernel.ctrl-alt-del", "kernel.poweroff_cmd"} {
		if !authorityKey(key) {
			t.Fatalf("imperative operation disguised as sysctl resource: %s", key)
		}
	}
}
