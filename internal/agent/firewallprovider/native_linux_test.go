//go:build linux

package firewallprovider

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// This test exercises the actual kernel netlink API only in a reexecuted private
// network namespace. It cannot modify the host owner's firewall and does not
// claim installed-helper/reboot/connectivity qualification. EPERM is a skip.
func TestNativeNetlinkAtomicOwnershipLifecycle(t *testing.T) {
	if os.Getenv("LINDM_FIREWALL_NATIVE_CHILD") != "1" {
		if os.Geteuid() != 0 {
			t.Skip("requires root and disposable network namespace")
		}
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, "-test.run=^TestNativeNetlinkAtomicOwnershipLifecycle$", "-test.v")
		command.Env = append(os.Environ(), "LINDM_FIREWALL_NATIVE_CHILD=1")
		command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
		out, err := command.CombinedOutput()
		if errors.Is(err, unix.EPERM) {
			t.Skip("network namespace creation denied")
		}
		if err != nil {
			t.Fatalf("isolated native test: %v\n%s", err, out)
		}
		if bytes.Contains(out, []byte("--- SKIP:")) {
			t.Skip(string(out))
		}
		return
	}
	if _, err := namespaceIdentity(); !errors.Is(err, ErrUnsupported) {
		t.Fatal("production helper accepted a private network namespace")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	connection, err := openNetlink(ctx)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skip("CAP_NET_ADMIN unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := connection.close(); err != nil {
			t.Error(err)
		}
	}()
	reopen := func() {
		t.Helper()
		if err := connection.close(); err != nil {
			t.Fatal(err)
		}
		connection, err = openNetlink(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}
	state, config := compilerFixture(t)
	state.Desired.Rules = []*resourcev1.FirewallRule{typedTCPRule()}
	compiled, err := compile(state, config)
	if err != nil {
		t.Fatal(err)
	}
	before, _, err := connection.observe(compiled.name)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skip("nftables CAP_NET_ADMIN unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.replace(before, compiled); err != nil {
		t.Fatal(err)
	}
	after, _, err := connection.observe(compiled.name)
	if err != nil {
		t.Fatal(err)
	}
	if after.GetConflict() || !nativeEqual(after, compiled.snapshot()) {
		t.Fatal("kernel read-back differs from compiled ownership/expression identity")
	}
	for _, r := range after.GetRules() {
		if r.GetHandle() == 0 || len(r.GetRawExpressionsSha256()) != 32 {
			t.Fatal("missing native rule identity")
		}
	}
	template := &resourcev1.ResourceObservation{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE, CanonicalKey: state.GetDesired().GetZoneId()}, Metadata: &resourcev1.ObservationMetadata{BootId: state.GetAppliedBootId()}}
	baseline := &agentv1.ResourceOwnershipSnapshot{Observation: template, Firewall: before}
	target := &agentv1.ResourceOwnershipSnapshot{Observation: template, Firewall: proto.CloneOf(after)}
	target.Firewall.Persistent = state
	if _, err := rollbackDecision(target, baseline, target, nil, config, "pending"); err != nil {
		t.Fatalf("lost Applied receipt rejected exact kernel target: %v", err)
	}
	for _, generationDrift := range []bool{true, false} {
		changed := &compiledTable{name: compiled.name, userdata: bytes.Clone(compiled.userdata), chains: compiled.chains, rules: append([]compiledRule(nil), compiled.rules...)}
		if generationDrift {
			changed.userdata[0] ^= 1
		} else if err := changed.rule("input", []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}); err != nil {
			t.Fatal(err)
		}
		if err := connection.replace(after, changed); err != nil {
			t.Fatal(err)
		}
		current, _, err := connection.observe(compiled.name)
		if err != nil {
			t.Fatal(err)
		}
		drift := &agentv1.ResourceOwnershipSnapshot{Observation: template, Firewall: current}
		if _, err := rollbackDecision(drift, baseline, target, target, config, "pending"); !errors.Is(err, ErrConflict) {
			t.Fatal("real kernel generation/expression drift permitted inverse")
		}
		if err := connection.replace(current, compiled); err != nil {
			t.Fatal(err)
		}
		after, _, err = connection.observe(compiled.name)
		if err != nil {
			t.Fatal(err)
		}
	}
	// Independent pre-existing owner and quarantine chains remain untouched by
	// profile replacement/release. Actual timed-quarantine probes belong to VMs.
	foreign := &compiledTable{name: "firewalld", userdata: []byte("independent-owner")}
	foreign.chain("input", proto.Uint32(unix.NF_INET_LOCAL_IN))
	foreign.chains[0].Priority = proto.Int32(0)
	if err := foreign.rule("input", []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}); err != nil {
		t.Fatal(err)
	}
	foreignBefore, _, err := connection.observe(foreign.name)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.replace(foreignBefore, foreign); err != nil {
		t.Fatal(err)
	}
	foreignApplied, _, err := connection.observe(foreign.name)
	if err != nil {
		t.Fatal(err)
	}
	quarantine := &compiledTable{name: "lindm_q_" + strings.ReplaceAll(state.Generation, "-", ""), userdata: []byte("action-quarantine")}
	quarantine.chain("input", proto.Uint32(unix.NF_INET_LOCAL_IN))
	quarantine.chains[0].Priority = proto.Int32(-10)
	if err := quarantine.rule("input", []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}); err != nil {
		t.Fatal(err)
	}
	quarantineBefore, _, err := connection.observe(quarantine.name)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.replace(quarantineBefore, quarantine); err != nil {
		t.Fatal(err)
	}
	quarantineApplied, _, err := connection.observe(quarantine.name)
	if err != nil {
		t.Fatal(err)
	}
	// A generation captured before another owner changed anything cannot commit.
	if err := connection.replace(after, &compiledTable{name: compiled.name}); err == nil {
		t.Fatal("stale ruleset generation committed")
	}
	reopen() // A failed batch can leave later ACKs queued; production closes it.
	fresh, _, err := connection.observe(compiled.name)
	if err != nil {
		t.Fatal(err)
	}
	if !nativeEqual(fresh, after) {
		t.Fatal("failed generation-CAS mutated owned table")
	}
	// Invalid expressions reject the entire delete/create replacement batch.
	invalid := &compiledTable{name: compiled.name, userdata: compiled.userdata, chains: compiled.chains, rules: append([]compiledRule(nil), compiled.rules...)}
	if err := invalid.rule("input", []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 999}}); err != nil {
		t.Fatal(err)
	}
	if err := connection.replace(fresh, invalid); err == nil {
		t.Fatal("invalid native expression committed")
	}
	reopen()
	fresh, _, err = connection.observe(compiled.name)
	if err != nil {
		t.Fatal(err)
	}
	if !nativeEqual(fresh, after) {
		t.Fatal("native batch failure did not roll back atomically")
	}
	if err := connection.replace(fresh, &compiledTable{name: compiled.name}); err != nil {
		t.Fatal(err)
	}
	removed, _, err := connection.observe(compiled.name)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed.GetUserdata()) != 0 {
		t.Fatal("owned table release did not restore absence")
	}
	for _, expected := range []*agentv1.FirewallNativeSnapshot{foreignApplied, quarantineApplied} {
		current, _, err := connection.observe(expected.GetTable())
		if err != nil {
			t.Fatal(err)
		}
		if !nativeEqual(current, expected) || !rawExpressionsMatch(current.GetRules(), expected.GetRules()) {
			t.Fatal("profile transaction modified another owner")
		}
	}
}
