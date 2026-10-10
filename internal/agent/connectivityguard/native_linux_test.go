//go:build linux

package connectivityguard

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Actual packet/netlink test, confined to a reexecuted private network namespace.
// It does not certify installed services, external peers, FORWARD routing, reboot
// recovery, or a platform matrix. Those remain parent native qualification gates.
func TestNativeNonceTraceAndSocketOwnedCleanup(t *testing.T) {
	if os.Getenv("LINDM_CONNECTIVITY_TRACE_CHILD") != "1" {
		if os.Geteuid() != 0 {
			t.Skip("requires root and a disposable network namespace")
		}
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, "-test.run=^TestNativeNonceTraceAndSocketOwnedCleanup$", "-test.v")
		command.Env = append(os.Environ(), "LINDM_CONNECTIVITY_TRACE_CHILD=1")
		command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
		output, err := command.CombinedOutput()
		if errors.Is(err, unix.EPERM) {
			t.Skip("network namespace privilege unavailable")
		}
		if err != nil {
			t.Fatalf("isolated packet trace: %v\n%s", err, output)
		}
		if bytes.Contains(output, []byte("--- SKIP:")) {
			t.Skip(string(output))
		}
		return
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("iproute2 fixture tool unavailable")
	}
	run := func(args ...string) {
		t.Helper()
		output, err := exec.CommandContext(t.Context(), ip, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("private namespace setup: %v %s", err, output)
		}
	}
	run("link", "set", "lo", "up")
	for _, address := range []string{"192.0.2.1/32", "192.0.2.2/32"} {
		run("address", "add", address, "dev", "lo")
	}
	for _, address := range []string{"2001:db8::1/128", "2001:db8::2/128"} {
		run("-6", "address", "add", address, "dev", "lo", "nodad")
	}
	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.CloseLasting() }()
	policy := nftables.ChainPolicyAccept
	for _, direction := range []agentv1.ConnectivityProbeDirection{agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_INPUT, agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_OUTPUT} {
		for _, v6 := range []bool{false, true} {
			for _, protocol := range []agentv1.ConnectivityProbeProtocol{agentv1.ConnectivityProbeProtocol_CONNECTIVITY_PROBE_PROTOCOL_TCP, agentv1.ConnectivityProbeProtocol_CONNECTIVITY_PROBE_PROTOCOL_UDP} {
				for _, verdict := range []string{"accept", "drop", "reject"} {
					target, packet, _ := probeFixture(t)
					target.Direction = direction
					target.Protocol = protocol
					if v6 {
						target.SourceAddress = "2001:db8::1"
						target.Address = "2001:db8::2"
					}
					if verdict != "accept" {
						target.Expected = agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_DENY
					}
					table := &nftables.Table{Name: "lindm_test_target", Family: nftables.TableFamilyINet}
					hook := nftables.ChainHookInput
					if direction == agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_OUTPUT {
						hook = nftables.ChainHookOutput
					}
					chain := &nftables.Chain{Name: "policy", Table: table, Type: nftables.ChainTypeFilter, Hooknum: hook, Priority: nftables.ChainPriorityFilter, Policy: &policy}
					var effect expr.Any = &expr.Verdict{Kind: expr.VerdictAccept}
					switch verdict {
					case "drop":
						effect = &expr.Verdict{Kind: expr.VerdictDrop}
					case "reject":
						effect = &expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED}
					}
					conn.AddTable(table)
					conn.AddChain(chain)
					conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{effect}})
					if err := conn.Flush(); errors.Is(err, unix.EPERM) {
						t.Skip("nftables privilege unavailable")
					} else if err != nil {
						t.Fatal(err)
					}
					rules, err := conn.GetRules(table, chain)
					if err != nil || len(rules) != 1 {
						t.Fatalf("native rule: %v", err)
					}
					snapshot := &agentv1.FirewallNativeSnapshot{Table: table.Name, Chains: []*agentv1.FirewallNativeChain{{Name: chain.Name, Hook: proto.Uint32(uint32(*hook)), Policy: proto.Uint32(1)}}, Rules: []*agentv1.FirewallNativeRule{{Chain: chain.Name, Handle: rules[0].Handle}}}
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					trace, err := startTrace(ctx, target, packet.GetNonce(), snapshot)
					if err != nil {
						cancel()
						t.Fatal(err)
					}
					traceName := trace.table.Name
					var receiver *packetReceiver
					if verdict == "accept" {
						receiver, err = receivePackets(target, packet.GetNonce())
						if err != nil {
							t.Fatal(err)
						}
					}
					_, sendErr := transmitPacket(ctx, target, packet.GetNonce())
					if sendErr != nil && verdict == "accept" {
						t.Fatal(sendErr)
					}
					proof, err := trace.observe(ctx)
					if err != nil {
						t.Fatalf("direction=%v IPv6=%v protocol=%v verdict=%s: %v", direction, v6, protocol, verdict, err)
					}
					if proof.GetTable() != table.Name || proof.GetRuleHandle() != rules[0].Handle {
						t.Fatal("native proof did not identify exact target rule")
					}
					if receiver != nil {
						ticker := time.NewTicker(time.Millisecond)
						for {
							digest, err := receiver.observe()
							if err != nil {
								t.Fatal(err)
							}
							if len(digest) != 0 {
								break
							}
							select {
							case <-ctx.Done():
								t.Fatal("ACCEPT lacked actual post-filter receive")
							case <-ticker.C:
							}
						}
						ticker.Stop()
						if err := receiver.close(); err != nil {
							t.Fatal(err)
						}
					}
					if err := trace.close(); err != nil {
						t.Fatal(err)
					}
					cancel()
					tables, err := conn.ListTables()
					if err != nil {
						t.Fatal(err)
					}
					for _, table := range tables {
						if table.Name == traceName {
							t.Fatal("diagnostic table survived owner socket close")
						}
					}
					conn.DelTable(table)
					if err := conn.Flush(); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
}
