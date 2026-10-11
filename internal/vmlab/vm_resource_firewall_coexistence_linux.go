//go:build linux

package vmlab

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

// The firewall zone's coexistence scenarios: the distribution's active native
// manager, the real signed quarantine device action, external edits of the
// zone's own table and a native helper killed at the effect boundary. Every
// oracle reads the guest with the distribution's own tools, never the agent.

// firewallNativeManagerScript activates the native manager before any zone
// exists. UFW (iptables-nft) admits SSH and the oracle ports; firewalld is
// installed and enabled with its default zone, whose ports provisioning opens.
const firewallNativeManagerScript = `. /etc/os-release
case "$ID" in
ubuntu)
 ufw allow 22/tcp >/dev/null
 for port in 8080 8081 8083; do ufw allow "$port/tcp" >/dev/null; done
 ufw --force enable >/dev/null
 ufw status | grep -qx 'Status: active'
 ;;
fedora|rhel|almalinux)
 rpm -q firewalld >/dev/null 2>&1 || dnf -y -q install firewalld >/dev/null
 systemctl enable --now firewalld.service >/dev/null 2>&1
 firewall-cmd --state >/dev/null
 ;;
esac`

// firewallNativeTablesOracle digests every nftables table lindm does not own
// with the distribution's own nft: stateless (no counter values) and with
// handles, so any deleted, added or recreated native rule changes the digest.
const firewallNativeTablesOracle = `import hashlib, json, subprocess, sys
listing = sys.argv[1] == "1"
tables = json.loads(subprocess.run(["nft", "-j", "list", "tables"], check=True, capture_output=True).stdout)["nftables"]
for o in tables:
    t = o.get("table")
    if not t or t["name"].startswith(("lindm_z_", "lindm_q_", "lindm_probe_")):
        continue
    text = subprocess.run(["nft", "-s", "-a", "list", "table", t["family"], t["name"]], check=True, capture_output=True).stdout
    print("table %s %s sha256 %s" % (t["family"], t["name"], hashlib.sha256(text).hexdigest()))
    if listing:
        sys.stdout.write(text.decode())
`

// nativeManager names the active native manager's own tables and the commands
// that show its status and reload it.
func (f *firewallLane) nativeManager() (tables []string, status, reload string, err error) {
	switch f.distro {
	case "ubuntu":
		return []string{"ip filter", "ip6 filter"}, "ufw status verbose", "ufw reload >/dev/null && ufw status | grep -qx 'Status: active'", nil
	case "fedora", "rhel", "almalinux":
		return []string{"inet firewalld"}, "firewall-cmd --get-default-zone; firewall-cmd --list-all", "firewall-cmd --reload >/dev/null && firewall-cmd --state", nil
	}
	return nil, "", "", fmt.Errorf("no qualified native firewall manager for %q", f.distro)
}

// nativeTables reads every foreign table digest and requires the active
// native manager's own tables among them.
func (f *firewallLane) nativeTables(ctx context.Context, vm *guestVM, name string, listing bool) (map[string]string, VMResourceNativeRecord, error) {
	required, status, _, err := f.nativeManager()
	if err != nil {
		return nil, VMResourceNativeRecord{}, err
	}
	flag := "0"
	if listing {
		flag = "1"
	}
	record, err := resourceOracle(ctx, vm, name, "python3 -c "+nativeQuote(firewallNativeTablesOracle)+" "+flag+"; "+status)
	if err != nil {
		return nil, VMResourceNativeRecord{}, err
	}
	tables := make(map[string]string)
	for line := range strings.SplitSeq(string(record.Bytes), "\n") {
		if fields := strings.Fields(line); len(fields) == 5 && fields[0] == "table" && fields[3] == "sha256" {
			tables[fields[1]+" "+fields[2]] = fields[4]
		}
	}
	for _, table := range append(required, "inet "+firewallBaseline) {
		if tables[table] == "" {
			return nil, VMResourceNativeRecord{}, fmt.Errorf("%s: native table %s absent", name, table)
		}
	}
	return tables, record, nil
}

// baselineNativeTables records the full foreign listing that later scenarios
// must leave byte-identical.
func (f *firewallLane) baselineNativeTables(ctx context.Context, vm *guestVM, name string) (VMResourceNativeRecord, error) {
	tables, record, err := f.nativeTables(ctx, vm, name, true)
	if err != nil {
		return VMResourceNativeRecord{}, err
	}
	f.native = tables
	return record, nil
}

func (f *firewallLane) nativeUnchanged(ctx context.Context, vm *guestVM, name string) (VMResourceNativeRecord, error) {
	tables, record, err := f.nativeTables(ctx, vm, name, false)
	if err != nil {
		return VMResourceNativeRecord{}, err
	}
	if !maps.Equal(tables, f.native) {
		return VMResourceNativeRecord{}, fmt.Errorf("%s: native firewall tables changed: %v -> %v", name, f.native, tables)
	}
	return record, nil
}

// coexisting extends a zone oracle with the unchanged native manager tables.
func (f *firewallLane) coexisting(vm *guestVM, oracle func(context.Context) (VMResourceNativeRecord, error)) func(context.Context) (VMResourceNativeRecord, error) {
	return func(ctx context.Context) (VMResourceNativeRecord, error) {
		packets, err := oracle(ctx)
		if err != nil {
			return VMResourceNativeRecord{}, err
		}
		native, err := f.nativeUnchanged(ctx, vm, "native-manager-unchanged")
		if err != nil {
			return VMResourceNativeRecord{}, err
		}
		data := append(append(slices.Clone(packets.Bytes), "\n== foreign nftables tables (stateless, with handles) unchanged ==\n"...), native.Bytes...)
		return resourceNativeRecord(packets.Name+"-native-manager-unchanged", data), nil
	}
}

// zoneState digests the zone table's JSON with handles: equal digests mean the
// kernel objects were not deleted or recreated.
func zoneState(ctx context.Context, vm *guestVM, name string) (string, VMResourceNativeRecord, error) {
	record, err := resourceOracle(ctx, vm, name, "out=$(nft -a -j list table inet "+firewallZoneTable()+"); printf '%s\\n' \"$out\" | sha256sum; printf '%s\\n' \"$out\"")
	if err != nil {
		return "", VMResourceNativeRecord{}, err
	}
	digest, _, _ := strings.Cut(string(record.Bytes), " ")
	if len(digest) != 64 {
		return "", VMResourceNativeRecord{}, fmt.Errorf("%s: malformed zone digest", name)
	}
	return digest, record, nil
}

// scenario appends one named scenario; fail records diagnostics on error.
func firewallScenario(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence, name string) (*VMResourceScenario, func(error) error) {
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: name, StartedAt: time.Now().UTC()})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	return s, func(err error) error {
		s.Failure = err.Error()
		s.Native = append(s.Native, r.failureDiagnostics(ctx)...)
		return fmt.Errorf("%s: %w", name, err)
	}
}

func passScenario(s *VMResourceScenario, records ...VMResourceNativeRecord) {
	s.Native = append(s.Native, records...)
	s.FinishedAt = time.Now().UTC()
	s.Passed = true
}

// verifyUnchanged republishes the same desired state and requires a converged
// verification that acquired no start grant.
func (f *firewallLane) verifyUnchanged(ctx context.Context, r *resourceDispatch, extra bool) (*adminv1.ServiceActionSummary, error) {
	if err := r.assign(ctx, f.firewallZoneDesired(extra), resourceCreatePolicy()); err != nil {
		return nil, err
	}
	action, err := r.action(ctx, false)
	if err != nil {
		return action, err
	}
	if action.GetStartAuthorizedAt() != nil {
		return action, errors.New("verification of an unchanged zone acquired a start grant")
	}
	return action, nil
}

// nativeReloadStep reloads the native manager under a converged zone: the
// zone's kernel objects must be untouched and a fresh verification converge.
func (f *firewallLane) nativeReloadStep(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence, udp map[int]bool) error {
	s, fail := firewallScenario(ctx, r, evidence, "native-manager-reload-preserves-zone")
	_, _, reload, err := f.nativeManager()
	if err != nil {
		return fail(err)
	}
	before, zoneBefore, err := zoneState(ctx, r.vm, "zone-before-native-reload")
	if err != nil {
		return fail(err)
	}
	if err := lifecycleCommand(ctx, r.vm, "reload the native firewall manager", reload); err != nil {
		return fail(err)
	}
	after, zoneAfter, err := zoneState(ctx, r.vm, "zone-after-native-reload")
	if err != nil {
		return fail(err)
	}
	if before != after {
		return fail(errors.New("native manager reload changed the zone's kernel objects"))
	}
	previous := f.native
	reloaded, err := f.baselineNativeTables(ctx, r.vm, "native-manager-after-reload")
	if err != nil {
		return fail(err)
	}
	reloaded.Bytes = append(reloaded.Bytes, fmt.Sprintf("== native tables recreated by reload: %t ==\n", !maps.Equal(previous, f.native))...)
	reloaded = resourceNativeRecord(reloaded.Name, reloaded.Bytes)
	action, err := f.verifyUnchanged(ctx, r, true)
	s.Action = action
	if err != nil {
		return fail(err)
	}
	packets, err := f.coexisting(r.vm, f.oracle(r.vm, firewallExpectation{zone: true, tcp: firewallOpen(true), udp: udp}, true))(ctx)
	if err != nil {
		return fail(err)
	}
	passScenario(s, zoneBefore, zoneAfter, reloaded, packets)
	return nil
}

// firewallDNSQuery sends one A query for example.com to the quarantine's only
// explicit DNS server and requires its matching response.
const firewallDNSQuery = `import random, socket, struct, sys
server = sys.argv[1]
qid = random.randrange(65536)
name = b"".join(bytes([len(p)]) + p.encode() for p in "example.com".split(".")) + b"\x00"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + name + struct.pack(">HH", 1, 1), (server, 53))
data, peer = s.recvfrom(4096)
rid, flags, qd, an = struct.unpack(">HHHH", data[:8])
assert rid == qid and flags & 0x8000, "unmatched DNS response"
print("dns", server, "from", peer[0], "rcode", flags & 0xf, "answers", an)
`

// deviceAction dispatches one real signed device action through the server and
// returns its root/server outcome with the server's attested record.
func (f *firewallLane) deviceAction(ctx context.Context, r *resourceDispatch, kind string, spec *agentv1.DeviceActionSpec) (*actionDispatchEvidence, VMResourceNativeRecord, error) {
	identity, err := readVMConnectionIdentity(ctx, r.vm)
	if err != nil {
		return nil, VMResourceNativeRecord{}, err
	}
	request := actionRequestFor(r.device, identity.GetEnrollmentGeneration(), spec)
	request.Reason = "disposable firewall zone quarantine coexistence qualification"
	dispatched, _, err := dispatchNativeAction(ctx, r.vm, r.control.session, request, nil, false)
	if err != nil {
		return nil, VMResourceNativeRecord{}, err
	}
	server, err := r.control.session.Admin.GetDeviceAction(ctx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: dispatched.ActionID}))
	if err != nil {
		return dispatched, VMResourceNativeRecord{}, err
	}
	data, err := protojson.Marshal(server.Msg)
	if err != nil {
		return dispatched, VMResourceNativeRecord{}, err
	}
	return dispatched, resourceNativeRecord("server-attested-device-action-"+kind, data), nil
}

// quarantineSteps issue the real signed quarantine under the converged zone,
// prove its precedence and that the server withholds zone reconciliation,
// then release it and require the zone's exact behavior and the withheld
// verification to resume.
func (f *firewallLane) quarantineSteps(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence, udp map[int]bool) error {
	s, fail := firewallScenario(ctx, r, evidence, "real-quarantine-precedence")
	zone, zoneBefore, err := zoneState(ctx, r.vm, "zone-before-quarantine")
	if err != nil {
		return fail(err)
	}
	// Host inventory is collected every ten minutes; the server requires a
	// fresh one for device actions. The relay collects on start.
	if err := lifecycleCommand(ctx, r.vm, "restart relay for fresh host inventory", "systemctl restart lindm-agent.service"); err != nil {
		return fail(err)
	}
	quarantine, server, err := f.deviceAction(ctx, r, "quarantine", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Quarantine{Quarantine: &agentv1.QuarantineAction{ManagementEndpoints: slices.Clone(firewallQuarantineManagement)}}})
	if quarantine != nil {
		s.DeviceActions = append(s.DeviceActions, quarantine)
	}
	if err != nil {
		return fail(err)
	}
	table := "lindm_q_" + strings.ReplaceAll(quarantine.ActionID, "-", "")
	native, err := resourceOracle(ctx, r.vm, "action-owned-quarantine-table", "nft --version; nft list table inet "+table)
	if err != nil {
		return fail(err)
	}
	filtered := map[int]string{firewallAllowPort: "filtered", firewallDenyPort: "filtered", firewallExtraPort: "filtered"}
	held, err := f.coexisting(r.vm, f.oracle(r.vm, firewallExpectation{zone: true, quarantine: table, tcp: filtered, udp: map[int]bool{firewallUDPAllow: false, firewallUDPDeny: false}}, true))(ctx)
	if err != nil {
		return fail(err)
	}
	held.Name = "quarantine-held-" + held.Name
	dns, err := resourceOracle(ctx, r.vm, "quarantine-explicit-dns-allowed", "python3 -c "+nativeQuote(firewallDNSQuery)+" "+firewallQuarantineDNS)
	if err != nil {
		return fail(err)
	}
	during, zoneDuring, err := zoneState(ctx, r.vm, "zone-during-quarantine")
	if err != nil {
		return fail(err)
	}
	if during != zone {
		return fail(errors.New("zone kernel objects changed under quarantine"))
	}
	passScenario(s, server, native, held, dns, zoneBefore, zoneDuring)

	s, fail = firewallScenario(ctx, r, evidence, "quarantine-withholds-then-resumes-reconcile")
	if err := r.assign(ctx, f.firewallZoneDesired(true), resourceCreatePolicy()); err != nil {
		return fail(err)
	}
	withheld, err := f.withheldWindow(ctx, r, 30*time.Second)
	if err != nil {
		return fail(err)
	}
	during, zoneHeld, err := zoneState(ctx, r.vm, "zone-after-withheld-window")
	if err != nil {
		return fail(err)
	}
	if during != zone {
		return fail(errors.New("zone kernel objects changed while reconciliation was withheld"))
	}
	// The lab and lindmd share one clock: no zone work may predate the release.
	releaseRequested := time.Now()
	release, releaseServer, err := f.deviceAction(ctx, r, "release-quarantine", &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseQuarantine{ReleaseQuarantine: &agentv1.ReleaseQuarantineAction{QuarantineActionId: quarantine.ActionID}}})
	if release != nil {
		s.DeviceActions = append(s.DeviceActions, release)
	}
	if err != nil {
		return fail(err)
	}
	action, err := r.action(ctx, false)
	s.Action = action
	if err != nil {
		return fail(err)
	}
	if action.GetStartAuthorizedAt() != nil {
		return fail(errors.New("resumed verification acquired a start grant"))
	}
	if action.GetIssuedAt().AsTime().Before(releaseRequested) {
		return fail(errors.New("zone work was issued before the quarantine release was requested"))
	}
	restored, err := f.coexisting(r.vm, f.oracle(r.vm, firewallExpectation{zone: true, tcp: firewallOpen(true), udp: udp}, true))(ctx)
	if err != nil {
		return fail(err)
	}
	restored.Name = "after-release-" + restored.Name
	passScenario(s, withheld, zoneHeld, releaseServer, restored)
	return nil
}

// withheldWindow requires that the server mints no zone work for the current
// head while the device is quarantined.
func (f *firewallLane) withheldWindow(ctx context.Context, r *resourceDispatch, window time.Duration) (VMResourceNativeRecord, error) {
	deadline := time.Now().Add(window)
	var last *adminv1.GetDeviceResourceStateResponse
	polls := 0
	for time.Now().Before(deadline) {
		state, err := r.control.dispatchState(ctx, r.device)
		if err != nil {
			return VMResourceNativeRecord{}, err
		}
		if state.GetAssignment().GetAssignmentId() != r.head || len(state.GetResources()) != 1 {
			return VMResourceNativeRecord{}, errors.New("resource dispatch head/cardinality changed")
		}
		if action := state.GetResources()[0].GetLatestAction(); action != nil {
			return VMResourceNativeRecord{}, fmt.Errorf("server issued zone work %s while quarantined", action.GetActionId())
		}
		last = state
		polls++
		if err := lifecycleDelay(ctx, time.Second); err != nil {
			return VMResourceNativeRecord{}, err
		}
	}
	data, err := protojson.Marshal(last)
	if err != nil {
		return VMResourceNativeRecord{}, err
	}
	journal, err := r.vm.run(ctx, "sudo -n journalctl --no-pager -o short-iso -b -u lindm-agent.service --since=-2min 2>&1 | grep -F -e device_quarantined | tail -n 20 || true", nil, 64<<10, 30*time.Second)
	if err != nil {
		return VMResourceNativeRecord{}, err
	}
	out := fmt.Appendf(nil, "== %d server polls over %s: no zone action under head %s ==\n", polls, window, r.head)
	out = append(append(append(out, data...), "\n== relay journal: device_quarantined ==\n"...), journal...)
	return resourceNativeRecord("server-withheld-zone-work-while-quarantined", out), nil
}

// driftSteps edit lindm's own table externally. Per contract the changed
// table is a conflict: reconcile refuses with a device-signed precondition
// failure and never overwrites it. A foreign rule removed again restores the
// exact table; a deleted owned rule remains until boot replay (reboot-restore).
func (f *firewallLane) driftSteps(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence, udp map[int]bool) error {
	s, fail := firewallScenario(ctx, r, evidence, "external-rule-added-refused")
	added, err := resourceOracle(ctx, r.vm, "external-rule-added", "nft -e -a add rule inet "+firewallZoneTable()+" input tcp dport 9 accept")
	if err != nil {
		return fail(err)
	}
	// nft echoes the rule with its handle, then a "# new generation" line.
	first, _, _ := strings.Cut(string(added.Bytes), "\n")
	_, handle, found := strings.Cut(first, "# handle ")
	if _, err := strconv.ParseUint(handle, 10, 64); !found || err != nil {
		return fail(fmt.Errorf("external rule handle: %q", added.Bytes))
	}
	if err := f.refusedDrift(ctx, r, s); err != nil {
		return fail(err)
	}
	retained, err := resourceOracle(ctx, r.vm, "external-rule-retained", "nft -a list chain inet "+firewallZoneTable()+" input | grep -F 'tcp dport 9 accept # handle "+handle+"'")
	if err != nil {
		return fail(err)
	}
	packets, err := f.coexisting(r.vm, f.oracle(r.vm, firewallExpectation{zone: true, tcp: firewallOpen(true), udp: udp}, true))(ctx)
	if err != nil {
		return fail(err)
	}
	passScenario(s, added, retained, packets)

	s, fail = firewallScenario(ctx, r, evidence, "external-rule-removed-converged")
	removed, err := resourceOracle(ctx, r.vm, "external-rule-removed", "nft delete rule inet "+firewallZoneTable()+" input handle "+handle+"; nft -a list chain inet "+firewallZoneTable()+" input")
	if err != nil {
		return fail(err)
	}
	action, err := f.verifyUnchanged(ctx, r, true)
	s.Action = action
	if err != nil {
		return fail(err)
	}
	packets, err = f.coexisting(r.vm, f.oracle(r.vm, firewallExpectation{zone: true, tcp: firewallOpen(true), udp: udp}, true))(ctx)
	if err != nil {
		return fail(err)
	}
	passScenario(s, removed, packets)

	// Typed rules sort by priority then UUID; with the extra rules the IPv6
	// TCP 8080 accept is rule 1 and its terminal verdict lives in chain r001_2.
	s, fail = firewallScenario(ctx, r, evidence, "owned-rule-deleted-refused")
	deleted, err := resourceOracle(ctx, r.vm, "owned-rule-deleted", "chain=$(nft -a list chain inet "+firewallZoneTable()+" r001_2); printf '%s\\n' \"$chain\"; handle=$(printf '%s\\n' \"$chain\" | sed -n 's/^[[:space:]]*accept # handle \\([0-9][0-9]*\\)$/\\1/p'); test -n \"$handle\"; nft delete rule inet "+firewallZoneTable()+" r001_2 handle \"$handle\"; nft -a list chain inet "+firewallZoneTable()+" r001_2")
	if err != nil {
		return fail(err)
	}
	if err := f.refusedDrift(ctx, r, s); err != nil {
		return fail(err)
	}
	tcp6 := firewallOpen(true)
	tcp6[firewallAllowPort] = "filtered"
	packets, err = f.coexisting(r.vm, f.oracle(r.vm, firewallExpectation{zone: true, tcp: firewallOpen(true), tcp6: tcp6, udp: udp}, true))(ctx)
	if err != nil {
		return fail(err)
	}
	passScenario(s, deleted, packets)
	return nil
}

// refusedDrift republishes the converged desired state over an externally
// edited zone and requires a device-signed precondition refusal.
func (f *firewallLane) refusedDrift(ctx context.Context, r *resourceDispatch, s *VMResourceScenario) error {
	if err := r.assign(ctx, f.firewallZoneDesired(true), resourceCreatePolicy()); err != nil {
		return err
	}
	action, err := r.action(ctx, true)
	s.Action = action
	if err != nil {
		return err
	}
	status := action.GetStatus()
	if status.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_FAILED || status.GetFailure() != agentv1.ResourceExecutionFailure_RESOURCE_EXECUTION_FAILURE_PRECONDITION || action.GetStartAuthorizedAt() != nil {
		return fmt.Errorf("external zone edit was not refused before authority: %s", status)
	}
	return nil
}

// firewallCrashWatch waits on the guest for the native kernel batch (the
// extra rules disappear atomically) and then SIGKILLs the transient effect
// helper, which is still waiting for packet proof and controller confirmation.
const firewallCrashWatch = `set -u
table=$1
log=/run/lindm-lab-firewall-crash.log
: > "$log"
echo "armed $(date +%s.%N)" >> "$log"
state=
end=$(( $(date +%s) + 300 ))
while :; do
 rules=$(nft list table inet "$table" 2>&1) || { [ "$state" = error ] || echo "list failed $(date +%s.%N): $rules" >> "$log"; state=error; rules=; }
 case $rules in *"dport 8080"*) case $rules in *"dport 8083"*) [ "$state" = before ] || echo "pre-batch zone observed $(date +%s.%N)" >> "$log"; state=before ;; *) break;; esac;; esac
 if [ "$(date +%s)" -ge "$end" ]; then echo "timeout before kernel batch" >> "$log"; exit 1; fi
 sleep 0.02
done
echo "kernel batch observed $(date +%s.%N) after state '$state'" >> "$log"
units=$(systemctl list-units --plain --no-legend --all 'lindm-resource-*.service')
echo "$units" >> "$log"
unit=$(printf '%s\n' "$units" | awk '$3=="active"{print $1}')
test -n "$unit" || { echo "no active effect helper" >> "$log"; exit 1; }
systemctl kill --kill-whom=all --signal=SIGKILL "$unit"
echo "killed $unit $(date +%s.%N)" >> "$log"
`

// firewallGuardRecord copies the supervisor's retained root custody record
// out of the guest and decodes it with the lab's own schema.
func firewallGuardRecord(ctx context.Context, vm *guestVM) (*agentv1.ConnectivityGuardRecord, error) {
	data, err := vm.run(ctx, "sudo -n base64 -w0 /var/lib/lindm/connectivity-guard/firewall-guard.pb", nil, 8<<20, 30*time.Second)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, err
	}
	record := new(agentv1.ConnectivityGuardRecord)
	return record, proto.Unmarshal(raw, record)
}

func guardSummary(record *agentv1.ConnectivityGuardRecord) []byte {
	return fmt.Appendf(nil, "guard record: action %s phase %s boot %s worker %d applied %t confirmation %d bytes\n", record.GetRequest().GetActionId(), record.GetPhase(), record.GetBootId(), record.GetWorkerPid(), record.GetApplied() != nil, len(record.GetConfirmationReceipt()))
}

// crashSteps kill the effect helper after the kernel batch of a signed rule
// removal. The guard supervisor must restore the exact prior zone, the action
// must stay OUTCOME_UNKNOWN without replay, and the next signed reconcile must
// resolve ownership from that exact custody and apply as a new generation.
func (f *firewallLane) crashSteps(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence, udp map[int]bool) error {
	s, fail := firewallScenario(ctx, r, evidence, "helper-killed-after-kernel-batch")
	stateCommand := "nft -s list table inet " + firewallZoneTable() + "; sha256sum /var/lib/lindm/firewall/" + firewallZoneID + ".pb"
	before, err := resourceOracle(ctx, r.vm, "zone-before-interrupted-apply", stateCommand)
	if err != nil {
		return fail(err)
	}
	if err := firewallUpload(ctx, r.vm, firewallLabDir+"/crash-watch.sh", 0755, []byte(firewallCrashWatch)); err != nil {
		return fail(err)
	}
	if err := lifecycleCommand(ctx, r.vm, "arm the lab effect-boundary interruption", "systemctl reset-failed lindm-lab-crash-watch.service 2>/dev/null || true; systemd-run --quiet --unit=lindm-lab-crash-watch --property=Type=exec /bin/sh "+firewallLabDir+"/crash-watch.sh "+firewallZoneTable()); err != nil {
		return fail(err)
	}
	if err := r.assign(ctx, f.firewallZoneDesired(false), resourceCreatePolicy()); err != nil {
		return fail(err)
	}
	crashed, err := r.action(ctx, true)
	s.Action = crashed
	if err != nil {
		// The lab interruption point is the evidence of this scenario; keep
		// its own log beside the executor and guard diagnostics.
		if watch, logErr := r.vm.runResult(ctx, "sudo -n sh -c 'cat /run/lindm-lab-firewall-crash.log; systemctl status --no-pager lindm-lab-crash-watch.service; journalctl --no-pager -o short-iso -b -u lindm-lab-crash-watch.service -u lindm-connectivity-guard.service | tail -n 80' 2>&1", nil, 128<<10, 30*time.Second); logErr == nil {
			s.Native = append(s.Native, resourceNativeRecord("failure-diagnostic-lab-interruption", watch.Stdout))
		}
		return fail(err)
	}
	if crashed.GetStatus().GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_OUTCOME_UNKNOWN || crashed.GetStartAuthorizedAt() == nil {
		return fail(fmt.Errorf("interrupted apply did not end OUTCOME_UNKNOWN after its start grant: %s", crashed.GetStatus()))
	}
	watch, err := resourceOracle(ctx, r.vm, "lab-interruption-log", "cat /run/lindm-lab-firewall-crash.log; grep -q '^killed lindm-resource-"+crashed.GetActionId()+".service ' /run/lindm-lab-firewall-crash.log; journalctl --no-pager -o short-iso -b -u lindm-connectivity-guard.service -u 'lindm-resource-"+crashed.GetActionId()+".service' | tail -n 60")
	if err != nil {
		return fail(err)
	}
	var record *agentv1.ConnectivityGuardRecord
	for wait := time.Now().Add(2 * time.Minute); ; {
		if record, err = firewallGuardRecord(ctx, r.vm); err != nil {
			return fail(err)
		}
		if record.GetRequest().GetActionId() == crashed.GetActionId() && record.GetPhase() == agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_ROLLED_BACK {
			break
		}
		if time.Now().After(wait) {
			return fail(fmt.Errorf("guard did not roll back the interrupted transaction: %s", guardSummary(record)))
		}
		if err := lifecycleDelay(ctx, time.Second); err != nil {
			return fail(err)
		}
	}
	after, err := resourceOracle(ctx, r.vm, "zone-after-guard-rollback", stateCommand+"; nft list tables")
	if err != nil {
		return fail(err)
	}
	if !strings.HasPrefix(string(after.Bytes), string(before.Bytes)) {
		return fail(errors.New("guard rollback did not restore the exact prior zone and committed state"))
	}
	if strings.Contains(string(after.Bytes), "lindm_probe_") {
		return fail(errors.New("interrupted helper left a trace table"))
	}
	state, err := r.control.dispatchState(ctx, r.device)
	if err != nil {
		return fail(err)
	}
	if latest := state.GetResources()[0].GetLatestAction(); latest.GetActionId() != crashed.GetActionId() {
		return fail(errors.New("server issued replacement work for the interrupted effect"))
	}
	packets, err := f.coexisting(r.vm, f.oracle(r.vm, firewallExpectation{zone: true, tcp: firewallOpen(true), udp: udp}, true))(ctx)
	if err != nil {
		return fail(err)
	}
	passScenario(s, before, watch, resourceNativeRecord("guard-record-rolled-back", guardSummary(record)), after, packets)

	s, fail = firewallScenario(ctx, r, evidence, "outcome-unknown-resolved-by-observation")
	if err := r.assign(ctx, f.firewallZoneDesired(false), resourceCreatePolicy()); err != nil {
		return fail(err)
	}
	action, err := r.action(ctx, false)
	s.Action = action
	if err != nil {
		return fail(err)
	}
	if action.GetStartAuthorizedAt() == nil || action.GetActionId() == crashed.GetActionId() {
		return fail(errors.New("resolved zone was not applied by a new authorized action"))
	}
	if record, err = firewallGuardRecord(ctx, r.vm); err != nil {
		return fail(err)
	}
	if record.GetRequest().GetActionId() != action.GetActionId() || record.GetPhase() != agentv1.ConnectivityGuardPhase_CONNECTIVITY_GUARD_PHASE_COMMITTED {
		return fail(fmt.Errorf("new generation was not guard-committed: %s", guardSummary(record)))
	}
	packets, err = f.coexisting(r.vm, f.oracle(r.vm, firewallExpectation{zone: true, tcp: firewallOpen(false), udp: udp}, false))(ctx)
	if err != nil {
		return fail(err)
	}
	passScenario(s, resourceNativeRecord("guard-record-new-generation-committed", guardSummary(record)), packets)
	return nil
}

// releaseStep releases the zone to absence and requires every foreign table,
// including the native manager's, byte-identical (with handles) across it.
func (f *firewallLane) releaseStep(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence) error {
	before, pre, err := f.nativeTables(ctx, r.vm, "native-manager-before-release", true)
	if err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, evidence, "release-restores-absence", f.firewallZoneDesired(false).GetRef(), f.oracle(r.vm, firewallExpectation{tcp: map[int]string{firewallAllowPort: "open", firewallDenyPort: "open", firewallExtraPort: "open"}, udp: map[int]bool{firewallUDPAllow: true, firewallUDPDeny: true}}, false)); err != nil {
		return err
	}
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	after, post, err := f.nativeTables(ctx, r.vm, "native-manager-after-release", true)
	if err == nil && (!maps.Equal(before, f.native) || !maps.Equal(after, before)) {
		err = fmt.Errorf("release changed native firewall tables: %v -> %v -> %v", f.native, before, after)
	}
	if err != nil {
		s.Passed, s.Failure = false, err.Error()
		s.Native = append(s.Native, r.failureDiagnostics(ctx)...)
		return fmt.Errorf("release-restores-absence: %w", err)
	}
	s.Native = append(s.Native, pre, post)
	return nil
}
