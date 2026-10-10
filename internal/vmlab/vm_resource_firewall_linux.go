//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/devlab"
	"lindm/internal/packaging"
)

// The firewall lane's fixed two-guest topology. nic1 of the device and of an
// independent probe-peer guest share a lane-private host-local L2 link; the
// slirp management NIC (SSH and the controller's loopback forward) is outside
// the zone's root-approved interface boundary.
const (
	firewallDeviceMAC  = "52:54:00:77:00:10"
	firewallPeerMAC    = "52:54:00:77:00:20"
	firewallDevice4    = "192.168.77.10"
	firewallPeer4      = "192.168.77.20"
	firewallDevice6    = "fd77::10"
	firewallPeer6      = "fd77::20"
	firewallPeerPort   = 9443
	firewallZoneID     = "6c1f8f0e-58f4-4f43-9a52-2f1e3b7d9a10"
	firewallAllowPort  = 8080
	firewallDenyPort   = 8081
	firewallExtraPort  = 8083
	firewallUDPAllow   = 5300
	firewallUDPDeny    = 5301
	firewallLabDir     = "/etc/lindm-lab-firewall"
	firewallProbeDir   = "connectivity-probe"
	firewallBaseline   = "lindm_lab_baseline"
	firewallQuarantine = "lindm_lab_quarantine"
)

// Probe source ports lie above Linux's default ephemeral range (32768–60999),
// so the lab baseline's exact deny tuples never match an oracle connection.
const firewallProbeSourcePort = 61001

// firewallLane owns the peer guest, the private link directory and the root
// provisioning shared by device, peer and server. Targets are the exact same
// protobuf messages in all three configurations.
type firewallLane struct {
	link      string
	peer      *guestVM
	proof     ed25519.PrivateKey
	targets   []*agentv1.ConnectivityProbeTarget
	authority *devlab.ConnectivityProbeAuthority
	deviceIf  string
	peerIf    string
	// rebootDevice reboots the device and reopens its controller forwards.
	rebootDevice func(context.Context) error
}

// newFirewallLane boots the probe peer from the same verified image and returns
// the device's hardware with the opposite end of the private link.
func newFirewallLane(ctx context.Context, manifest *labv1.ImageManifest, cacheDir, workDir string, hardware *VMHardwareOptions) (_ *firewallLane, device *VMHardwareOptions, err error) {
	parent := workDir
	if parent == "" {
		parent = os.TempDir()
	}
	parent, err = filepath.Abs(parent)
	if err != nil {
		return nil, nil, err
	}
	link, err := os.MkdirTemp(parent, "lindm-link-")
	if err != nil {
		return nil, nil, err
	}
	f := &firewallLane{link: link}
	defer func() {
		if err != nil {
			err = errors.Join(err, f.Close())
		}
	}()
	_, f.proof, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	f.targets = firewallTargets(ed25519.PublicKey(f.proof[ed25519.SeedSize:]))
	deviceEnd, peerEnd := filepath.Join(link, "device.sock"), filepath.Join(link, "peer.sock")
	peerHardware, deviceHardware := VMHardwareOptions{}, VMHardwareOptions{}
	if hardware != nil {
		peerHardware, deviceHardware = *hardware, *hardware
	}
	peerHardware.dataLink = &vmDataLink{MAC: firewallPeerMAC, Local: peerEnd, Remote: deviceEnd}
	deviceHardware.dataLink = &vmDataLink{MAC: firewallDeviceMAC, Local: deviceEnd, Remote: peerEnd}
	f.peer, _, err = newVerifiedGuestWithHardware(ctx, manifest, cacheDir, workDir, true, &peerHardware)
	if err != nil {
		return nil, nil, fmt.Errorf("boot independent probe peer: %w", err)
	}
	return f, &deviceHardware, nil
}

func (f *firewallLane) Close() error {
	var err error
	if f.peer != nil {
		err = f.peer.close()
	}
	clear(f.proof)
	return errors.Join(err, os.RemoveAll(f.link))
}

// firewallTargets are the eight dual-stack INPUT/OUTPUT allow/deny experiments.
// The peer is the external sender for INPUT and the receiver for OUTPUT.
func firewallTargets(public ed25519.PublicKey) []*agentv1.ConnectivityProbeTarget {
	peer := &agentv1.ConnectivityProbePeer{Origin: "https://" + firewallPeer4 + ":" + strconv.Itoa(firewallPeerPort), PublicKey: public}
	var targets []*agentv1.ConnectivityProbeTarget
	port := uint32(firewallProbeSourcePort)
	for _, family := range [][2]string{{firewallDevice4, firewallPeer4}, {firewallDevice6, firewallPeer6}} {
		device, remote := family[0], family[1]
		for _, t := range []struct {
			direction agentv1.ConnectivityProbeDirection
			protocol  agentv1.ConnectivityProbeProtocol
			port      uint32
			expected  agentv1.ConnectivityProbeVerdict
		}{
			{agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_INPUT, agentv1.ConnectivityProbeProtocol_CONNECTIVITY_PROBE_PROTOCOL_TCP, firewallAllowPort, agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_ALLOW},
			{agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_INPUT, agentv1.ConnectivityProbeProtocol_CONNECTIVITY_PROBE_PROTOCOL_TCP, firewallDenyPort, agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_DENY},
			{agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_OUTPUT, agentv1.ConnectivityProbeProtocol_CONNECTIVITY_PROBE_PROTOCOL_UDP, firewallUDPAllow, agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_ALLOW},
			{agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_OUTPUT, agentv1.ConnectivityProbeProtocol_CONNECTIVITY_PROBE_PROTOCOL_UDP, firewallUDPDeny, agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_DENY},
		} {
			target := &agentv1.ConnectivityProbeTarget{Id: uuid.NewString(), Port: t.port, Expected: t.expected, SourcePort: port, Direction: t.direction, Protocol: t.protocol}
			if t.direction == agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_INPUT {
				target.Address, target.SourceAddress, target.Sender = device, remote, proto.CloneOf(peer)
			} else {
				target.Address, target.SourceAddress, target.Receiver = remote, device, proto.CloneOf(peer)
			}
			targets = append(targets, target)
			port++
		}
	}
	return targets
}

// firewallLinkScript assigns persistent static addresses to the NIC with the
// exact permanent MAC and prints its kernel name once both are usable.
// Ubuntu's netplan renders systemd-networkd; Fedora uses NetworkManager.
const firewallLinkScript = `set -eu
mac=$1; v4=$2; v6=$3
ifname=
for path in /sys/class/net/*; do
 if test "$(cat "$path/address")" = "$mac" && test "$(cat "$path/addr_assign_type")" = 0; then ifname=${path##*/}; fi
done
test -n "$ifname"
. /etc/os-release
case "$ID" in
ubuntu)
 install -d -m 0755 /etc/systemd/network
 cat > /etc/systemd/network/10-lindm-lab-peer-link.network <<EOF
[Match]
MACAddress=$mac

[Link]
RequiredForOnline=no

[Network]
DHCP=no
IPv6AcceptRA=no
LinkLocalAddressing=ipv6

[Address]
Address=$v4/24

[Address]
Address=$v6/64
DuplicateAddressDetection=none
EOF
 chmod 0644 /etc/systemd/network/10-lindm-lab-peer-link.network
 networkctl reload
 networkctl reconfigure "$ifname"
 ;;
fedora)
 cat > /etc/NetworkManager/system-connections/lindm-lab-peer-link.nmconnection <<EOF
[connection]
id=lindm-lab-peer-link
type=ethernet
autoconnect=true
autoconnect-priority=100

[ethernet]
mac-address=$mac

[ipv4]
method=manual
address1=$v4/24

[ipv6]
method=manual
address1=$v6/64
EOF
 chmod 0600 /etc/NetworkManager/system-connections/lindm-lab-peer-link.nmconnection
 restorecon -F /etc/NetworkManager/system-connections/lindm-lab-peer-link.nmconnection
 nmcli connection reload
 nmcli connection up lindm-lab-peer-link >/dev/null
 ;;
*) exit 1 ;;
esac
i=0
until ip -4 -o addr show dev "$ifname" | grep -qF " $v4/24" && ip -6 -o addr show dev "$ifname" | grep -qF " $v6/64" && test -z "$(ip -6 -o addr show dev "$ifname" tentative)"; do
 i=$((i+1)); test "$i" -lt 120; sleep 0.5
done
printf '%s\n' "$ifname"
`

func firewallConfigureLink(ctx context.Context, vm *guestVM, mac, v4, v6 string) (string, error) {
	result, err := vm.runResult(ctx, "sudo -n sh -c "+nativeQuote(firewallLinkScript)+" lindm-lab-link "+nativeQuote(mac)+" "+nativeQuote(v4)+" "+nativeQuote(v6)+" 2>&1", nil, 64<<10, 2*time.Minute)
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(string(result.Stdout))
	if result.ExitCode != 0 || strings.ContainsAny(name, " \n/") || name == "" || len(name) > 15 {
		return "", fmt.Errorf("configure static peer link: guest exit %d: %q", result.ExitCode, tail(result.Stdout, 1024))
	}
	return name, nil
}

func tail(data []byte, limit int) string {
	text := strings.TrimSpace(string(data))
	if len(text) > limit {
		text = text[len(text)-limit:]
	}
	return text
}

// firewallUpload installs root-owned bytes through stdin, never argv.
func firewallUpload(ctx context.Context, vm *guestVM, path string, mode os.FileMode, data []byte) error {
	command := "umask 077; tmp=$(mktemp " + nativeQuote(filepath.Dir(path)+"/.lindm-lab-XXXXXX") + "); cat > \"$tmp\"; chown root:root \"$tmp\"; chmod " + strconv.FormatUint(uint64(mode), 8) + " \"$tmp\"; mv -f \"$tmp\" " + nativeQuote(path) + "; if command -v restorecon >/dev/null 2>&1; then restorecon -F " + nativeQuote(path) + "; fi"
	result, err := vm.runResult(ctx, "sudo -n sh -eu -c "+nativeQuote(command), bytes.NewReader(data), 4096, time.Minute)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("install %s: guest exit %d: %q", path, result.ExitCode, tail(result.Stderr, 512))
	}
	return nil
}

func readGuestAgentConfig(ctx context.Context, vm *guestVM) (*agentv1.AgentConfig, error) {
	data, err := vm.run(ctx, "sudo -n cat /etc/lindm/executor.json", nil, 128<<10, 15*time.Second)
	if err != nil {
		return nil, err
	}
	config := new(agentv1.AgentConfig)
	if err := protojson.Unmarshal(data, config); err != nil {
		return nil, err
	}
	return config, nil
}

func writeGuestAgentConfig(ctx context.Context, vm *guestVM, config *agentv1.AgentConfig) error {
	if err := protovalidate.Validate(config); err != nil {
		return err
	}
	encoded, err := protojson.Marshal(config)
	if err != nil {
		return err
	}
	return firewallUpload(ctx, vm, "/etc/lindm/executor.json", 0600, encoded)
}

// installPeer installs the same signed agent package on the unenrolled peer.
func (f *firewallLane) installPeer(ctx context.Context, manifest *labv1.ImageManifest, artifact packaging.Artifact, apt *packaging.APTRepository, publicKey, fingerprint string) error {
	if err := f.peer.connect(ctx); err != nil {
		return fmt.Errorf("connect probe peer: %w", err)
	}
	if _, err := f.peer.run(ctx, "sudo -n cloud-init status --wait --format=json", nil, 64<<10, 5*time.Minute); err != nil {
		return err
	}
	if err := pinArchRepositories(ctx, f.peer, manifest); err != nil {
		return err
	}
	packages, err := newNativeGuestPackages(ctx, f.peer, artifact, artifact, apt, publicKey, fingerprint)
	if err != nil {
		return err
	}
	return errors.Join(packages.InstallFirst(ctx), packages.Close())
}

// firewallPeerWitness is an independent UDP receiver used only by the lab's
// egress oracle; it logs datagrams carrying a lab nonce.
const firewallPeerWitness = `import socket, select
socks = []
for port in (5300, 5301):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.bind(("::", port))
    socks.append(s)
with open("/run/lindm-lab-firewall/udp.log", "a", buffering=1) as log:
    while True:
        ready, _, _ = select.select(socks, [], [])
        for s in ready:
            data, peer = s.recvfrom(256)
            if data.startswith(b"lindm-lab-"):
                log.write("%d %s %s\n" % (s.getsockname()[1], peer[0], data.decode("ascii", "replace")))
`

// firewallDeviceListener accepts and closes TCP connections on the zone's
// allow, deny and reconciled ports so the peer's packet oracle sees open vs
// filtered rather than a refused port.
const firewallDeviceListener = `import socket, select
socks = []
for port in (8080, 8081, 8083):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("::", port))
    s.listen(16)
    socks.append(s)
while True:
    ready, _, _ = select.select(socks, [], [])
    for s in ready:
        conn, _ = s.accept()
        conn.close()
`

// provisionPeer gives the peer root-owned probe credentials and targets, and a
// firewall that admits exactly the probe control port and receiver ports.
func (f *firewallLane) provisionPeer(ctx context.Context, authority *devlab.ConnectivityProbeAuthority) ([]VMResourceNativeRecord, error) {
	f.authority = authority
	var err error
	f.peerIf, err = firewallConfigureLink(ctx, f.peer, firewallPeerMAC, firewallPeer4, firewallPeer6)
	if err != nil {
		return nil, err
	}
	proofDER, err := x509.MarshalPKCS8PrivateKey(f.proof)
	if err != nil {
		return nil, err
	}
	proofPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: proofDER})
	clear(proofDER)
	defer clear(proofPEM)
	if err := lifecycleCommand(ctx, f.peer, "create probe credential directory", "install -d -o root -g root -m 0700 /etc/lindm/"+firewallProbeDir+" "+firewallLabDir+" /run/lindm-lab-firewall"); err != nil {
		return nil, err
	}
	for _, file := range []struct {
		name string
		mode os.FileMode
		data []byte
	}{{"tls.crt", 0644, authority.PeerCertificatePEM}, {"tls.key", 0600, authority.PeerKeyPEM}, {"device-ca.crt", 0644, authority.DeviceCAPEM}, {"proof.key", 0600, proofPEM}} {
		if err := firewallUpload(ctx, f.peer, "/etc/lindm/"+firewallProbeDir+"/"+file.name, file.mode, file.data); err != nil {
			return nil, err
		}
	}
	config, err := readGuestAgentConfig(ctx, f.peer)
	if err != nil {
		return nil, err
	}
	config.ConnectivityProbe = &agentv1.ConnectivityProbeServerConfig{
		Origin: "https://" + firewallPeer4 + ":" + strconv.Itoa(firewallPeerPort), DeploymentId: authority.DeploymentID,
		ListenAddress: firewallPeer4, ListenPort: firewallPeerPort,
		TlsCertificateFile: firewallProbeDir + "/tls.crt", TlsPrivateKeyFile: firewallProbeDir + "/tls.key",
		DeviceCaFile: firewallProbeDir + "/device-ca.crt", ProofKeyFile: firewallProbeDir + "/proof.key",
		Targets: cloneTargets(f.targets),
	}
	if err := writeGuestAgentConfig(ctx, f.peer, config); err != nil {
		return nil, err
	}
	if err := firewallUpload(ctx, f.peer, firewallLabDir+"/udp-witness.py", 0644, []byte(firewallPeerWitness)); err != nil {
		return nil, err
	}
	// Fedora keeps firewalld active (typed coexistence): only the probe control
	// and receiver ports are opened. Receivers are post-filter raw sockets.
	script := `set -eu
if systemctl is-active --quiet firewalld.service; then
 firewall-cmd --permanent --add-port=` + strconv.Itoa(firewallPeerPort) + `/tcp --add-port=5300/udp --add-port=5301/udp >/dev/null
 firewall-cmd --reload >/dev/null
fi
systemd-run --quiet --unit=lindm-lab-udp-witness --property=Type=exec /usr/bin/python3 ` + firewallLabDir + `/udp-witness.py
systemctl enable --now lindm-connectivity-probe.service
i=0
until ss -Hltn "sport = :` + strconv.Itoa(firewallPeerPort) + `" | grep -qF '` + firewallPeer4 + `:` + strconv.Itoa(firewallPeerPort) + `'; do i=$((i+1)); test "$i" -lt 60; sleep 0.5; done
`
	if err := lifecycleCommand(ctx, f.peer, "start independent probe peer", script); err != nil {
		return nil, errors.Join(err, errors.New(f.peerJournal(ctx)))
	}
	record, err := resourceOracle(ctx, f.peer, "probe-peer-provisioning", "printf 'ifname %s\\n' "+nativeQuote(f.peerIf)+"; ip -o addr show dev "+nativeQuote(f.peerIf)+"; systemctl show -p ActiveState -p SubState lindm-connectivity-probe.service; ss -Hltn; "+firewallHostFirewallEvidence+"; if test -e /sys/fs/selinux/enforce; then getenforce; fi")
	if err != nil {
		return nil, err
	}
	return []VMResourceNativeRecord{record}, nil
}

func cloneTargets(targets []*agentv1.ConnectivityProbeTarget) []*agentv1.ConnectivityProbeTarget {
	cloned := make([]*agentv1.ConnectivityProbeTarget, len(targets))
	for i, target := range targets {
		cloned[i] = proto.CloneOf(target)
	}
	return cloned
}

// firewallHostFirewallEvidence records the distribution firewall the zone
// coexists with: its package, enablement and live rules when active.
const firewallHostFirewallEvidence = "if command -v rpm >/dev/null 2>&1; then rpm -q firewalld || true; fi; printf 'firewalld enablement: %s\\n' \"$(systemctl is-enabled firewalld.service 2>&1 || true)\"; if systemctl is-active --quiet firewalld.service; then firewall-cmd --list-all; else printf 'firewalld not active\\n'; fi; if command -v ufw >/dev/null 2>&1; then ufw status verbose; fi; if command -v nft >/dev/null 2>&1; then nft list tables; fi"

func (f *firewallLane) peerJournal(ctx context.Context) string {
	data, err := f.peer.run(ctx, "sudo -n journalctl --no-pager -o short-iso -b -n 200 -u lindm-connectivity-probe.service -u lindm-lab-udp-witness.service 2>&1", nil, 128<<10, 30*time.Second)
	if err != nil {
		return err.Error()
	}
	return string(data)
}

// firewallBaselineRules is a lab-owned foreign table after the zone (priority
// 100) that drops exactly the DENY probe tuples. While the zone exists its own
// earlier drop is traced first; after release to absence it keeps the static
// deny experiments meaningful without admitting or blocking anything else.
func firewallBaselineRules(ifname string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\ntable inet %s {\n", firewallBaseline, firewallBaseline, firewallBaseline)
	b.WriteString(" chain input {\n  type filter hook input priority 100; policy accept;\n")
	for i, family := range []string{"ip", "ip6"} {
		device, peer := firewallDevice4, firewallPeer4
		if i == 1 {
			device, peer = firewallDevice6, firewallPeer6
		}
		fmt.Fprintf(&b, "  iifname %q %s saddr %s %s daddr %s tcp sport %d tcp dport %d drop\n", ifname, family, peer, family, device, firewallProbeSourcePort+4*i+1, firewallDenyPort)
	}
	b.WriteString(" }\n chain output {\n  type filter hook output priority 100; policy accept;\n")
	for i, family := range []string{"ip", "ip6"} {
		device, peer := firewallDevice4, firewallPeer4
		if i == 1 {
			device, peer = firewallDevice6, firewallPeer6
		}
		fmt.Fprintf(&b, "  oifname %q %s saddr %s %s daddr %s udp sport %d udp dport %d drop\n", ifname, family, device, family, peer, firewallProbeSourcePort+4*i+3, firewallUDPDeny)
	}
	b.WriteString(" }\n}\n")
	return b.String()
}

// firewallQuarantineRules imitates the action-owned quarantine shape: a
// foreign inet table at priority -10 that drops the zone's allowed port.
func firewallQuarantineRules(ifname string) string {
	return fmt.Sprintf("table inet %s {\n chain input {\n  type filter hook input priority -10; policy accept;\n  iifname %q tcp dport %d drop\n }\n}\n", firewallQuarantine, ifname, firewallAllowPort)
}

const firewallLabUnits = `[Unit]
Description=Disposable lindm lab deny-probe baseline (not lindm-owned)
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f ` + firewallLabDir + `/baseline.nft

[Install]
WantedBy=multi-user.target
`

const firewallListenerUnit = `[Unit]
Description=Disposable lindm lab TCP oracle listener

[Service]
Type=exec
ExecStart=/usr/bin/python3 ` + firewallLabDir + `/listener.py

[Install]
WantedBy=multi-user.target
`

// provisionDevice configures nic1, the lab baseline and oracle listener, then
// root-provisions the firewall provider and connectivity guard and enables the
// packaged guard and restore units before restarting the executor.
func (f *firewallLane) provisionDevice(ctx context.Context, vm *guestVM) ([]VMResourceNativeRecord, error) {
	var err error
	f.deviceIf, err = firewallConfigureLink(ctx, vm, firewallDeviceMAC, firewallDevice4, firewallDevice6)
	if err != nil {
		return nil, err
	}
	if err := lifecycleCommand(ctx, vm, "create lab firewall fixture directory", "install -d -o root -g root -m 0755 "+firewallLabDir); err != nil {
		return nil, err
	}
	for _, file := range []struct{ path, data string }{
		{firewallLabDir + "/baseline.nft", firewallBaselineRules(f.deviceIf)},
		{firewallLabDir + "/listener.py", firewallDeviceListener},
		{"/etc/systemd/system/lindm-lab-firewall-baseline.service", firewallLabUnits},
		{"/etc/systemd/system/lindm-lab-firewall-listener.service", firewallListenerUnit},
	} {
		if err := firewallUpload(ctx, vm, file.path, 0644, []byte(file.data)); err != nil {
			return nil, err
		}
	}
	// Fedora keeps firewalld active (typed coexistence): its default zone
	// admits only the oracle ports, so the lindm zone decides the probes.
	script := `set -eu
if ! command -v nft >/dev/null 2>&1; then
 export DEBIAN_FRONTEND=noninteractive
 apt-get install -y nftables >/dev/null 2>&1 || { apt-get update -q >/dev/null && apt-get install -y nftables >/dev/null; }
fi
if systemctl is-active --quiet firewalld.service; then
 firewall-cmd --permanent --add-port=8080/tcp --add-port=8081/tcp --add-port=8083/tcp >/dev/null
 firewall-cmd --reload >/dev/null
fi
systemctl daemon-reload
systemctl enable --now lindm-lab-firewall-baseline.service lindm-lab-firewall-listener.service
i=0
until test "$(ss -Hltn '( sport = :8080 or sport = :8081 or sport = :8083 )' | wc -l)" -ge 3; do i=$((i+1)); test "$i" -lt 60; sleep 0.5; done
`
	if err := lifecycleCommand(ctx, vm, "install lab firewall baseline and oracle listener", script); err != nil {
		return nil, err
	}
	config, err := readGuestAgentConfig(ctx, vm)
	if err != nil {
		return nil, err
	}
	selector := f.deviceSelector()
	config.FirewallProvider = &agentv1.NativeFirewallProviderConfig{AllowedInterfaces: []*resourcev1.InterfaceSelector{selector}, ManagementEndpoints: []*agentv1.NativeFirewallEndpoint{{Address: firewallPeer4, Port: firewallPeerPort}}}
	config.ConnectivityGuard = &agentv1.ConnectivityGuardConfig{Probes: cloneTargets(f.targets), ConfirmationPublicKey: append([]byte(nil), f.authority.ConfirmationPublicKey...)}
	if err := writeGuestAgentConfig(ctx, vm, config); err != nil {
		return nil, err
	}
	if err := lifecycleCommand(ctx, vm, "enable packaged firewall guard and restore", "systemctl enable lindm-firewall-restore.service; systemctl enable lindm-connectivity-guard.service; systemctl restart lindm-connectivity-guard.service; systemctl is-active --quiet lindm-connectivity-guard.service; systemctl restart lindm-executor.service"); err != nil {
		return nil, err
	}
	if _, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return nil, err
	}
	record, err := resourceOracle(ctx, vm, "firewall-device-provisioning", "printf 'ifname %s\\n' "+nativeQuote(f.deviceIf)+"; ip -o addr show dev "+nativeQuote(f.deviceIf)+"; cat /sys/class/net/"+f.deviceIf+"/addr_assign_type; systemctl show -p ActiveState -p UnitFileState lindm-connectivity-guard.service lindm-firewall-restore.service lindm-lab-firewall-baseline.service; readlink /etc/systemd/system/network-pre.target.wants/lindm-firewall-restore.service; sha256sum /usr/lib/systemd/system/lindm-firewall-restore.service; nft list table inet "+firewallBaseline+"; "+firewallHostFirewallEvidence+"; if test -e /sys/fs/selinux/enforce; then getenforce; fi")
	if err != nil {
		return nil, err
	}
	return []VMResourceNativeRecord{record}, nil
}

func (f *firewallLane) deviceSelector() *resourcev1.InterfaceSelector {
	return &resourcev1.InterfaceSelector{Identity: &resourcev1.InterfaceSelector_PermanentMac{PermanentMac: firewallDeviceMAC}, Ifname: proto.String(f.deviceIf)}
}

// Fixed rule identities make every revision a pure typed change.
var firewallRuleIDs = [...]string{
	"0b4f6a52-1d2e-4c3b-8f9a-7e6d5c4b3a01", "0b4f6a52-1d2e-4c3b-8f9a-7e6d5c4b3a02",
	"0b4f6a52-1d2e-4c3b-8f9a-7e6d5c4b3a03", "0b4f6a52-1d2e-4c3b-8f9a-7e6d5c4b3a04",
	"0b4f6a52-1d2e-4c3b-8f9a-7e6d5c4b3a05", "0b4f6a52-1d2e-4c3b-8f9a-7e6d5c4b3a06",
}

// firewallZoneDesired drops unlisted ingress on nic1, accepts TCP 8080 (and
// 8083 after reconciliation) from the peer and drops egress to UDP 5301.
func (f *firewallLane) firewallZoneDesired(extra bool) *resourcev1.ResourceDesiredState {
	host := func(address string, family resourcev1.IPFamily) []*resourcev1.CIDR {
		prefix := uint32(32)
		if family == resourcev1.IPFamily_IP_FAMILY_IPV6 {
			prefix = 128
		}
		return []*resourcev1.CIDR{{NetworkAddress: address, PrefixLength: prefix}}
	}
	ports := func(port uint32) []*resourcev1.PortRange { return []*resourcev1.PortRange{{First: port, Last: port}} }
	var rules []*resourcev1.FirewallRule
	for i, family := range []resourcev1.IPFamily{resourcev1.IPFamily_IP_FAMILY_IPV4, resourcev1.IPFamily_IP_FAMILY_IPV6} {
		peer := firewallPeer4
		if i == 1 {
			peer = firewallPeer6
		}
		rules = append(rules,
			&resourcev1.FirewallRule{RuleId: firewallRuleIDs[i], Direction: resourcev1.FirewallDirection_FIREWALL_DIRECTION_INPUT, Family: family, Protocol: resourcev1.IPProtocol_IP_PROTOCOL_TCP, Sources: host(peer, family), DestinationPorts: ports(firewallAllowPort), Verdict: resourcev1.FirewallVerdict_FIREWALL_VERDICT_ACCEPT},
			&resourcev1.FirewallRule{RuleId: firewallRuleIDs[2+i], Direction: resourcev1.FirewallDirection_FIREWALL_DIRECTION_OUTPUT, Family: family, Protocol: resourcev1.IPProtocol_IP_PROTOCOL_UDP, Destinations: host(peer, family), DestinationPorts: ports(firewallUDPDeny), Verdict: resourcev1.FirewallVerdict_FIREWALL_VERDICT_DROP})
		if extra {
			rules = append(rules, &resourcev1.FirewallRule{RuleId: firewallRuleIDs[4+i], Direction: resourcev1.FirewallDirection_FIREWALL_DIRECTION_INPUT, Family: family, Protocol: resourcev1.IPProtocol_IP_PROTOCOL_TCP, Sources: host(peer, family), DestinationPorts: ports(firewallExtraPort), Verdict: resourcev1.FirewallVerdict_FIREWALL_VERDICT_ACCEPT})
		}
	}
	zone := &resourcev1.FirewallZoneDesired{ZoneId: firewallZoneID, Presence: resourcev1.Presence_PRESENCE_PRESENT, Interfaces: []*resourcev1.InterfaceSelector{f.deviceSelector()}, DefaultIngress: resourcev1.FirewallVerdict_FIREWALL_VERDICT_DROP, DefaultEgress: resourcev1.FirewallVerdict_FIREWALL_VERDICT_ACCEPT, Rules: rules}
	return &resourcev1.ResourceDesiredState{Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_FIREWALL_ZONE, CanonicalKey: firewallZoneID}, State: &resourcev1.ResourceDesiredState_FirewallZone{FirewallZone: zone}}
}

// firewallExpectation is the independent packet result the peer must observe.
type firewallExpectation struct {
	zone       bool
	quarantine bool
	tcp        map[int]string
	udp        map[int]bool
}

func firewallZoneTable() string {
	return "lindm_z_" + strings.ReplaceAll(firewallZoneID, "-", "")
}

// firewallRulesetOracle reads the device's complete JSON ruleset with the
// distribution's own nft and reports only lindm-named tables and the table
// list, so foreign firewalld state is bounded but still visible.
const firewallRulesetOracle = `import json, subprocess, sys
zone, extra, present, quarantine = sys.argv[1], sys.argv[2] == "1", sys.argv[3] == "1", sys.argv[4] == "1"
ruleset = json.loads(subprocess.run(["nft", "-j", "list", "ruleset"], check=True, capture_output=True).stdout)["nftables"]
tables = sorted("%s %s" % (o["table"]["family"], o["table"]["name"]) for o in ruleset if "table" in o)
owned = [o for o in ruleset if any(k in o and o[k].get("table", o[k].get("name", "")).startswith("lindm_") for k in ("table", "chain", "rule"))]
print("tables:", ", ".join(tables))
print(json.dumps(owned, sort_keys=True))
def values(node, found):
    if isinstance(node, dict):
        if "right" in node:
            right = node["right"]
            if isinstance(right, int):
                found.add(right)
            elif isinstance(right, dict) and "range" in right:
                found.update(range(right["range"][0], right["range"][1] + 1))
        for value in node.values():
            values(value, found)
    elif isinstance(node, list):
        for value in node:
            values(value, found)
    return found
matched = values([o["rule"]["expr"] for o in owned if "rule" in o and o["rule"]["table"] == zone], set())
assert ("inet " + zone in tables) == present, "zone table presence"
assert ("inet lindm_lab_quarantine" in tables) == quarantine, "quarantine table presence"
assert "inet lindm_lab_baseline" in tables, "lab deny baseline"
if present:
    chains = {o["chain"]["name"]: o["chain"] for o in owned if "chain" in o and o["chain"]["table"] == zone}
    for hook in ("input", "output", "forward"):
        assert chains[hook].get("hook") == hook and chains[hook].get("prio") == 10 and chains[hook].get("policy") == "accept", hook
    assert {8080, 5301} <= matched, "typed rules"
    assert (8083 in matched) == extra, "reconciled rule"
print("zone", "present" if present else "absent", "extra", extra)
`

// firewallTCPOracle connects from the peer with ephemeral source ports; a
// DROP verdict appears as a timeout ("filtered"), never as refused.
const firewallTCPOracle = `import socket, sys
for host in sys.argv[1].split(","):
    for port in map(int, sys.argv[2].split(",")):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            s.connect((host, port))
            result = "open"
        except socket.timeout:
            result = "filtered"
        except ConnectionRefusedError:
            result = "refused"
        except OSError as e:
            result = "error-%d" % e.errno
        finally:
            s.close()
        print("tcp", host, port, result)
`

// firewallUDPSender sends nonce datagrams from the device to the peer witness.
const firewallUDPSender = `import socket, sys
nonce = sys.argv[1]
for host in ("192.168.77.20", "fd77::20"):
    for port in (5300, 5301):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        s = socket.socket(family, socket.SOCK_DGRAM)
        try:
            s.sendto(("%s-%s-%d" % (nonce, host, port)).encode(), (host, port))
            print("udp-send", host, port, "sent")
        except PermissionError:
            print("udp-send", host, port, "eperm")
        finally:
            s.close()
`

// oracle combines the device's own nft JSON view with the independent peer's
// TCP connection results and UDP receipts.
func (f *firewallLane) oracle(vm *guestVM, expect firewallExpectation, extra bool) func(context.Context) (VMResourceNativeRecord, error) {
	return func(ctx context.Context) (VMResourceNativeRecord, error) {
		var out bytes.Buffer
		flag := func(v bool) string {
			if v {
				return "1"
			}
			return "0"
		}
		ruleset, err := resourceOracle(ctx, vm, "nft", "python3 -c "+nativeQuote(firewallRulesetOracle)+" "+firewallZoneTable()+" "+flag(extra)+" "+flag(expect.zone)+" "+flag(expect.quarantine))
		if err != nil {
			return VMResourceNativeRecord{}, err
		}
		out.WriteString("== device nft -j list ruleset (lindm tables) ==\n")
		out.Write(ruleset.Bytes)
		ports := make([]int, 0, len(expect.tcp))
		for port := range expect.tcp {
			ports = append(ports, port)
		}
		slices.Sort(ports)
		portList := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(ports)), ","), "[]")
		packets, err := f.peer.runResult(ctx, "python3 -c "+nativeQuote(firewallTCPOracle)+" "+firewallDevice4+","+firewallDevice6+" "+portList, nil, 16<<10, time.Minute)
		if err != nil {
			return VMResourceNativeRecord{}, err
		}
		if packets.ExitCode != 0 {
			return VMResourceNativeRecord{}, fmt.Errorf("peer TCP oracle exit %d: %q", packets.ExitCode, tail(packets.Stderr, 512))
		}
		out.WriteString("== peer TCP connections to device ==\n")
		out.Write(packets.Stdout)
		for _, line := range strings.Split(strings.TrimSpace(string(packets.Stdout)), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 4 {
				return VMResourceNativeRecord{}, fmt.Errorf("malformed peer TCP oracle line %q", line)
			}
			port, err := strconv.Atoi(fields[2])
			if err != nil || expect.tcp[port] != fields[3] {
				return VMResourceNativeRecord{}, fmt.Errorf("peer observed %s, expected %s on port %s", line, expect.tcp[port], fields[2])
			}
		}
		nonce := "lindm-lab-" + uuid.NewString()
		sent, err := vm.runResult(ctx, "python3 -c "+nativeQuote(firewallUDPSender)+" "+nonce, nil, 16<<10, time.Minute)
		if err != nil {
			return VMResourceNativeRecord{}, err
		}
		if sent.ExitCode != 0 {
			return VMResourceNativeRecord{}, fmt.Errorf("device UDP sender exit %d: %q", sent.ExitCode, tail(sent.Stderr, 512))
		}
		out.WriteString("== device UDP sends ==\n")
		out.Write(sent.Stdout)
		if err := lifecycleDelay(ctx, 2*time.Second); err != nil {
			return VMResourceNativeRecord{}, err
		}
		received, err := f.peer.run(ctx, "sudo -n sh -c "+nativeQuote("grep -F "+nativeQuote(nonce)+" /run/lindm-lab-firewall/udp.log || true"), nil, 16<<10, 30*time.Second)
		if err != nil {
			return VMResourceNativeRecord{}, err
		}
		out.WriteString("== peer UDP witness receipts ==\n")
		out.Write(received)
		for _, host := range []string{firewallPeer4, firewallPeer6} {
			for port, want := range expect.udp {
				got := bytes.Contains(received, []byte(nonce+"-"+host+"-"+strconv.Itoa(port)))
				if got != want {
					return VMResourceNativeRecord{}, fmt.Errorf("peer UDP receipt for %s:%d = %v, expected %v", host, port, got, want)
				}
			}
		}
		return resourceNativeRecord("device-nft-json-and-peer-packet-oracle", out.Bytes()), nil
	}
}

// diagnostics retains the guard, restore, probe peer and ruleset context for
// a failed firewall scenario. It is never qualification evidence.
func (f *firewallLane) diagnostics(vm *guestVM) func(context.Context) []VMResourceNativeRecord {
	return func(ctx context.Context) []VMResourceNativeRecord {
		data, err := vm.run(ctx, "sudo -n sh -c "+nativeQuote("journalctl --no-pager -o short-iso -b -n 3000 -u lindm-executor.service -u 'lindm-observe-*' -u 'lindm-package-*' -u lindm-connectivity-guard.service -u lindm-firewall-restore.service -u lindm-lab-firewall-baseline.service | grep -v -e native-observation-custody -e resource_execution_not_found -e rate_limited | tail -n 400; nft list ruleset; ls -la /var/lib/lindm/firewall /var/lib/lindm/connectivity-guard")+" 2>&1 | tail -c 196608", nil, 256<<10, 30*time.Second)
		if err != nil {
			data = []byte(err.Error())
		}
		return []VMResourceNativeRecord{resourceNativeRecord("failure-diagnostic-firewall-guard-restore-ruleset", data), resourceNativeRecord("failure-diagnostic-probe-peer-journal", []byte(f.peerJournal(ctx)))}
	}
}

func firewallOpen(extra bool) map[int]string {
	tcp := map[int]string{firewallAllowPort: "open", firewallDenyPort: "filtered", firewallExtraPort: "filtered"}
	if extra {
		tcp[firewallExtraPort] = "open"
	}
	return tcp
}

// exerciseResourceFirewall runs the connected firewall zone scenarios. Every
// converged step carries the device's fresh allow/deny probe receipts and the
// controller's DSSE confirmation; every oracle is independent of the agent.
func exerciseResourceFirewall(ctx context.Context, r *resourceDispatch, f *firewallLane, fixtures *[]VMResourceNativeRecord, evidence *VMResourceKindEvidence) error {
	if f == nil || f.authority == nil {
		return errors.New("firewall lane requires the provisioned probe peer and controller targets")
	}
	provisioned, err := f.provisionDevice(ctx, r.vm)
	if err != nil {
		return fmt.Errorf("provision device firewall roots: %w", err)
	}
	*fixtures = append(*fixtures, provisioned...)
	r.diagnostics = f.diagnostics(r.vm)
	defer func() { r.diagnostics = nil }()
	before, err := f.oracle(r.vm, firewallExpectation{tcp: map[int]string{firewallAllowPort: "open", firewallDenyPort: "open", firewallExtraPort: "open"}, udp: map[int]bool{firewallUDPAllow: true, firewallUDPDeny: true}}, false)(ctx)
	if err != nil {
		return fmt.Errorf("pre-zone packet baseline: %w", err)
	}
	before.Name = "pre-zone-" + before.Name
	*fixtures = append(*fixtures, before)
	zoneUDP := map[int]bool{firewallUDPAllow: true, firewallUDPDeny: false}
	r.fresh()
	if err := resourceStep(ctx, r, evidence, "zone-create-converged", f.firewallZoneDesired(false), resourceCreatePolicy(), false, f.oracle(r.vm, firewallExpectation{zone: true, tcp: firewallOpen(false), udp: zoneUDP}, false)); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "repeat-no-start-grant", f.firewallZoneDesired(false), resourceCreatePolicy(), true, f.oracle(r.vm, firewallExpectation{zone: true, tcp: firewallOpen(false), udp: zoneUDP}, false)); err != nil {
		return err
	}
	if err := resourceStep(ctx, r, evidence, "reconcile-rule-change", f.firewallZoneDesired(true), resourceCreatePolicy(), false, f.oracle(r.vm, firewallExpectation{zone: true, tcp: firewallOpen(true), udp: zoneUDP}, true)); err != nil {
		return err
	}
	if err := f.quarantineStep(ctx, r, evidence, zoneUDP); err != nil {
		return err
	}
	if err := f.rebootStep(ctx, r, evidence, zoneUDP); err != nil {
		return err
	}
	if err := resourceReleaseStep(ctx, r, evidence, "release-restores-absence", f.firewallZoneDesired(true).GetRef(), f.oracle(r.vm, firewallExpectation{tcp: map[int]string{firewallAllowPort: "open", firewallDenyPort: "open", firewallExtraPort: "open"}, udp: map[int]bool{firewallUDPAllow: true, firewallUDPDeny: true}}, false)); err != nil {
		return err
	}
	evidence.Unproven = []string{
		"real timed quarantine device action not exercised; a lab-owned priority -10 drop table stands in for its precedence",
		"FORWARD probes, partitions, generation-CAS races, foreign drift, approved adoption and guard crash boundaries not exercised",
	}
	return qualifyResourceEvidence(evidence, []string{"zone-create-converged", "repeat-no-start-grant", "reconcile-rule-change", "quarantine-precedence", "reboot-restore", "release-restores-absence"})
}

// quarantineStep proves a foreign priority -10 drop stays final over the
// zone's accept, then removes it and requires a fresh converged verification
// (no start grant) with the zone's accept restored.
func (f *firewallLane) quarantineStep(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence, udp map[int]bool) error {
	const name = "quarantine-precedence"
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: name, StartedAt: time.Now().UTC()})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	fail := func(err error) error {
		s.Failure = err.Error()
		s.Native = append(s.Native, r.failureDiagnostics(ctx)...)
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := firewallUpload(ctx, r.vm, firewallLabDir+"/quarantine.nft", 0644, []byte(firewallQuarantineRules(f.deviceIf))); err != nil {
		return fail(err)
	}
	if err := lifecycleCommand(ctx, r.vm, "install lab quarantine-priority drop", "nft -f "+firewallLabDir+"/quarantine.nft"); err != nil {
		return fail(err)
	}
	quarantined := firewallOpen(true)
	quarantined[firewallAllowPort] = "filtered"
	held, err := f.oracle(r.vm, firewallExpectation{zone: true, quarantine: true, tcp: quarantined, udp: udp}, true)(ctx)
	if err != nil {
		return fail(err)
	}
	held.Name = "quarantine-held-" + held.Name
	if err := lifecycleCommand(ctx, r.vm, "remove lab quarantine-priority drop", "nft delete table inet "+firewallQuarantine); err != nil {
		return fail(err)
	}
	if err := r.assign(ctx, f.firewallZoneDesired(true), resourceCreatePolicy()); err != nil {
		return fail(err)
	}
	action, err := r.action(ctx, false)
	s.Action = action
	if err != nil {
		return fail(err)
	}
	if action.GetStartAuthorizedAt() != nil {
		return fail(errors.New("verification after quarantine removal acquired a start grant"))
	}
	after, err := f.oracle(r.vm, firewallExpectation{zone: true, tcp: firewallOpen(true), udp: udp}, true)(ctx)
	if err != nil {
		return fail(err)
	}
	s.Native = []VMResourceNativeRecord{held, after}
	s.FinishedAt = time.Now().UTC()
	s.Passed = true
	return nil
}

// rebootStep reboots the device: the packaged guard and restore units must
// replay only the committed typed state before the network, and a fresh
// verification (no start grant) must converge with new packet receipts.
func (f *firewallLane) rebootStep(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence, udp map[int]bool) error {
	const name = "reboot-restore"
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: name, StartedAt: time.Now().UTC()})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	fail := func(err error) error {
		s.Failure = err.Error()
		s.Native = append(s.Native, r.failureDiagnostics(ctx)...)
		return fmt.Errorf("%s: %w", name, err)
	}
	if f.rebootDevice == nil {
		return fail(errors.New("device reboot is not wired"))
	}
	if err := f.rebootDevice(ctx); err != nil {
		return fail(err)
	}
	if _, err := waitGuestExecutorReady(ctx, r.vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return fail(err)
	}
	restored, err := resourceOracle(ctx, r.vm, "boot-restore-units", "systemctl show -p ActiveState -p Result -p ExecMainStatus lindm-firewall-restore.service lindm-connectivity-guard.service; test \"$(systemctl show -p Result --value lindm-firewall-restore.service)\" = success; test \"$(systemctl show -p ActiveState --value lindm-firewall-restore.service)\" = active; journalctl --no-pager -o short-iso -b -u lindm-connectivity-guard.service -u lindm-firewall-restore.service; ls -la /var/lib/lindm/firewall")
	if err != nil {
		return fail(err)
	}
	booted, err := f.oracle(r.vm, firewallExpectation{zone: true, tcp: firewallOpen(true), udp: udp}, true)(ctx)
	if err != nil {
		return fail(err)
	}
	booted.Name = "after-boot-" + booted.Name
	if err := r.assign(ctx, f.firewallZoneDesired(true), resourceCreatePolicy()); err != nil {
		return fail(err)
	}
	action, err := r.action(ctx, false)
	s.Action = action
	if err != nil {
		return fail(err)
	}
	if action.GetStartAuthorizedAt() != nil {
		return fail(errors.New("verification of the restored zone acquired a start grant"))
	}
	s.Native = []VMResourceNativeRecord{restored, booted}
	s.FinishedAt = time.Now().UTC()
	s.Passed = true
	return nil
}

// firewallBootID reads the protected boot identity before a deliberate reboot.
func firewallBootID(ctx context.Context, vm *guestVM) (string, error) {
	data, err := vm.run(ctx, "cat /proc/sys/kernel/random/boot_id", nil, 128, 10*time.Second)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(data))
	if _, err := uuid.Parse(id); err != nil {
		return "", err
	}
	return id, nil
}
