//go:build linux

package vmlab

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	configv1 "lindm/gen/lindm/config/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
)

// VMAssistanceOptions configures the maintained remote-assistance lane. Only
// signed official encrypted GNOME installer manifests and disposable VMs run.
type VMAssistanceOptions struct {
	Repository      string
	BuildRepository string
	LabBinary       string
	LindmdBinary    string
	// EvidenceDir is a new private directory owned by this run.
	EvidenceDir string
	// RelayAddress is the TURN relay allocation address. 127.0.0.1 keeps all
	// relayed media on the lab host.
	RelayAddress string
	Encrypted    EncryptedVMOptions
}

// assistanceRelayPorts is the relay allocation range size; four allocations
// per session suffice and the lane runs one session at a time.
const assistanceRelayPorts = 32

// assistanceOperator is the console account the browser enrolls and signs in
// with; it creates, joins and answers every session.
const assistanceOperator = "assistance-operator"

// AssistanceVM boots one encrypted GNOME clone, enrolls it against an isolated
// lindmd with the embedded relay, and drives real consent, portal, media,
// input and every local/operator end path through a real Chromium console.
func AssistanceVM(ctx context.Context, manifest *labv1.ImageManifest, options VMAssistanceOptions) (result *VMAssistanceResult, err error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	distribution := manifest.GetDistribution()
	if distribution != "ubuntu" && distribution != "fedora" {
		return nil, errors.New("assistance lane requires the Ubuntu 24.04/26.04 or Fedora 44 encrypted GNOME installer")
	}
	if options.Encrypted.Desktop != "gnome" || options.Encrypted.Hardware == nil || !options.Encrypted.Hardware.Desktop || !options.Encrypted.Hardware.AllowNetwork {
		return nil, errors.New("assistance lane requires the installer GNOME desktop, a lab display and signed-package egress")
	}
	evidence, err := newAssistanceEvidence(options.EvidenceDir)
	if err != nil {
		return nil, err
	}
	result = &VMAssistanceResult{ImageID: manifest.GetId(), ImageSHA256: manifest.GetSha256(), Distribution: distribution, Architecture: manifest.GetArchitecture(), StartedAt: time.Now().UTC(), Boundaries: []string{
		"One disposable QEMU guest (virtio-gpu, usb-tablet, PS/2 keyboard); local-user consent and stop clicks are QMP absolute-pointer input located from QMP screendumps, not a human at a physical display.",
		"Relayed media stays on the lab host: guest UDP reaches the embedded TURN listener through QEMU user networking (10.0.2.2 to host loopback); NAT traversal, public relays and multi-host paths are not qualified.",
		"The operator browser is headless Playwright Chromium on the lab host with a virtual WebAuthn authenticator; other browsers are not qualified by this lane.",
		"Media and control proofs are the console's own WebRTC statistics and decoded frames plus a guest-side typed nonce; video quality, latency and bandwidth are not qualified.",
		"GNOME idle blanking and automatic lock are disabled in the lab session; the lock scenario uses loginctl lock-session.",
	}}
	defer func() {
		result.FinishedAt = time.Now().UTC()
		if err == nil {
			err = verifyAssistanceEvidence(options.EvidenceDir, result)
		}
		result.Passed = err == nil
		if err != nil {
			result.Failure = err.Error()
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	if result.LabSHA256, err = dispatchFileDigest(options.LabBinary); err != nil {
		return result, err
	}
	if result.LindmdSHA256, err = dispatchFileDigest(options.LindmdBinary); err != nil {
		return result, err
	}
	packages, err := buildActionNativePackage(ctx, manifest, VMBuildRepository(options.Repository, options.BuildRepository), options.Encrypted.WorkDir)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, packages.Close()) }()
	result.PackageSHA256, result.SignerFingerprint = packages.artifact.SHA256, packages.fingerprint
	// Resolve a potentially cold installer golden before any bounded online
	// authority or session exists; NewEncryptedVM reuses the verified cache.
	if _, err := encryptedGolden(ctx, manifest, options.Encrypted); err != nil {
		return result, err
	}
	fixture, err := devlab.OpenDeviceActionAuthorityFixture(ctx, options.Repository, options.LindmdBinary)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, fixture.Close()) }()
	result.Database = fixture.DatabaseName
	// Enrollment imports the same isolated execution authority the native
	// action lanes use; assistance itself needs no signed action capability.
	delegation, err := fixture.ConfigureDeviceActions(ctx)
	if err != nil {
		return result, fmt.Errorf("configure isolated execution authority: %w", err)
	}
	assistance, err := reserveAssistanceRelay(options.RelayAddress)
	if err != nil {
		return result, err
	}
	relay := assistance.GetRelay()
	result.Relay = assistanceRelayEvidence{ListenerAddress: relay.GetListener().GetAddress(), ListenerPort: relay.GetListener().GetPort(), RelayAddress: relay.GetRelayAddress(), PortMin: relay.GetRelayPortMin(), PortMax: relay.GetRelayPortMax(), URLs: relay.GetUrls(), GuestRoute: "guest localhost -> 10.0.2.2 (QEMU user networking) -> host 127.0.0.1"}
	if err := fixture.ConfigureAssistance(ctx, assistance); err != nil {
		return result, fmt.Errorf("enable isolated assistance relay: %w", err)
	}
	control, err := openVMControlPlane(ctx, options.Repository, fixture)
	if err != nil {
		return result, fmt.Errorf("open isolated assistance control plane: %w", err)
	}
	defer func() { err = errors.Join(err, control.Close(context.WithoutCancel(ctx))) }()
	if err := control.applyExecutionAuthority(ctx, delegation, 1, 1, 0); err != nil {
		return result, fmt.Errorf("admit isolated execution authority: %w", err)
	}
	vm, err := NewEncryptedVM(ctx, manifest, options.Encrypted)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, vm.Close()) }()
	boot, err := vm.ColdBoot(ctx, vm.InitialUnlockSecret())
	if err != nil {
		return result, err
	}
	if !boot.PromptSeen {
		return result, errors.New("encrypted clone did not request its owner credential")
	}
	result.Firmware, result.RecipeVersion = vm.firmware, encryptedRecipeVersion
	if result.Runtime, err = vm.guest.runtimeEvidence(ctx); err != nil {
		return result, err
	}
	result.Runtime.SeedDisk = false
	guestStart, err := vm.guest.run(ctx, "date +%s", nil, 64, 10*time.Second)
	if err != nil {
		return result, err
	}
	since, err := strconv.ParseInt(strings.TrimSpace(string(guestStart)), 10, 64)
	if err != nil {
		return result, errors.New("invalid guest clock observation")
	}
	if err := packages.Install(ctx, vm.guest, options.LabBinary); err != nil {
		return result, err
	}
	result.Guest = &assistanceGuestEvidence{ExecutorSocket: "/run/lindm-session/session.sock"}
	if result.Guest.LocalhostResolution, err = routeAssistanceLocalhost(ctx, vm.guest); err != nil {
		return result, err
	}
	if err := configureAssistanceGuest(ctx, vm.guest); err != nil {
		return result, err
	}
	issued, _, err := enrollActionGuest(ctx, vm.guest, control, delegation)
	if err != nil {
		return result, err
	}
	result.DeviceID = issued.GetDeviceId()
	if err := waitNativeActionPresence(ctx, control.session, result.DeviceID); err != nil {
		return result, err
	}
	if result.Guest.Desktop, err = prepareAssistanceDesktop(ctx, vm, distribution); err != nil {
		return result, err
	}
	if err := waitAssistanceSessionUnit(ctx, vm.guest, result.Guest); err != nil {
		return result, err
	}
	if result.Guest.Packages, err = observeAssistancePackages(ctx, vm.guest, distribution); err != nil {
		return result, err
	}
	screen := &assistanceScreen{vm: vm.guest, evidence: evidence, result: result}
	if _, err := screen.captureReference(ctx); err != nil {
		return result, err
	}
	private, err := os.MkdirTemp("", "lindm-assistance-secrets-")
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(private)) }()
	browser, err := openAssistanceOperator(ctx, fixture, options, private)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, browser.Close()) }()
	result.Browser = &assistanceBrowserEvidence{Engine: "chromium", Version: browser.version, Username: assistanceOperator}
	run := &assistanceRun{vm: vm, screen: screen, browser: browser, owner: control.session, evidence: evidence, result: result, distribution: distribution, deviceID: result.DeviceID}
	var scenarioErr error
	for _, scenario := range assistanceScenarios {
		if scenarioErr = run.scenario(ctx, scenario); scenarioErr != nil {
			scenarioErr = fmt.Errorf("assistance scenario %s: %w", scenario.name, scenarioErr)
			break
		}
	}
	// Device journals are recorded for failures too: they are the product
	// slices' diagnostic for a wrong end cause.
	result.Journals, err = collectAssistanceJournals(ctx, vm.guest, since, evidence)
	if scenarioErr != nil || err != nil {
		return result, errors.Join(scenarioErr, err)
	}
	result.Audit, err = collectAssistanceAudit(ctx, control.session, result.Scenarios)
	return result, err
}

// openAssistanceOperator issues a distinct owner account through the real
// account API and lets Chromium enroll and sign in through the console UI.
// The browser driver comes from the checkout under test, like the packages.
func openAssistanceOperator(ctx context.Context, fixture *devlab.AuthorityFixture, options VMAssistanceOptions, private string) (*assistanceBrowser, error) {
	enrollment, err := fixture.CreateAcceptanceEnrollment(ctx, assistanceOperator)
	if err != nil {
		return nil, fmt.Errorf("issue assistance operator enrollment: %w", err)
	}
	defer func() { enrollment.Secret = "" }()
	cfg := assistanceBrowserConfig{Origin: fixture.ConsoleOrigin, Username: assistanceOperator, Password: rand.Text(), EnrollmentSecret: enrollment.GetSecret(), EvidenceDirectory: options.EvidenceDir, ActionTimeoutMS: 30000}
	browser, err := startAssistanceBrowser(ctx, VMBuildRepository(options.Repository, options.BuildRepository), private, cfg)
	cfg.Password, cfg.EnrollmentSecret = "", ""
	return browser, err
}

// reserveAssistanceRelay picks a free loopback TURN listener port (UDP and
// TCP) and a free relay allocation range on relayAddress. The guest reaches
// the loopback listener through QEMU's 10.0.2.2 host alias.
func reserveAssistanceRelay(relayAddress string) (*configv1.AssistanceConfig, error) {
	address, err := netip.ParseAddr(relayAddress)
	if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
		return nil, errors.New("assistance relay address must be a specific IPv4 address")
	}
	for range 20 {
		listenerPort, err := reserveUDPAndTCPPort()
		if err != nil {
			return nil, err
		}
		offset, err := rand.Int(rand.Reader, big.NewInt(20000-assistanceRelayPorts))
		if err != nil {
			return nil, err
		}
		base := 40000 + int(offset.Int64())
		if listenerPort >= base && listenerPort < base+assistanceRelayPorts || !udpRangeFree(address, base, assistanceRelayPorts) {
			continue
		}
		return &configv1.AssistanceConfig{Relay: &configv1.AssistanceRelayConfig{
			Listener:     &configv1.ListenerConfig{Address: "127.0.0.1", Port: uint32(listenerPort)},
			RelayAddress: address.String(),
			RelayPortMin: uint32(base),
			RelayPortMax: uint32(base + assistanceRelayPorts - 1),
			Urls:         []string{"turn:localhost:" + strconv.Itoa(listenerPort) + "?transport=udp"},
			Realm:        "lindm-lab",
		}}, nil
	}
	return nil, errors.New("no free assistance relay ports on the lab host")
}

func reserveUDPAndTCPPort() (int, error) {
	for range 20 {
		packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return 0, err
		}
		local, ok := packet.LocalAddr().(*net.UDPAddr)
		if !ok {
			return 0, errors.Join(errors.New("relay listener probe is not UDP"), packet.Close())
		}
		port := local.Port
		stream, streamErr := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		closeErr := packet.Close()
		if streamErr == nil {
			closeErr = errors.Join(closeErr, stream.Close())
			return port, closeErr
		}
		if closeErr != nil {
			return 0, closeErr
		}
	}
	return 0, errors.New("no free assistance relay listener port")
}

func udpRangeFree(address netip.Addr, base, count int) bool {
	for port := base; port < base+count; port++ {
		packet, err := net.ListenPacket("udp4", netip.AddrPortFrom(address, uint16(port)).String())
		if err != nil {
			return false
		}
		if err := packet.Close(); err != nil {
			return false
		}
	}
	return true
}

// assistanceScenarioSpec is one end-to-end session and its required end path.
type assistanceScenarioSpec struct {
	name  string
	mode  agentv1.AssistanceMode
	cause agentv1.AssistanceEndCause
	// portalCancel accepts the product prompt, then cancels the desktop's own
	// portal dialog instead (also DECLINED, without consent).
	portalCancel bool
}

var assistanceScenarios = []assistanceScenarioSpec{
	{name: "control", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED},
	{name: "view", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED},
	{name: "decline", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED},
	{name: "portal-cancel", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED, portalCancel: true},
	{name: "lock", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED},
}

// assistanceAuditExpectations are the audit actions each scenario must leave,
// in addition to assistance.end carrying its cause.
var assistanceAuditExpectations = map[string][]string{
	"control":       {"assistance.request", "assistance.prompt", "assistance.consent", "assistance.join", "assistance.answer", "assistance.start", "assistance.stop"},
	"view":          {"assistance.request", "assistance.prompt", "assistance.consent", "assistance.join", "assistance.answer", "assistance.start"},
	"lock":          {"assistance.request", "assistance.prompt", "assistance.consent", "assistance.join", "assistance.answer", "assistance.start"},
	"decline":       {"assistance.request", "assistance.prompt"},
	"portal-cancel": {"assistance.request", "assistance.prompt"},
}

func assistanceCauseText(cause agentv1.AssistanceEndCause) string {
	return strings.ToLower(strings.TrimPrefix(cause.String(), "ASSISTANCE_END_CAUSE_"))
}

func assistanceStateText(state adminv1.AssistanceState) string {
	return strings.ToLower(strings.TrimPrefix(state.String(), "ASSISTANCE_STATE_"))
}
