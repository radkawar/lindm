//go:build linux

package vmlab

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/devlab"
	"lindm/internal/platform"
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
	// RedHatTokenFile registers an entitled organization device with RHSM;
	// only the organization demo mode uses it.
	RedHatTokenFile string
	// RedHatRegistered durably records an organization device's RHSM identity
	// on its controller: the public run name before Red Hat is contacted, then
	// the same run's consumer UUID. The worker continues only after it returns.
	RedHatRegistered func(context.Context, *labv1.RedHatRegistrationIdentity) error
	// Scenarios selects lane scenarios by name, in lane order; nil runs all.
	Scenarios []string
	// Hold, when set, receives the owner's access once the selected scenarios
	// passed; lindmd and the VM then keep running until ctx ends. Any held run
	// is a hands-on demo, never a qualification record.
	Hold func(*AssistanceHold) error
	// ConsoleTURNTCP restricts the operator Chromium to TURN over TCP, as a
	// remote browser behind an SSH forward is, and requires a TCP relay pair.
	ConsoleTURNTCP bool
	// ControlPlane connects to a controller-owned fixture through SSH forwards.
	ControlPlane *AssistanceControlPlane
	// AdvisoryCache persists revalidated vendor feeds for hands-on demos.
	AdvisoryCache string
	// PersistentDir retains one enrolled machine; FixtureDir retains its local
	// fixture or the remote authority credentials in split topology.
	PersistentDir string
	FixtureDir    string
	ExistingOwner bool
	// RebootPolicy selects separate reboot qualification using this desktop
	// fixture. It never qualifies remote assistance or a persistent demo.
	RebootPolicy *VMRebootPolicyResult
}

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
	architecture, err := nativePackageArchitecture(manifest.GetArchitecture())
	if err != nil {
		return nil, err
	}
	release := platform.ForManifest(manifest.GetDistribution(), manifest.GetVersion())
	desktop, err := labDesktopFor(options.Encrypted.Desktop, release)
	if err != nil {
		return nil, err
	}
	if err := assistanceAdmission(release, desktop); err != nil {
		return nil, err
	}
	if options.Encrypted.Hardware == nil || !options.Encrypted.Hardware.Desktop || !options.Encrypted.Hardware.AllowNetwork {
		return nil, errors.New("assistance lane requires an installer desktop, a lab display and signed-package egress")
	}
	if options.RebootPolicy != nil && (options.Hold != nil || options.PersistentDir != "") {
		return nil, errors.New("reboot qualification refuses persistent or held desktops")
	}
	if options.PersistentDir != "" && (options.Hold == nil || options.FixtureDir == "") {
		return nil, errors.New("persistent assistance requires hold and a persistent fixture directory")
	}
	resuming := false
	if options.PersistentDir != "" {
		_, statErr := os.Lstat(options.PersistentDir)
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return nil, statErr
		}
		resuming = statErr == nil
	}
	evidence, err := newAssistanceEvidence(options.EvidenceDir)
	if err != nil {
		return nil, err
	}
	result = &VMAssistanceResult{ImageID: manifest.GetId(), ImageSHA256: manifest.GetSha256(), Distribution: manifest.GetDistribution(), DesktopProfile: desktop.name, Architecture: manifest.GetArchitecture(), StartedAt: time.Now().UTC(), Boundaries: []string{
		"One disposable QEMU guest (virtio-gpu, usb-tablet, virtual keyboard); local-user consent and stop clicks are QMP absolute-pointer input located from QMP screendumps, not a human at a physical display.",
		"Relayed media stays on the lab host: guest UDP reaches the embedded TURN listener through QEMU user networking (10.0.2.2 to host loopback); NAT traversal, public relays and multi-host paths are not qualified.",
		"The operator browser is headless Playwright Chromium on the lab host with a virtual WebAuthn authenticator; other browsers are not qualified by this lane.",
		"Media and control proofs are the console's own WebRTC statistics and decoded frames plus a guest-side typed nonce; video quality, latency and bandwidth are not qualified.",
		"Idle blanking and automatic lock are disabled in the lab " + desktop.name + " session; the lock scenario uses loginctl lock-session.",
		"Scenarios that must end UNAVAILABLE prove the visible refusal before consent on this desktop, not that the capability works.",
		"Tier1 witnesses use a disposable native GTK client and fresh nonces; clipboard automation is explicit, never continuous synchronization. Message visibility is OCR of QMP pixels, not notification command acceptance.",
		"The GTK witness requires and records GdkWaylandDisplay, observed UID and logind display-session identity. XWayland applications and Wayland/XWayland clipboard interoperability are not qualified.",
		"Mandatory native negative witnesses cover per-device policy revocation, a real custom-role creator with remote_assistance.view and remote_assistance.control but no remote_assistance.clipboard, denied direction, and oversized/ended-session RPC refusals with independent fresh unchanged GTK clipboard observations; modifier release and selected-monitor hot-unplug are also required. Selected subsets do not inherit these proofs.",
		"The policy scenario exercises an administrative per-device POLICY downgrade and matching session revocation. Neither agent nor deployment CONFIG ceiling restriction is exercised; both configured ceilings remain ON. FD cancellation and unmappable-Unicode injection remain separate deterministic criteria, not native passes.",
		"Two-head qualification requires two active native GDK monitors backed by distinct virtio-gpu scanouts activated with private RFB SetDesktopSize. No physical multi-monitor, other compositor, IME, file transfer or secure-attention claim is made.",
	}}
	if options.ControlPlane != nil {
		options.ConsoleTURNTCP = true
		result.Topology = "split"
		result.Boundaries[1] = "One-time enrollment uses the console origin through the lab host's SSH forward. Device mTLS and media traffic dial out through QEMU user NAT and the routed LAN to the controller. The admin browser uses SSH reverse forwards for HTTPS and TURN TCP. Public Internet NAT traversal is not qualified."
		result.Boundaries = append(result.Boundaries, "The split operator test driver filters only ICE server URLs to the SSH-forwarded localhost TURN TCP endpoint, modeling an admin outside the controller LAN; the console's own relay-only policy is unchanged and the selected candidate URL and TCP protocol are required.")
	} else {
		result.Topology = "colocated"
	}
	defer func() {
		result.FinishedAt = time.Now().UTC()
		if err == nil {
			err = verifyAssistanceEvidence(options.EvidenceDir, result)
		}
		result.Passed = err == nil && options.RebootPolicy == nil
		result.TierOnePassed = result.Passed && len(result.Witnesses) == 6 && len(result.NotRun) == 0 && completeAssistanceNativeBoundaries(result)
		if err != nil {
			result.Failure = err.Error()
		}
	}()
	// Setup and scenarios are bounded; a held demo then outlives the bound,
	// so the deadline cancels a context the owned processes keep using.
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	deadline := time.AfterFunc(2*time.Hour, func() { cancel(errors.New("assistance lane exceeded its 2h bound")) })
	defer deadline.Stop()
	scenarios, err := selectAssistanceScenarios(desktop.assistance, options.Scenarios)
	if err != nil {
		return result, err
	}
	tierOne := false
	selected := make([]assistanceScenarioSpec, 0, len(scenarios))
	for _, scenario := range scenarios {
		if scenario.capability != "" {
			if gateErr := release.Gate(scenario.capability); gateErr != nil {
				if options.Scenarios != nil {
					return result, gateErr
				}
				result.NotRun = append(result.NotRun, assistanceNotRunEvidence{Scenario: scenario.name, Capability: string(scenario.capability), Reason: gateErr.Error()})
				continue
			}
			tierOne = true
		}
		selected = append(selected, scenario)
	}
	scenarios = selected
	if slices.ContainsFunc(scenarios, func(scenario assistanceScenarioSpec) bool { return scenario.name == "monitors" }) {
		hardware := *options.Encrypted.Hardware
		hardware.DisplayHeads = 2
		options.Encrypted.Hardware = &hardware
	}
	if len(result.NotRun) != 0 {
		result.Boundaries = append(result.Boundaries, "Passed covers only the recorded scenarios; capability not-run entries are unsupported/not-qualified, never capability passes. tier_one_passed remains false.")
	}
	if result.LabSHA256, err = dispatchFileDigest(options.LabBinary); err != nil {
		return result, err
	}
	if options.ControlPlane != nil {
		result.LindmdSHA256 = options.ControlPlane.LindmdSHA256
	} else if result.LindmdSHA256, err = dispatchFileDigest(options.LindmdBinary); err != nil {
		return result, err
	}
	var packages *actionNativePackage
	if !resuming {
		packages, err = buildActionNativePackage(ctx, manifest, VMBuildRepository(options.Repository, options.BuildRepository), options.Encrypted.WorkDir)
		if err != nil {
			return result, err
		}
		defer func() { err = errors.Join(err, packages.Close()) }()
		result.PackageSHA256, result.SignerFingerprint = packages.artifact.SHA256, packages.fingerprint
		// Resolve a cold installer before bounded online authority exists.
		if _, err := encryptedGolden(ctx, manifest, options.Encrypted); err != nil {
			return result, err
		}
	}
	fixture, delegation, relay, err := openAssistanceFixture(ctx, options, architecture)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, fixture.Close()) }()
	result.Database, result.Relay = fixture.DatabaseName, relay
	control, err := openVMControlPlane(ctx, options.Repository, fixture)
	if err != nil {
		return result, fmt.Errorf("open isolated assistance control plane: %w", err)
	}
	defer func() { err = errors.Join(err, control.Close(context.WithoutCancel(ctx))) }()
	if options.ControlPlane == nil {
		if err := ensureAssistanceAuthority(ctx, control, delegation); err != nil {
			return result, fmt.Errorf("admit isolated execution authority: %w", err)
		}
	}
	vm, saved, err := openHeldVM(ctx, manifest, options, resuming)
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
	if !resuming {
		// The agent package Recommends the capture stack; the lab installs it with
		// --no-install-recommends, so install the release's capture packages from
		// its signed archive first (Debian's GNOME task lacks gstreamer1.0-tools).
		// A refusal-only desktop never captures; its stack is only recorded.
		if !desktop.refusalOnly() {
			if err := installAssistanceCapture(ctx, vm.guest, release); err != nil {
				return result, err
			}
		}
		if err := packages.Install(ctx, vm.guest, options.LabBinary); err != nil {
			return result, err
		}
	}
	result.Guest = &assistanceGuestEvidence{ExecutorSocket: "/run/lindm-session/session.sock"}
	if result.Guest.LocalhostResolution, err = routeAssistanceLocalhost(ctx, vm.guest); err != nil {
		return result, err
	}
	if options.ControlPlane != nil {
		route, routeErr := vm.guest.run(ctx, "ip route get "+options.ControlPlane.ControllerAddress, nil, 4096, 10*time.Second)
		if routeErr != nil {
			return result, routeErr
		}
		result.Guest.ControllerRoute = strings.TrimSpace(string(route))
	}
	if !resuming {
		if err := configureAssistanceGuest(ctx, vm.guest); err != nil {
			return result, err
		}
		issued, _, err := enrollActionGuest(ctx, vm.guest, control, delegation)
		if err != nil {
			return result, err
		}
		result.DeviceID = issued.GetDeviceId()
		if options.PersistentDir != "" {
			if err := vm.SavePersistentDevice(&PersistentDevice{DeviceID: result.DeviceID}); err != nil {
				return result, err
			}
			// The persistent fixture owns these consumed grants and this device.
			// Closing a run logs out only its session, never revokes enrollment.
			control.grants = nil
			clear(control.devices)
		}
	} else {
		result.DeviceID = saved.DeviceID
	}
	if _, err := control.session.Admin.UpdateAssistancePolicy(ctx, connect.NewRequest(&adminv1.UpdateAssistancePolicyRequest{RequestId: uuid.NewString(), DeviceId: result.DeviceID, Policy: assistanceFullPolicy()})); err != nil {
		return result, fmt.Errorf("enable disposable device Tier1 policy: %w", err)
	}
	if err := waitNativeActionPresence(ctx, control.session, result.DeviceID); err != nil {
		return result, err
	}
	if result.Guest.Desktop, err = prepareAssistanceDesktop(ctx, vm, desktop, release, resuming); err != nil {
		return result, err
	}
	if err := waitAssistanceSessionUnit(ctx, vm.guest, desktop, result.Guest); err != nil {
		return result, err
	}
	if tierOne {
		if err := installAssistanceFixture(ctx, vm.guest, desktop, release, evidence, result); err != nil {
			return result, err
		}
	}
	if result.Guest.Packages, err = observeAssistancePackages(ctx, vm.guest, release, tierOne); err != nil {
		return result, err
	}
	if result.Guest.Capabilities, err = observeAssistanceCapabilities(ctx, vm.guest, desktop); err != nil {
		return result, err
	}
	screen := &assistanceScreen{vm: vm.guest, evidence: evidence, result: result}
	if _, err := screen.captureReference(ctx, "desktop-reference"); err != nil {
		return result, err
	}
	if options.RebootPolicy != nil {
		return result, exerciseDesktopRebootPolicy(ctx, vm, screen, control, release, result, options.RebootPolicy)
	}
	result.Browser = &assistanceBrowserEvidence{Engine: "chromium", Username: assistanceOperator}
	var scenarioErr error
	if len(scenarios) != 0 {
		readiness, err := awaitAssistanceReadiness(ctx, vm.guest, control.session, result.DeviceID)
		if err != nil {
			return result, err
		}
		result.Readiness = &assistanceReadinessEvidence{State: readiness.GetState().String(), InventoryObservedAt: readiness.GetInventoryObservedAt().AsTime()}
		scenarioErr = runAssistanceScenarios(ctx, &assistanceRun{vm: vm, screen: screen, owner: control.session, evidence: evidence, result: result, release: release, desktop: desktop, deviceID: result.DeviceID, turnTCP: options.ConsoleTURNTCP}, fixture, options, scenarios)
	}
	// Device journals are recorded for failures too: they are the product
	// slices' diagnostic for a wrong end cause.
	result.Journals, err = collectAssistanceJournals(ctx, vm.guest, since, evidence)
	if scenarioErr != nil || err != nil {
		return result, errors.Join(scenarioErr, err)
	}
	if result.Audit, err = collectAssistanceAudit(ctx, control.session, result.Scenarios); err != nil || options.Hold == nil {
		return result, err
	}
	var findings *devlab.DeviceFindingCounts
	if options.ControlPlane == nil {
		advisories, err := devlab.HeldAdvisories(*release, manifest.GetArchitecture())
		if err != nil {
			return result, err
		}
		if err := fixture.EnableAdvisories(ctx, advisories, options.AdvisoryCache); err != nil {
			return result, err
		}
		findings, err = waitAssistanceFindings(ctx, fixture, result.DeviceID)
		if err != nil {
			return result, err
		}
	}
	if !deadline.Stop() {
		return result, context.Cause(ctx)
	}
	return result, holdAssistance(ctx, vm, fixture, screen, result, options.Hold, options.ControlPlane != nil, findings, options.ExistingOwner)
}

// runAssistanceScenarios signs the operator browser in and runs each scenario
// in order; the browser is gone before the lane collects journals or holds.
func runAssistanceScenarios(ctx context.Context, run *assistanceRun, fixture *devlab.AuthorityFixture, options VMAssistanceOptions, scenarios []assistanceScenarioSpec) (err error) {
	private, err := os.MkdirTemp("", "lindm-assistance-secrets-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(private)) }()
	if options.ControlPlane != nil {
		run.forwardedTURNURL = options.ControlPlane.forwardedTURNURL()
	}
	if run.browser, err = openAssistanceOperator(ctx, fixture, options, private, assistanceOperator, "owner"); err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, run.browser.Close())
		if options.PersistentDir != "" {
			err = errors.Join(err, retireAssistanceOperator(ctx, fixture, run.browser.accountID))
		}
	}()
	run.result.Browser.Version = run.browser.version
	for _, scenario := range scenarios {
		if scenario.name == "authority-view" || scenario.name == "authority-control" {
			if err := run.modeAuthorityScenario(ctx, fixture, options, private, scenario); err != nil {
				return fmt.Errorf("assistance scenario %s: %w", scenario.name, err)
			}
			continue
		}
		if scenario.name == "clipboard-permission" {
			if err := run.restrictedClipboardScenario(ctx, fixture, options, private, scenario); err != nil {
				return fmt.Errorf("assistance scenario %s: %w", scenario.name, err)
			}
			continue
		}
		if err := run.scenario(ctx, scenario); err != nil {
			// Preserve the console's actual negotiation failure before closing
			// Chromium; an earlier awaiting-consent screenshot cannot explain
			// a later TURN/signaling failure on the routed admin path.
			current := run.result.Scenarios[len(run.result.Scenarios)-1]
			capture, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			screenshotErr := run.browserScreenshot(capture, current, "failure")
			cancel()
			return errors.Join(fmt.Errorf("assistance scenario %s: %w", scenario.name, err), screenshotErr)
		}
	}
	return nil
}

// selectAssistanceScenarios keeps the desktop's lane order and rejects
// unknown names.
func selectAssistanceScenarios(available []assistanceScenarioSpec, names []string) ([]assistanceScenarioSpec, error) {
	if names == nil {
		return available, nil
	}
	selected := make([]assistanceScenarioSpec, 0, len(names))
	known := make([]string, 0, len(available))
	for _, spec := range available {
		known = append(known, spec.name)
		if slices.Contains(names, spec.name) {
			selected = append(selected, spec)
		}
	}
	if len(selected) != len(names) {
		return nil, fmt.Errorf("assistance scenarios must be distinct names from %s", strings.Join(known, ", "))
	}
	return selected, nil
}

// openAssistanceOperator issues a distinct account with the requested configured
// role through the real account API, then enrolls and signs in through the UI.
// The browser driver comes from the checkout under test, like the packages.
func openAssistanceOperator(ctx context.Context, fixture *devlab.AuthorityFixture, options VMAssistanceOptions, private, username, role string) (_ *assistanceBrowser, err error) {
	username, enrollment, err := createAssistanceOperator(ctx, fixture, options.PersistentDir != "", username, role)
	if err != nil {
		return nil, err
	}
	defer func() { enrollment.Secret = "" }()
	defer func() {
		if err != nil && options.PersistentDir != "" {
			err = errors.Join(err, retireAssistanceOperator(ctx, fixture, enrollment.GetAccountId()))
		}
	}()
	cfg := assistanceBrowserConfig{Origin: fixture.ConsoleOrigin, Username: username, Password: rand.Text(), EnrollmentSecret: enrollment.GetSecret(), EvidenceDirectory: options.EvidenceDir, ActionTimeoutMS: 30000, TURNTCPOnly: options.ConsoleTURNTCP}
	if options.ControlPlane != nil {
		cfg.ForwardedTURNURL = options.ControlPlane.forwardedTURNURL()
	}
	browser, err := startAssistanceBrowser(ctx, VMBuildRepository(options.Repository, options.BuildRepository), private, cfg)
	cfg.Password, cfg.EnrollmentSecret = "", ""
	if browser != nil {
		browser.accountID = enrollment.GetAccountId()
	}
	return browser, err
}

// assistanceScenarioSpec is one end-to-end session and its required end path.
type assistanceScenarioSpec struct {
	name  string
	mode  agentv1.AssistanceMode
	cause agentv1.AssistanceEndCause
	// portalCancel accepts the product prompt, then cancels the desktop's own
	// portal dialog instead (also DECLINED, without consent).
	portalCancel bool
	// detail is the exact UNAVAILABLE end detail of a session the desktop
	// cannot serve; such a session must end before any consent prompt.
	detail     string
	capability platform.Capability
}

var assistanceScenarios = []assistanceScenarioSpec{
	{name: "control", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED},
	{name: "rerequest", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED},
	{name: "view", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED},
	{name: "authority-view", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_USER_STOPPED},
	{name: "authority-control", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST},
	{name: "decline", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED},
	{name: "portal-cancel", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_DECLINED, portalCancel: true},
	{name: "lock", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_SESSION_LOCKED},
	{name: "clipboard", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED, capability: platform.AssistanceClipboard},
	{name: "clipboard-limited", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED, capability: platform.AssistanceClipboard},
	{name: "clipboard-policy", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST, capability: platform.AssistanceClipboard},
	{name: "clipboard-permission", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED, capability: platform.AssistanceClipboard},
	{name: "keyboard", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED, capability: platform.AssistanceKeyboard},
	{name: "display", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED, capability: platform.AssistanceDisplays},
	{name: "message", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED, capability: platform.AssistanceMessages},
	{name: "monitors", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_OPERATOR_STOPPED, capability: platform.AssistanceDisplays},
}

// unavailableScenarios are a desktop's visible pre-consent refusals.
func unavailableScenarios(view, control string) []assistanceScenarioSpec {
	return []assistanceScenarioSpec{
		{name: "view-unavailable", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, detail: view},
		{name: "control-unavailable", mode: agentv1.AssistanceMode_ASSISTANCE_MODE_CONTROL, cause: agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_UNAVAILABLE, detail: control},
	}
}

// assistanceAuditExpectations are the audit actions each scenario must leave,
// in addition to assistance.end carrying its cause.
var assistanceAuditExpectations = map[string][]string{
	"control":              {"assistance.request", "assistance.prompt", "assistance.consent", "assistance.join", "assistance.answer", "assistance.start", "assistance.stop"},
	"view":                 {"assistance.request", "assistance.prompt", "assistance.consent", "assistance.join", "assistance.answer", "assistance.start"},
	"authority-view":       {"assistance.request", "assistance.prompt", "assistance.consent", "assistance.join", "assistance.answer", "assistance.start"},
	"authority-control":    {"assistance.request", "assistance.prompt", "assistance.consent", "assistance.join", "assistance.answer", "assistance.start"},
	"lock":                 {"assistance.request", "assistance.prompt", "assistance.consent", "assistance.join", "assistance.answer", "assistance.start"},
	"decline":              {"assistance.request", "assistance.prompt"},
	"rerequest":            {"assistance.request", "assistance.prompt"},
	"portal-cancel":        {"assistance.request", "assistance.prompt"},
	"clipboard-policy":     {"assistance.request", "assistance.prompt", "assistance.consent", "assistance.join", "assistance.answer", "assistance.start", "assistance.clipboard"},
	"clipboard-permission": {"assistance.request", "assistance.prompt", "assistance.consent", "assistance.join", "assistance.answer", "assistance.start", "assistance.clipboard", "assistance.stop"},
	"view-unavailable":     {"assistance.request"},
	"control-unavailable":  {"assistance.request"},
}

// assistanceAuditForbidden are audit actions a scenario must never leave.
var assistanceAuditForbidden = map[string][]string{
	"view-unavailable":    {"assistance.prompt", "assistance.consent", "assistance.start"},
	"control-unavailable": {"assistance.prompt", "assistance.consent", "assistance.start"},
}

func assistanceCauseText(cause agentv1.AssistanceEndCause) string {
	return strings.ToLower(strings.TrimPrefix(cause.String(), "ASSISTANCE_END_CAUSE_"))
}

func assistanceStateText(state adminv1.AssistanceState) string {
	return strings.ToLower(strings.TrimPrefix(state.String(), "ASSISTANCE_STATE_"))
}

// assistanceAdmission requires the registry and the desktop profile to agree:
// a supported release runs the live scenarios, and a release whose registry
// gates assistance runs only its desktop's pre-consent refusals, which prove
// the gate's visible product behaviour rather than a capability.
func assistanceAdmission(release *platform.Release, desktop *labDesktop) error {
	refusalOnly := desktop.refusalOnly()
	gate := release.Gate(platform.Assistance)
	switch {
	case refusalOnly && gate == nil:
		return fmt.Errorf("%s supports assistance in the registry, but the %s lab desktop refuses every session", release.Name, desktop.name)
	case !refusalOnly && gate != nil:
		return gate
	}
	return nil
}

// refusalOnly reports whether every scenario of the desktop is a pre-consent
// refusal, so no session on it ever captures.
func (d *labDesktop) refusalOnly() bool {
	return len(d.assistance) != 0 && !slices.ContainsFunc(d.assistance, func(spec assistanceScenarioSpec) bool { return spec.detail == "" })
}
