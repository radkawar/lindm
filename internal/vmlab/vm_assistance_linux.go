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
	release := platform.ForManifest(manifest.GetDistribution(), manifest.GetVersion())
	if err := release.Gate(platform.Assistance); err != nil {
		return nil, err
	}
	if options.Encrypted.Desktop != "gnome" || options.Encrypted.Hardware == nil || !options.Encrypted.Hardware.Desktop || !options.Encrypted.Hardware.AllowNetwork {
		return nil, errors.New("assistance lane requires the installer GNOME desktop, a lab display and signed-package egress")
	}
	evidence, err := newAssistanceEvidence(options.EvidenceDir)
	if err != nil {
		return nil, err
	}
	result = &VMAssistanceResult{ImageID: manifest.GetId(), ImageSHA256: manifest.GetSha256(), Distribution: manifest.GetDistribution(), Architecture: manifest.GetArchitecture(), StartedAt: time.Now().UTC(), Boundaries: []string{
		"One disposable QEMU guest (virtio-gpu, usb-tablet, virtual keyboard); local-user consent and stop clicks are QMP absolute-pointer input located from QMP screendumps, not a human at a physical display.",
		"Relayed media stays on the lab host: guest UDP reaches the embedded TURN listener through QEMU user networking (10.0.2.2 to host loopback); NAT traversal, public relays and multi-host paths are not qualified.",
		"The operator browser is headless Playwright Chromium on the lab host with a virtual WebAuthn authenticator; other browsers are not qualified by this lane.",
		"Media and control proofs are the console's own WebRTC statistics and decoded frames plus a guest-side typed nonce; video quality, latency and bandwidth are not qualified.",
		"GNOME idle blanking and automatic lock are disabled in the lab session; the lock scenario uses loginctl lock-session.",
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
		result.Passed = err == nil
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
	scenarios, err := selectAssistanceScenarios(options.Scenarios)
	if err != nil {
		return result, err
	}
	if result.LabSHA256, err = dispatchFileDigest(options.LabBinary); err != nil {
		return result, err
	}
	if options.ControlPlane != nil {
		result.LindmdSHA256 = options.ControlPlane.LindmdSHA256
	} else if result.LindmdSHA256, err = dispatchFileDigest(options.LindmdBinary); err != nil {
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
	fixture, delegation, relay, err := openAssistanceFixture(ctx, options)
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
		if err := control.applyExecutionAuthority(ctx, delegation, 1, 1, 0); err != nil {
			return result, fmt.Errorf("admit isolated execution authority: %w", err)
		}
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
	// The agent package Recommends the capture stack; the lab installs it with
	// --no-install-recommends, so install the release's capture packages from
	// its signed archive first (Debian's GNOME task lacks gstreamer1.0-tools).
	if err := installAssistanceCapture(ctx, vm.guest, release); err != nil {
		return result, err
	}
	if err := packages.Install(ctx, vm.guest, options.LabBinary); err != nil {
		return result, err
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
	if result.Guest.Desktop, err = prepareAssistanceDesktop(ctx, vm, release); err != nil {
		return result, err
	}
	if err := waitAssistanceSessionUnit(ctx, vm.guest, result.Guest); err != nil {
		return result, err
	}
	if result.Guest.Packages, err = observeAssistancePackages(ctx, vm.guest, release); err != nil {
		return result, err
	}
	screen := &assistanceScreen{vm: vm.guest, evidence: evidence, result: result}
	if _, err := screen.captureReference(ctx); err != nil {
		return result, err
	}
	result.Browser = &assistanceBrowserEvidence{Engine: "chromium", Username: assistanceOperator}
	var scenarioErr error
	if len(scenarios) != 0 {
		scenarioErr = runAssistanceScenarios(ctx, &assistanceRun{vm: vm, screen: screen, owner: control.session, evidence: evidence, result: result, release: release, deviceID: result.DeviceID, turnTCP: options.ConsoleTURNTCP}, fixture, options, scenarios)
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
	return result, holdAssistance(ctx, vm, fixture, screen, result, options.Hold, options.ControlPlane != nil, findings)
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
	if run.browser, err = openAssistanceOperator(ctx, fixture, options, private); err != nil {
		return err
	}
	defer func() { err = errors.Join(err, run.browser.Close()) }()
	run.result.Browser.Version = run.browser.version
	for _, scenario := range scenarios {
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

// selectAssistanceScenarios keeps lane order and rejects unknown names.
func selectAssistanceScenarios(names []string) ([]assistanceScenarioSpec, error) {
	if names == nil {
		return assistanceScenarios, nil
	}
	selected := make([]assistanceScenarioSpec, 0, len(names))
	for _, spec := range assistanceScenarios {
		if slices.Contains(names, spec.name) {
			selected = append(selected, spec)
		}
	}
	if len(selected) != len(names) {
		return nil, errors.New("assistance scenarios must be distinct names from control, view, decline, portal-cancel, lock")
	}
	return selected, nil
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
	cfg := assistanceBrowserConfig{Origin: fixture.ConsoleOrigin, Username: assistanceOperator, Password: rand.Text(), EnrollmentSecret: enrollment.GetSecret(), EvidenceDirectory: options.EvidenceDir, ActionTimeoutMS: 30000, TURNTCPOnly: options.ConsoleTURNTCP}
	if options.ControlPlane != nil {
		cfg.ForwardedTURNURL = options.ControlPlane.forwardedTURNURL()
	}
	browser, err := startAssistanceBrowser(ctx, VMBuildRepository(options.Repository, options.BuildRepository), private, cfg)
	cfg.Password, cfg.EnrollmentSecret = "", ""
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
