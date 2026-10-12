package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "lindm/gen/lindm/admin/v1"
	configv1 "lindm/gen/lindm/config/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/demolab"
	"lindm/internal/devlab"
	"lindm/internal/labhost"
	"lindm/internal/orgapply"
	"lindm/internal/vmlab"
)

type demoDeviceHeldKey struct{}

type demoOptions struct {
	name, spec, repository, build, lab, lindmd, evidence, address, ledger string
	cache, golden, redhatToken                                            string
	destroy                                                               bool
}

type demoRun struct {
	options        demoOptions
	root           string
	spec           *demolab.Spec
	state          *labv1.DemoState
	controller     *vmlab.AssistanceController
	access         *demoOwnerAccess
	stdout, stderr io.Writer
}

type demoWriter struct {
	mu     *sync.Mutex
	output io.Writer
}

func (w demoWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.output.Write(data)
}

func runDemo(ctx context.Context, args []string, stdout, stderr io.Writer) (err error) {
	outputLock := new(sync.Mutex)
	stdout, stderr = demoWriter{outputLock, stdout}, demoWriter{outputLock, stderr}
	flags := flag.NewFlagSet("demo", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var options demoOptions
	flags.StringVar(&options.name, "name", "", "persistent organization demo name")
	flags.StringVar(&options.spec, "spec", "lab/demo/org-demo.json", "strict protobuf JSON organization lab spec")
	flags.BoolVar(&options.destroy, "destroy", false, "remove stopped controller and all bound devices on their original hosts")
	flags.StringVar(&options.repository, "repo", ".", "repository with initialized development PostgreSQL and trust")
	flags.StringVar(&options.build, "build-repo", ".", "current source checkout with built console and installed npm dependencies")
	flags.StringVar(&options.lab, "lab", "artifacts/bin/lab", "rebuilt native lab binary")
	flags.StringVar(&options.lindmd, "lindmd", "artifacts/bin/lindmd", "rebuilt server with embedded console")
	flags.StringVar(&options.evidence, "evidence", "", "new private evidence directory; defaults to a unique controller work directory")
	flags.StringVar(&options.address, "controller-address", "", "routed controller IPv4; normally inferred from a bound SSH host")
	flags.StringVar(&options.ledger, "ledger", "lab/ledger.json", "maintained qualification ledger")
	flags.StringVar(&options.cache, "cache", "", "verified image cache; defaults to REPO/.cache/lab/images")
	flags.StringVar(&options.golden, "golden-cache", "", "local encrypted golden cache; defaults to REPO/.cache/lab/encrypted")
	flags.StringVar(&options.redhatToken, "redhat-token-file", "", "protected Red Hat offline-token file; required for subscription-entitled (RHEL) devices, which are registered with RHSM and unregistered by exact consumer UUID on -destroy")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if options.name == "" || flags.NArg() != 0 {
		return errors.New("lab demo requires -name NAME and no positional arguments")
	}
	root, err := controllerDemoDirectory(options.name)
	if err != nil {
		return err
	}
	lock, err := lockAssistanceDemo(root)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	if options.redhatToken != "" {
		if options.redhatToken, err = filepath.Abs(options.redhatToken); err != nil {
			return err
		}
	}
	if options.destroy {
		return destroyOrganizationDemo(ctx, options, root, stdout, stderr)
	}
	spec, err := demolab.Load(options.spec)
	if err != nil {
		return err
	}
	ledgerData, err := os.ReadFile(options.ledger)
	if err != nil {
		return err
	}
	ledger := new(labv1.MatrixLedger)
	if err := protojson.Unmarshal(ledgerData, ledger); err != nil {
		return err
	}
	if err := demolab.Admit(spec, ledger); err != nil {
		return err
	}
	for _, device := range spec.Devices {
		if device.Release.Lab.Entitlement && options.redhatToken == "" {
			return fmt.Errorf("device %s: subscription-entitled release requires -redhat-token-file (it is registered with RHSM)", device.Config.GetKey())
		}
	}
	if err := openAssistanceDemoRoot(root); err != nil {
		return err
	}
	cfg, err := labhost.Load()
	if err != nil {
		return err
	}
	state, err := bindDemoState(options.name, root, spec, cfg)
	if err != nil {
		return err
	}
	for _, path := range []*string{&options.repository, &options.build, &options.lab, &options.lindmd} {
		*path, err = filepath.Abs(*path)
		if err != nil {
			return err
		}
	}
	if options.cache == "" {
		options.cache = filepath.Join(options.repository, ".cache", "lab", "images")
	}
	if options.golden == "" {
		options.golden = filepath.Join(options.repository, ".cache", "lab", "encrypted")
	}
	if options.evidence == "" {
		options.evidence, err = os.MkdirTemp(filepath.Dir(root), options.name+"-evidence-")
	} else {
		options.evidence, err = filepath.Abs(options.evidence)
		if err == nil {
			err = os.Mkdir(options.evidence, 0700)
		}
	}
	if err != nil {
		return err
	}
	run := &demoRun{options: options, root: root, spec: spec, state: state, stdout: stdout, stderr: stderr}
	return run.run(ctx)
}

func (r *demoRun) run(ctx context.Context) (err error) {
	address, err := r.controllerAddress(ctx)
	if err != nil {
		return err
	}
	var architectures []string
	for _, device := range r.spec.Devices {
		arch, err := labhost.NormalizeArchitecture(device.Manifest.GetArchitecture())
		if err != nil {
			return err
		}
		if !slices.Contains(architectures, arch) {
			architectures = append(architectures, arch)
		}
	}
	slices.Sort(architectures)
	r.controller, err = vmlab.OpenPersistentAssistanceController(ctx, r.options.repository, r.options.lindmd, filepath.Join(r.root, "control-plane"), address, "organization-demo", devlab.LoadAuthorityOptions{NativeEnrollmentArchitectures: architectures, NativeEnrollmentSourceRepository: r.options.build})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, r.controller.Close()) }()
	defer r.controller.Handle.Authority.ClearCredentials()
	advisories := &configv1.AdvisoryConfig{RefreshEnabled: true}
	seen := make(map[string]bool)
	for _, device := range r.spec.Devices {
		feeds, err := devlab.HeldAdvisories(*device.Release, device.Manifest.GetArchitecture())
		if err != nil {
			return err
		}
		for _, feed := range feeds.GetFeeds() {
			if !seen[feed.GetId()] {
				advisories.Feeds = append(advisories.Feeds, feed)
				seen[feed.GetId()] = true
			}
		}
	}
	cache, err := controllerAdvisoryCache()
	if err != nil {
		return err
	}
	if err := r.controller.Fixture.EnableAdvisories(ctx, advisories, cache); err != nil {
		return err
	}
	if err := r.openOwnerAccess(); err != nil {
		return err
	}
	if err := r.apply(ctx, "organization-initial.json", false, false); err != nil {
		return err
	}
	return r.holdDevices(ctx)
}

func (r *demoRun) controllerAddress(ctx context.Context) (netip.Addr, error) {
	if r.options.address != "" {
		return assistanceControllerIPv4(r.options.address)
	}
	for _, bound := range r.state.Bindings {
		if bound.Host.GetTransport() == "ssh" {
			return controllerAddress(ctx, bound.Host.GetSshAlias(), "")
		}
	}
	return netip.Addr{}, errors.New("local-only organization demo requires -controller-address LAN_IPV4")
}

func (r *demoRun) openOwnerAccess() error {
	path := filepath.Join(r.root, "owner-access")
	data, err := readDemoPrivate(path)
	if err == nil {
		defer clear(data)
		if err := json.Unmarshal(data, &r.access); err != nil {
			return err
		}
		if r.access == nil || r.access.ConsoleOrigin != r.controller.Fixture.ConsoleOrigin || (r.access.EnrollmentStarted && r.access.Username == "") {
			return errors.New("incomplete or mismatched original owner access; no enrollment is reissued")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	r.access = &demoOwnerAccess{ConsoleOrigin: r.controller.Fixture.ConsoleOrigin, Devices: make(map[string]*vmlab.AssistanceHold)}
	return r.saveOwnerAccess()
}

func (r *demoRun) enrollOwner(ctx context.Context) error {
	if r.access.Username != "" {
		return nil
	}
	// Reserve custody before issuing the one-time human enrollment. An interrupted
	// response is a visible incomplete record, never a silent second issuance.
	r.access.EnrollmentStarted = true
	if err := r.saveOwnerAccess(); err != nil {
		return err
	}
	enrollment, err := r.controller.Fixture.CreateConsoleEnrollment(ctx)
	if err != nil {
		return err
	}
	r.access.Username, r.access.EnrollmentSecret = "console-owner", enrollment.GetSecret()
	r.access.EnrollmentExpiresAt = enrollment.GetExpiresAt().AsTime()
	enrollment.Secret = ""
	return r.saveOwnerAccess()
}

func (r *demoRun) saveOwnerAccess() error {
	return publishDemoJSON(filepath.Join(r.root, "owner-access"), r.access, 0400)
}

func (r *demoRun) apply(ctx context.Context, record string, complete, unchanged bool) (err error) {
	owner, err := r.controller.Fixture.OpenOwnerSession(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeDemoSession(owner)) }()
	organization := r.spec.Organization
	if !complete {
		organization = demoPrerequisiteOrganization(organization)
	}
	plan, err := orgapply.Plan(ctx, owner.Admin, organization)
	if err != nil {
		return err
	}
	options := orgapply.Options{}
	if complete {
		options.AccountClient = owner
	}
	result, applyErr := orgapply.Apply(ctx, owner.Admin, plan, options)
	if result == nil {
		return applyErr
	}
	r.access.Secrets = append(r.access.Secrets, result.Secrets...)
	if err := r.saveOwnerAccess(); err != nil {
		return errors.Join(applyErr, err)
	}
	if err := publishDemoJSON(filepath.Join(r.options.evidence, record), result, 0400); err != nil {
		return errors.Join(applyErr, err)
	}
	if applyErr != nil {
		return applyErr
	}
	if unchanged {
		for _, outcome := range result.Outcomes {
			if outcome.Status == "created" || outcome.Status == "updated" {
				return fmt.Errorf("second organization apply changed %s %s", outcome.Kind, outcome.Name)
			}
		}
	}
	return nil
}

func (r *demoRun) holdDevices(ctx context.Context) (err error) {
	ctx, cancel := context.WithCancelCause(ctx)
	var workers sync.WaitGroup
	failures := make(chan error, len(r.state.Bindings))
	batches := make(map[string]*labhost.BatchReservation)
	var reservations []*labhost.BatchReservation
	defer func() {
		cancel(nil)
		for i := len(reservations) - 1; i >= 0; i-- {
			err = errors.Join(err, reservations[i].Close())
		}
		workers.Wait()
		close(failures)
		for failure := range failures {
			if failure != nil && !errors.Is(failure, context.Canceled) {
				err = errors.Join(err, failure)
			}
		}
	}()
	workers.Go(func() {
		if err := r.controller.Fixture.Wait(ctx); err != nil && ctx.Err() == nil {
			cancel(err)
		}
	})
	requests, err := r.demoBatchRequests()
	if err != nil {
		return err
	}
	for _, request := range requests {
		request.Stderr = r.stderr
		reservation, err := request.Acquire(ctx)
		if err != nil {
			if ctx.Err() != nil && errors.Is(err, context.Cause(ctx)) {
				return demoContextError(ctx)
			}
			return fmt.Errorf("reserve demo host %s: %w", request.Host.GetName(), err)
		}
		reservations = append(reservations, reservation)
		batches[request.Host.GetName()] = reservation
		workers.Go(func() {
			err := reservation.Wait()
			if ctx.Err() == nil {
				if err == nil {
					err = errors.New("batch reservation exited before stop")
				}
				cancel(fmt.Errorf("host %s: %w", request.Host.GetName(), err))
			}
		})
	}
	forwarded := make(map[string]bool)
	for _, bound := range r.state.Bindings {
		ready := make(chan *vmlab.AssistanceHold, 1)
		needForward := !forwarded[bound.Host.GetName()]
		forwarded[bound.Host.GetName()] = true
		workers.Go(func() {
			err := r.runDevice(ctx, bound, batches[bound.Host.GetName()].Credential(), needForward, func(access *vmlab.AssistanceHold) error {
				copy := *access
				select {
				case ready <- &copy:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			failures <- err
			if ctx.Err() == nil {
				if err == nil {
					err = errors.New("demo worker exited before stop")
				}
				cancel(fmt.Errorf("device %s: %w", bound.Key, err))
			}
		})
		select {
		case <-ctx.Done():
			return demoContextError(ctx)
		case access := <-ready:
			findings, err := r.controller.WaitDeviceFindings(ctx, access.DeviceID)
			var unknown *devlab.UnknownEvaluationError
			if errors.As(err, &unknown) && ctx.Err() == nil && demoTerminalUnknown(unknown.Counts.Freshness.GetReason()) {
				// The product cannot classify this device; show its reason, never zero.
				findings, err = unknown.Counts, nil
			}
			if err != nil {
				return err
			}
			access.Findings = findings
			r.access.Devices[bound.Key] = access
			if err := r.saveOwnerAccess(); err != nil {
				return err
			}
			if err := r.verifyDeviceGroup(ctx, bound, access.DeviceID); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(r.stdout, "Device %s ready: %s (%s on %s), TPM action %s; %s\n", bound.Key, access.DeviceID, access.Hostname, bound.Host.GetName(), access.TPMActionID, demoFindingsText(findings)); err != nil {
				return err
			}
			if access.TPMPassphraseFallback {
				if _, err := fmt.Fprintf(r.stdout, "%s: TPM unattended unlock fell back to passphrase on this boot (known intermittent race, reported)\n", bound.Key); err != nil {
					return err
				}
			}
		}
	}
	if err := r.apply(ctx, "organization-ready.json", true, false); err != nil {
		return err
	}
	if err := r.apply(ctx, "organization-unchanged.json", true, true); err != nil {
		return err
	}
	if err := r.enrollOwner(ctx); err != nil {
		return err
	}
	if err := r.writeReady(); err != nil {
		return err
	}
	workers.Go(func() {
		if err := r.watchResources(ctx); err != nil && ctx.Err() == nil {
			cancel(fmt.Errorf("resource report: %w", err))
		}
	})
	<-ctx.Done()
	return demoContextError(ctx)
}

// demoTerminalUnknown lists product evaluation reasons that persist until the
// device's own evidence changes; a demo device is shown with that reason
// instead of waiting forever. Pending and stale states never qualify.
func demoTerminalUnknown(reason string) bool {
	return reason == "rhel_platform_stream_unavailable"
}

func demoFindingsText(findings *devlab.DeviceFindingCounts) string {
	if findings.Freshness.GetState() == adminv1.AdvisoryFindingState_ADVISORY_FINDING_STATE_UNKNOWN {
		return "findings unknown (" + findings.Freshness.GetReason() + ")"
	}
	return fmt.Sprintf("findings affected=%d accepted=%d unknown=%d clear=%d", findings.Affected, findings.Accepted, findings.Unknown, findings.Clear)
}

func demoContextError(ctx context.Context) error {
	cause := context.Cause(ctx)
	if errors.Is(cause, context.Canceled) {
		return nil
	}
	return cause
}

func closeDemoSession(owner *devlab.OwnerSession) error {
	cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return owner.Close(cleanup)
}
